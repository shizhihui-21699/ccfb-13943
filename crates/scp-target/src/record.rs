//! Record-layer helpers shared across implementations.
//!
//! These only apply the spec's crypto; each implementation decides *when* a
//! record may be opened and what a rejected one means.

use scp_core::crypto::{open, seal, Side, TrafficKeys};
use scp_core::wire::{Frame, MsgType, Sealed};

pub const OP_PING: u8 = 0x01;
pub const OP_SUBMIT: u8 = 0x02;
pub const OP_PONG: u8 = 0x81;
pub const OP_ACK: u8 = 0x82;
pub const OP_UNKNOWN: u8 = 0xff;

pub fn aad(mtype: MsgType) -> [u8; 1] {
    [mtype as u8]
}

pub fn seal_frame(
    keys: &TrafficKeys,
    side: Side,
    seq: u64,
    mtype: MsgType,
    plaintext: &[u8],
) -> Frame {
    let ct = seal(keys.send(side), keys.epoch, seq, &aad(mtype), plaintext);
    Sealed { seq, ct }.to_frame(mtype)
}

pub fn open_frame(keys: &TrafficKeys, side: Side, seq: u64, frame: &Frame) -> Option<Vec<u8>> {
    if frame.body.len() < 8 {
        return None;
    }
    open(keys.recv(side), keys.epoch, seq, &aad(frame.mtype), &frame.body[8..])
}

/// The reply plaintext for an accepted APP_DATA body (SPEC R-4.4).
/// `submissions` is the connection's running submit counter.
pub fn app_reply(plaintext: &[u8], submissions: &mut u32) -> Option<Vec<u8>> {
    let (&op, body) = plaintext.split_first()?;
    Some(match op {
        OP_PING => {
            let mut v = Vec::with_capacity(1 + body.len());
            v.push(OP_PONG);
            v.extend_from_slice(body);
            v
        }
        OP_SUBMIT => {
            *submissions = submissions.wrapping_add(1);
            let mut v = Vec::with_capacity(5);
            v.push(OP_ACK);
            v.extend_from_slice(&submissions.to_be_bytes());
            v
        }
        _ => vec![OP_UNKNOWN, 0x01],
    })
}
