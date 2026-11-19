//! The compliant reference implementation. `reference` is the oracle the
//! spec was written against; every rule in `docs/spec.md` is honoured here.
//!
//! It is written as an explicit state machine so that the faults planted in
//! the other implementations read as small deltas from this file.

use std::time::{Duration, Instant};

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use scp_core::crypto::{
    rekey_keys, resume_keys, HandshakeState, Side, Ticket, TrafficKeys,
};
use scp_core::wire::{
    ClientFinish, ClientHello, ErrorCode, MsgType, ResumeOk, Sealed, ServerFinish, ServerHello,
    SessionResume, VERSION,
};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::record::{app_reply, open_frame, seal_frame};
use crate::transport::{is_server_type, now_ms, wire_error_code, Link, Recv, ServerCfg, Shared};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    AwaitFinish,
    Established,
}

pub fn run(link: &mut Link, shared: &Shared, cfg: &ServerCfg, mut rng: ChaCha20Rng) {
    let mut state = State::Start;
    let mut hs: Option<HandshakeState> = None;
    let mut keys: Option<TrafficKeys> = None;
    let mut send_seq: u64 = 0;
    let mut recv_seq: u64 = 0;
    let mut submissions: u32 = 0;
    let handshake_started_at = Instant::now();

    loop {
        let timeout = match state {
            State::Established => cfg.idle_timeout,
            _ => {
                let remain = cfg
                    .handshake_deadline
                    .saturating_sub(handshake_started_at.elapsed());
                if remain.is_zero() {
                    link.fail(ErrorCode::DeadlineExceeded); // R-7.1
                    return;
                }
                remain
            }
        };

        let frame = match link.recv(timeout) {
            Recv::Frame(f) => f,
            Recv::TimedOut => {
                if state == State::Established {
                    link.close(); // R-7.2, silent
                } else {
                    link.fail(ErrorCode::DeadlineExceeded); // R-7.1
                }
                return;
            }
            Recv::Closed => {
                link.close();
                return;
            }
            Recv::Bad(e) => {
                link.fail(wire_error_code(&e)); // R-1.2 / R-1.3
                return;
            }
        };

        if is_server_type(frame.mtype) {
            link.fail(ErrorCode::DecodeError); // R-1.4
            return;
        }

        match state {
            State::Start => match frame.mtype {
                MsgType::ClientHello => {
                    let ch = match ClientHello::parse(&frame.body) {
                        Ok(m) => m,
                        Err(_) => {
                            link.fail(ErrorCode::DecodeError);
                            return;
                        }
                    };
                    if ch.version != VERSION {
                        link.fail(ErrorCode::BadVersion); // R-3.2
                        return;
                    }
                    let secret = StaticSecret::from(random32(&mut rng));
                    let server_random = random32(&mut rng);
                    let sh = ServerHello {
                        version: VERSION,
                        random: server_random,
                        eph: PublicKey::from(&secret).to_bytes(),
                        suite: scp_core::wire::SUITE,
                        ticket_ttl_ms: cfg.ticket_ttl_ms as u32,
                    };
                    let sh_frame = sh.to_frame();
                    let st = HandshakeState::new_hello(
                        Side::Server,
                        secret,
                        server_random,
                        ch.eph,
                        ch.random,
                        &frame.body,
                        &sh_frame.body,
                    );
                    if !link.send(&sh_frame) {
                        return;
                    }
                    hs = Some(st);
                    state = State::AwaitFinish;
                }
                MsgType::SessionResume => {
                    let Some(rk) = handle_resume(link, shared, cfg, &mut rng, &frame, &mut hs)
                    else {
                        return;
                    };
                    keys = Some(rk);
                    send_seq = 0;
                    recv_seq = 0;
                    state = State::Established;
                }
                _ => {
                    link.fail(ErrorCode::UnexpectedMessage); // R-3.1
                    return;
                }
            },

            State::AwaitFinish => match frame.mtype {
                MsgType::ClientFinish => {
                    let cf = match ClientFinish::parse(&frame.body) {
                        Ok(m) => m,
                        Err(_) => {
                            link.fail(ErrorCode::DecodeError);
                            return;
                        }
                    };
                    let st = hs.as_ref().expect("AwaitFinish implies hello state");
                    if cf.verify != st.client_verify {
                        link.fail(ErrorCode::BadMac); // R-3.4
                        return;
                    }
                    let app = st.app_keys();
                    let id = random16(&mut rng);
                    let expiry = now_ms() + cfg.ticket_ttl_ms;
                    let ticket = Ticket::issue(&shared.ticket_root, &st.ticket_base(), id, expiry);
                    let sf = ServerFinish {
                        verify: st.server_verify,
                        ticket,
                    };
                    if !link.send(&sf.to_frame()) {
                        return;
                    }
                    keys = Some(app);
                    send_seq = 0;
                    recv_seq = 0;
                    state = State::Established;
                }
                // R-3.7: no early data, and no second hello/finish.
                _ => {
                    link.fail(ErrorCode::UnexpectedMessage);
                    return;
                }
            },

            State::Established => {
                let k = *keys.as_ref().expect("Established implies keys");
                match frame.mtype {
                    MsgType::AppData | MsgType::Rekey | MsgType::Close => {
                        let sealed = match Sealed::parse(&frame.body, "record") {
                            Ok(s) => s,
                            Err(_) => {
                                link.fail(ErrorCode::DecodeError);
                                return;
                            }
                        };
                        if sealed.seq != recv_seq {
                            link.fail(ErrorCode::Replay); // R-4.3
                            return;
                        }
                        let pt = match open_frame(&k, Side::Server, sealed.seq, &frame) {
                            Some(p) => p,
                            None => {
                                link.fail(ErrorCode::BadMac); // R-4.2 / R-5.4
                                return;
                            }
                        };
                        recv_seq += 1;
                        match frame.mtype {
                            MsgType::AppData => {
                                let Some(reply) = app_reply(&pt, &mut submissions) else {
                                    link.fail(ErrorCode::DecodeError);
                                    return;
                                };
                                let f =
                                    seal_frame(&k, Side::Server, send_seq, MsgType::AppData, &reply);
                                send_seq += 1;
                                if !link.send(&f) {
                                    return;
                                }
                            }
                            MsgType::Rekey => {
                                if pt.len() != 32 {
                                    link.fail(ErrorCode::DecodeError);
                                    return;
                                }
                                let mut contrib = [0u8; 32];
                                contrib.copy_from_slice(&pt);
                                let next = rekey_keys(&k, &contrib); // R-5.2
                                let mut server_contrib = [0u8; 32];
                                rng.fill_bytes(&mut server_contrib);
                                let f = seal_frame(
                                    &next,
                                    Side::Server,
                                    0,
                                    MsgType::Rekey,
                                    &server_contrib,
                                );
                                if !link.send(&f) {
                                    return;
                                }
                                keys = Some(next); // R-5.1
                                send_seq = 1;
                                recv_seq = 0;
                            }
                            MsgType::Close => {
                                if !pt.is_empty() {
                                    link.fail(ErrorCode::DecodeError);
                                    return;
                                }
                                let f = seal_frame(&k, Side::Server, send_seq, MsgType::Close, &[]);
                                link.send(&f);
                                link.close(); // R-4.5
                                return;
                            }
                            _ => unreachable!(),
                        }
                    }
                    // R-3.8: re-handshake on an established connection.
                    _ => {
                        link.fail(ErrorCode::UnexpectedMessage);
                        return;
                    }
                }
            }
        }
    }
}

fn random32(rng: &mut ChaCha20Rng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

fn random16(rng: &mut ChaCha20Rng) -> [u8; 16] {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b
}

/// Handle `SESSION_RESUME`. On success returns the new epoch-0 keys and has
/// already sent `RESUME_OK`; on failure sends the appropriate `ERR` and
/// closes, returning `None`.
fn handle_resume(
    link: &mut Link,
    shared: &Shared,
    cfg: &ServerCfg,
    rng: &mut ChaCha20Rng,
    frame: &scp_core::wire::Frame,
    _hs: &mut Option<HandshakeState>,
) -> Option<TrafficKeys> {
    let sr = match SessionResume::parse(&frame.body) {
        Ok(m) => m,
        Err(_) => {
            link.fail(ErrorCode::DecodeError);
            return None;
        }
    };
    let Some(ticket) = Ticket::parse(&sr.ticket) else {
        link.fail(ErrorCode::TicketInvalid); // R-6.3
        return None;
    };
    if ticket.expiry_ms <= now_ms() {
        link.fail(ErrorCode::TicketInvalid); // R-6.3
        return None;
    }
    let Some(base) = ticket.open_psk(&shared.ticket_root) else {
        link.fail(ErrorCode::TicketInvalid); // R-6.3
        return None;
    };
    {
        // R-6.4: single use.
        let mut redeemed = shared.redeemed.lock().unwrap();
        if !redeemed.insert(ticket.id) {
            drop(redeemed);
            link.fail(ErrorCode::TicketInvalid);
            return None;
        }
    }
    let psk = scp_core::crypto::resume_psk(&base, &ticket.id, ticket.expiry_ms);

    let secret = StaticSecret::from(random32(rng));
    let server_eph = PublicKey::from(&secret).to_bytes();
    let server_random = random32(rng);
    let shared_dh = secret.diffie_hellman(&PublicKey::from(sr.eph)).to_bytes();
    let rk = resume_keys(
        &psk,
        &sr.ticket,
        &sr.client_random,
        &server_random,
        &sr.eph,
        &server_eph,
        &shared_dh,
    );
    let id = random16(rng);
    let expiry = now_ms() + cfg.ticket_ttl_ms;
    let new_ticket = Ticket::issue(&shared.ticket_root, &rk.base, id, expiry);
    let ok = ResumeOk {
        server_random,
        eph: server_eph,
        ticket: new_ticket,
    };
    if !link.send(&ok.to_frame()) {
        return None;
    }
    Some(rk.keys)
}

// `Duration` is used in the signature of `ServerCfg` fields elsewhere.
#[allow(dead_code)]
fn _uses_duration(_d: Duration) {}

#[allow(dead_code)]
fn _seeded<T: SeedableRng>() {}
