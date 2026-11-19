//! **Target A — "eager"**.
//!
//! This is the incident described in the exercise: the server processes
//! application data that arrives *before* the handshake has completed.
//!
//! Fault profile (everything else follows the reference):
//!
//! * **A1** In `AwaitFinish`, `APP_DATA` is decrypted and answered with the
//!   epoch-0 keys.  The keys are derivable from the HELLO flight alone, so
//!   the records decrypt cleanly — the state check is simply missing. (R-3.7)
//! * **A2** In `AwaitFinish`, a `REKEY` is likewise processed, rotating keys
//!   before `SERVER_FINISH` was sent. (R-3.7, R-5.3)
//! * **A3** `CLOSE` received before the handshake finishes is answered with a
//!   `CLOSE` and the connection is torn down "gracefully". (R-3.7)
//!
//! The fault is easy to spot from the outside: send CLIENT_HELLO, read
//! SERVER_HELLO, then send an encrypted APP_DATA/PING before CLIENT_FINISH.
//! A conforming server answers `ERR(UnexpectedMessage)`; this one answers
//! PONG (or ACK).

use std::time::Instant;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use scp_core::crypto::{rekey_keys, resume_keys, resume_psk, HandshakeState, Side, Ticket, TrafficKeys};
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
    // A1/A2: early records use their own receive counter, so the first
    // post-handshake record does not look like a gap.
    let mut early_recv_seq: u64 = 0;
    let started = Instant::now();

    loop {
        let timeout = match state {
            State::Established => cfg.idle_timeout,
            _ => {
                let remain = cfg.handshake_deadline.saturating_sub(started.elapsed());
                if remain.is_zero() {
                    link.fail(ErrorCode::DeadlineExceeded);
                    return;
                }
                remain
            }
        };

        let frame = match link.recv(timeout) {
            Recv::Frame(f) => f,
            Recv::TimedOut => {
                if state == State::Established {
                    link.close();
                } else {
                    link.fail(ErrorCode::DeadlineExceeded);
                }
                return;
            }
            Recv::Closed => {
                link.close();
                return;
            }
            Recv::Bad(e) => {
                link.fail(wire_error_code(&e));
                return;
            }
        };

        if is_server_type(frame.mtype) {
            link.fail(ErrorCode::DecodeError);
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
                        link.fail(ErrorCode::BadVersion);
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
                    // Keys are derived as soon as the HELLO is processed,
                    // which is what makes early data decryptable.
                    keys = Some(st.app_keys());
                    if !link.send(&sh_frame) {
                        return;
                    }
                    hs = Some(st);
                    state = State::AwaitFinish;
                }
                MsgType::SessionResume => {
                    let Some(rk) = handle_resume(link, shared, cfg, &mut rng, &frame) else {
                        return;
                    };
                    keys = Some(rk);
                    send_seq = 0;
                    recv_seq = 0;
                    state = State::Established;
                }
                _ => {
                    link.fail(ErrorCode::UnexpectedMessage);
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
                    let st = hs.as_ref().unwrap();
                    if cf.verify != st.client_verify {
                        link.fail(ErrorCode::BadMac);
                        return;
                    }
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
                    send_seq = 0;
                    recv_seq = 0;
                    state = State::Established;
                }
                // ---- A1: early APP_DATA is accepted -----------------------
                MsgType::AppData => {
                    let k = keys.as_ref().unwrap();
                    let sealed = match Sealed::parse(&frame.body, "record") {
                        Ok(s) => s,
                        Err(_) => {
                            link.fail(ErrorCode::DecodeError);
                            return;
                        }
                    };
                    let Some(pt) = open_frame(k, Side::Server, sealed.seq, &frame) else {
                        link.fail(ErrorCode::BadMac);
                        return;
                    };
                    early_recv_seq = early_recv_seq.wrapping_add(1);
                    if let Some(reply) = app_reply(&pt, &mut submissions) {
                        let f = seal_frame(k, Side::Server, send_seq, MsgType::AppData, &reply);
                        send_seq += 1;
                        if !link.send(&f) {
                            return;
                        }
                    }
                }
                // ---- A2: early REKEY is accepted --------------------------
                MsgType::Rekey => {
                    let k = keys.as_ref().unwrap();
                    let sealed = match Sealed::parse(&frame.body, "record") {
                        Ok(s) => s,
                        Err(_) => {
                            link.fail(ErrorCode::DecodeError);
                            return;
                        }
                    };
                    let Some(pt) = open_frame(k, Side::Server, sealed.seq, &frame) else {
                        link.fail(ErrorCode::BadMac);
                        return;
                    };
                    if pt.len() != 32 {
                        link.fail(ErrorCode::DecodeError);
                        return;
                    }
                    let mut contrib = [0u8; 32];
                    contrib.copy_from_slice(&pt);
                    let next = rekey_keys(k, &contrib);
                    let mut server_contrib = [0u8; 32];
                    rng.fill_bytes(&mut server_contrib);
                    let f =
                        seal_frame(&next, Side::Server, 0, MsgType::Rekey, &server_contrib);
                    if !link.send(&f) {
                        return;
                    }
                    keys = Some(next);
                    send_seq = 1;
                    early_recv_seq = 0;
                }
                // ---- A3: early CLOSE is honoured --------------------------
                MsgType::Close => {
                    let k = keys.as_ref().unwrap();
                    let sealed = match Sealed::parse(&frame.body, "record") {
                        Ok(s) => s,
                        Err(_) => {
                            link.fail(ErrorCode::DecodeError);
                            return;
                        }
                    };
                    if open_frame(k, Side::Server, sealed.seq, &frame).is_none() {
                        link.fail(ErrorCode::BadMac);
                        return;
                    }
                    let f = seal_frame(k, Side::Server, send_seq, MsgType::Close, &[]);
                    link.send(&f);
                    link.close();
                    return;
                }
                _ => {
                    link.fail(ErrorCode::UnexpectedMessage);
                    return;
                }
            },

            State::Established => {
                let k = *keys.as_ref().unwrap();
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
                            link.fail(ErrorCode::Replay);
                            return;
                        }
                        let Some(pt) = open_frame(&k, Side::Server, sealed.seq, &frame) else {
                            link.fail(ErrorCode::BadMac);
                            return;
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
                                let next = rekey_keys(&k, &contrib);
                                let mut server_contrib = [0u8; 32];
                                rng.fill_bytes(&mut server_contrib);
                                let f = seal_frame(&next, Side::Server, 0, MsgType::Rekey, &server_contrib);
                                if !link.send(&f) {
                                    return;
                                }
                                keys = Some(next);
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
                                link.close();
                                return;
                            }
                            _ => unreachable!(),
                        }
                    }
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

fn handle_resume(
    link: &mut Link,
    shared: &Shared,
    cfg: &ServerCfg,
    rng: &mut ChaCha20Rng,
    frame: &scp_core::wire::Frame,
) -> Option<TrafficKeys> {
    let sr = match SessionResume::parse(&frame.body) {
        Ok(m) => m,
        Err(_) => {
            link.fail(ErrorCode::DecodeError);
            return None;
        }
    };
    let Some(ticket) = Ticket::parse(&sr.ticket) else {
        link.fail(ErrorCode::TicketInvalid);
        return None;
    };
    if ticket.expiry_ms <= now_ms() {
        link.fail(ErrorCode::TicketInvalid);
        return None;
    }
    let Some(base) = ticket.open_psk(&shared.ticket_root) else {
        link.fail(ErrorCode::TicketInvalid);
        return None;
    };
    {
        let mut redeemed = shared.redeemed.lock().unwrap();
        if !redeemed.insert(ticket.id) {
            drop(redeemed);
            link.fail(ErrorCode::TicketInvalid);
            return None;
        }
    }
    let psk = resume_psk(&base, &ticket.id, ticket.expiry_ms);
    let secret = StaticSecret::from(random32(rng));
    let server_eph = PublicKey::from(&secret).to_bytes();
    let server_random = random32(rng);
    let shared_dh = secret.diffie_hellman(&PublicKey::from(sr.eph)).to_bytes();
    let rk = resume_keys(
        &psk, &sr.ticket, &sr.client_random, &server_random, &sr.eph, &server_eph, &shared_dh,
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

#[allow(dead_code)]
fn _seeded<T: SeedableRng>() {}
