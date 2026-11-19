//! **Target C — "sticky"**.
//!
//! Handshake ordering is right, records are checked, but the *session
//! lifecycle* is wrong: tickets do not burn, old keys linger, and a resume
//! is accepted whenever it shows up.  This is the profile you get when the
//! session layer was bolted on after the fact.
//!
//! Fault profile:
//!
//! * **C1** Tickets are not single-use: the same ticket may be presented on
//!   any number of later connections and every one succeeds. (R-6.4)
//! * **C2** After a `REKEY`, the server keeps the previous epoch's keys and
//!   will still decrypt records sealed under them, as long as their header
//!   carries the old epoch in the nonce. Old keys are never retired. (R-5.4)
//! * **C3** `SESSION_RESUME` is accepted mid-connection, on an already
//!   established session, where the spec allows it only as a first frame.
//!   (R-6.2)
//!
//! These are all "accepts something it must reject" faults, so the probe
//! finds them by sending legal-looking messages at the wrong time.

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
    // ---- C2: previous epoch kept forever -------------------------------
    let mut prev_keys: Option<TrafficKeys> = None;
    let mut send_seq: u64 = 0;
    let mut recv_seq: u64 = 0;
    let mut submissions: u32 = 0;
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
                _ => {
                    link.fail(ErrorCode::UnexpectedMessage);
                    return;
                }
            },

            State::Established => {
                // ---- C3: resume accepted on an established session --------
                if frame.mtype == MsgType::SessionResume {
                    let Some(rk) = handle_resume(link, shared, cfg, &mut rng, &frame) else {
                        return;
                    };
                    keys = Some(rk);
                    prev_keys = None;
                    send_seq = 0;
                    recv_seq = 0;
                    continue;
                }

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
                        // ---- C2: fall back to the retired epoch -------------
                        let pt = match open_frame(&k, Side::Server, sealed.seq, &frame) {
                            Some(p) => p,
                            None => match prev_keys.as_ref() {
                                Some(pk) => match open_frame(pk, Side::Server, sealed.seq, &frame) {
                                    Some(p) => p,
                                    None => {
                                        link.fail(ErrorCode::BadMac);
                                        return;
                                    }
                                },
                                None => {
                                    link.fail(ErrorCode::BadMac);
                                    return;
                                }
                            },
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
                                prev_keys = Some(k); // C2: never dropped
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

/// ---- C1: nothing here records the redeemed ticket id ------------------
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
