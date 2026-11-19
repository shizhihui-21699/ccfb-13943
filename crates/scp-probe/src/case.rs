//! Executing one **experiment**: walk a fresh connection into a known
//! protocol phase, present exactly one input, and record every observable
//! consequence along with the exact bytes transmitted.
//!
//! A `Reaction` is the probe's complete evidence.  There is no side channel.

use std::net::SocketAddr;
use std::time::Duration;


use scp_core::wire::{
    ClientFinish, ClientHello, ErrorCode, MsgType, ServerHello, TICKET_LEN, VERSION,
};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::client::{Client, Keyset, Observed, Session};

#[derive(Clone)]
pub struct Target {
    pub addr: SocketAddr,
    /// How long to wait for a reply before calling it silence.
    pub reply_timeout: Duration,
    /// How long to wait on an idle connection past the target's own
    /// handshake deadline before expecting it to have closed.
    pub handshake_timeout: Duration,
}

impl Target {
    pub fn new(addr: SocketAddr) -> Self {
        Target {
            addr,
            reply_timeout: Duration::from_millis(200),
            handshake_timeout: Duration::from_millis(900),
        }
    }

    pub fn session(&self, seed: u64) -> Result<Session, String> {
        let mut s = Session::new(self.addr, seed).map_err(|e| format!("connect: {e}"))?;
        s.client.reply_timeout = self.reply_timeout;
        Ok(s)
    }
}

/// What the target did in response to one input.
#[derive(Debug, Clone)]
pub struct Reaction {
    pub observed: Vec<Observed>,
    /// True if the target treated the input as acceptable, judged purely
    /// from the evidence (it produced the in-kind reply rather than an ERR).
    pub accepted: bool,
    pub err: Option<ErrorCode>,
    pub closed: bool,
}

impl Reaction {
    pub fn classify(observed: Vec<Observed>, action: crate::model::Action) -> Reaction {
        use crate::model::Action as A;
        let err = observed.iter().find_map(|o| o.err_code());
        let closed = observed.iter().any(|o| matches!(o, Observed::Closed));
        let accepted = match action {
            A::AppDataInSequence
            | A::AppDataGap
            | A::AppDataReplay
            | A::AppDataOldEpoch
            | A::AppDataBadMac => {
                observed
                    .iter()
                    .any(|o| matches!(o, Observed::AppData(_) | Observed::AppDataOldEpoch(_)))
            }
            A::RekeyValid => observed.iter().any(|o| matches!(o, Observed::Rekey { .. })),
            A::CloseValid => observed.iter().any(|o| matches!(o, Observed::CloseRecv)),
            A::ClientHelloV1 | A::ClientHelloBadVersion => observed
                .iter()
                .any(|o| matches!(o, Observed::ServerHello { .. })),
            A::ClientFinishValid | A::ClientFinishBadMac => observed
                .iter()
                .any(|o| matches!(o, Observed::ServerFinish { .. })),
            A::SessionResumeValid
            | A::SessionResumeInvalidTicket
            | A::SessionResumeReusedTicket => {
                observed.iter().any(|o| matches!(o, Observed::ResumeOk { .. }))
            }
            _ => false,
        };
        Reaction {
            observed,
            accepted,
            err,
            closed,
        }
    }

    pub fn summary(&self) -> String {
        if self.observed.is_empty() {
            return "SILENCE".into();
        }
        self.observed
            .iter()
            .map(|o| o.short())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    pub fn meets(&self, e: crate::model::Expect) -> bool {
        use crate::model::Expect as E;
        match e {
            E::Accept => self.accepted,
            E::Reject(c) => !self.accepted && (self.err == Some(c) || self.closed),
            E::SilentClose => !self.accepted && self.observed.is_empty() && self.closed,
            E::Nothing => !self.accepted && self.observed.is_empty(),
        }
    }

    /// True if the target met the *direction* of the expectation, even if
    /// with the wrong error code.  Used to separate "accepted something
    /// forbidden" (critical) from "rejected with the wrong code" (minor).
    pub fn meets_direction(&self, e: crate::model::Expect) -> bool {
        use crate::model::Expect as E;
        match e {
            E::Accept => self.accepted,
            E::Reject(_) => !self.accepted,
            E::SilentClose => !self.accepted,
            E::Nothing => !self.accepted,
        }
    }
}

/// A live connection plus the state needed to walk it into any phase.
pub struct Scenario {
    pub target: Target,
    pub session: Session,
    pub ticket: Option<[u8; TICKET_LEN]>,
    pub ticket_base: Option<[u8; 32]>,
    /// True once the scenario has performed a rekey (old epoch available).
    pub rekeyed: bool,
}

impl Scenario {
    pub fn new(target: &Target, seed: u64) -> Result<Scenario, String> {
        Ok(Scenario {
            target: target.clone(),
            session: target.session(seed)?,
            ticket: None,
            ticket_base: None,
            rekeyed: false,
        })
    }

    /// Complete a throwaway handshake first, to obtain a genuine ticket,
    /// then open the connection under test.
    pub fn with_ticket(target: &Target, seed: u64) -> Result<Scenario, String> {
        let mut provider = target.session(seed ^ 0xA5A5_5A5A)?;
        provider.handshake()?;
        let ticket = provider.ticket.ok_or("handshake issued no ticket")?;
        let base = provider.ticket_base.ok_or("handshake produced no ticket base")?;
        let mut s = Scenario::new(target, seed)?;
        s.ticket = Some(ticket);
        s.ticket_base = Some(base);
        Ok(s)
    }

    pub fn needs_ticket(&self) -> bool {
        self.ticket.is_none()
    }

    /// Walk into `phase`.  `with_rekey` additionally performs one rekey
    /// once established.
    /// Walk into `phase` over a *fresh* connection.
    pub fn reach(&mut self, phase: crate::model::Phase, with_rekey: bool) -> Result<(), String> {
        use crate::model::Phase as P;
        match phase {
            P::Start => {}
            P::AwaitFinish => self.session.hello_flight(VERSION)?,
            P::Established | P::Closed => {
                self.session.handshake()?;
                if with_rekey {
                    self.session.rekey().ok_or("rekey did not produce a frame")?;
                    self.rekeyed = true;
                }
            }
        }
        if phase == P::Closed {
            // Close the session so the server tears the connection down,
            // then present further inputs on the now-dead socket.  Any
            // reply to those inputs would be a violation of R-7.3.
            let f = self
                .session
                .seal_at(MsgType::Close, &[], self.session.send_seq)
                .ok_or("no app keys for CLOSE")?;
            self.session.send_labeled("CLOSE", &f);
            let keys = self.session.keys.clone();
            let _ = self
                .session
                .client
                .observe_until_quiet(&keys, self.target.reply_timeout);
        }
        Ok(())
    }

    /// One legal APP_DATA round-trip: send a PING, read the PONG.  Used by
    /// the `AfterActivity` context so the action under test sees a
    /// connection that has already carried traffic.
    pub fn activity_roundtrip(&mut self) -> Result<(), String> {
        if self.session.send_seq == 0 && !self.session.established {
            return Err("not established".into());
        }
        let before = self.session.transcript.len();
        if !self.session.send_app(b"\x01warm") {
            return Err("activity send failed".into());
        }
        let _ = before;
        let keys = self.session.keys.clone();
        let obs = self
            .session
            .client
            .observe_until_quiet(&keys, self.target.reply_timeout);
        // A conforming target answers with PONG; a faulty one may not.  Either
        // way the connection has now carried traffic.
        let ok = obs.iter().any(|o| matches!(o, Observed::AppData(_)));
        if !ok {
            return Err("activity round-trip got no reply".into());
        }
        Ok(())
    }

    /// Present one abstract input.  Returns the exact bytes transmitted, or
    /// an error if the scenario cannot support that input.
    pub fn present(&mut self, action: crate::model::Action) -> Result<Vec<u8>, String> {
        use crate::model::Action as A;
        let sess = &mut self.session;

        // Helper to send a hello-shaped frame built fresh.
        macro_rules! hello {
            ($version:expr, $label:expr) => {{
                let secret = StaticSecret::from(sess.client.random32());
                let random = sess.client.random32();
                let ch = ClientHello {
                    version: $version,
                    random,
                    eph: PublicKey::from(&secret).to_bytes(),
                };
                let f = ch.to_frame();
                sess.send_labeled($label, &f);
                f.encode()
            }};
        }

        let bytes = match action {
            A::ClientHelloV1 => hello!(VERSION, "CLIENT_HELLO"),
            A::ClientHelloBadVersion => {
                hello!(scp_core::wire::UNSUPPORTED_VERSION, "CLIENT_HELLO(bad-version)")
            }
            A::ClientFinishValid => {
                let cf = ClientFinish {
                    verify: sess.client_verify().ok_or("no handshake state")?,
                }
                .to_frame();
                sess.send_labeled("CLIENT_FINISH", &cf);
                cf.encode()
            }
            A::ClientFinishBadMac => {
                let cf = ClientFinish { verify: [0x5a; 32] }.to_frame();
                sess.send_labeled("CLIENT_FINISH(bad-mac)", &cf);
                cf.encode()
            }
            A::SessionResumeValid => {
                let ticket = self.ticket.ok_or("no ticket")?;
                let base = self.ticket_base.ok_or("no ticket base")?;
                sess.resume(&ticket, &base)?
            }
            A::SessionResumeInvalidTicket => {
                let mut bad = self.ticket.ok_or("no ticket")?;
                bad[40] ^= 0xff; // corrupt the sealed payload, keep id+expiry
                let base = self.ticket_base.ok_or("no ticket base")?;
                sess.resume(&bad, &base)?
            }
            A::SessionResumeReusedTicket => {
                let ticket = self.ticket.ok_or("no ticket")?;
                let base = self.ticket_base.ok_or("no ticket base")?;
                // Redeem once on a separate connection...
                let mut first = self.target.session(sess.seed ^ 0xBEEF)?;
                let _ = first.resume_established(&ticket, &base)?;
                // ...then present the same ticket here.
                sess.resume(&ticket, &base)?
            }
            A::AppDataInSequence => {
                let seq = sess.send_seq;
                let f = sess.seal_at(MsgType::AppData, b"\x01ping", seq).ok_or("no keys")?;
                sess.send_seq += 1;
                sess.send_labeled("APP_DATA(seq)", &f);
                f.encode()
            }
            A::AppDataGap => {
                let seq = sess.send_seq + 1;
                let f = sess.seal_at(MsgType::AppData, b"\x01ping", seq).ok_or("no keys")?;
                sess.send_labeled("APP_DATA(gap)", &f);
                f.encode()
            }
            A::AppDataReplay => {
                // A true replay only exists once a record has been sent.
                // In Established we prime with a valid record, read the
                // reply, then repeat the identical bytes.  Earlier phases
                // have no prior record, so this action is skipped there by
                // the frontier (see `valid_in_phase`).
                // (Replaying at seq 0 without ever having sent seq 0 would
                // just be a first, legal record.)
                let seq = sess.send_seq;
                let f = sess.seal_at(MsgType::AppData, b"\x01ping", seq).ok_or("no keys")?;
                sess.send_seq += 1;
                if !sess.send_labeled("APP_DATA(first, valid)", &f) {
                    return Err("send failed".into());
                }
                let keys = sess.keys.clone();
                let _ = sess
                    .client
                    .observe_until_quiet(&keys, self.target.reply_timeout);
                sess.send_labeled("APP_DATA(replay of previous frame)", &f);
                f.encode()
            }
            A::AppDataOldEpoch => {
                // Seal at the sequence the server currently expects, so the
                // *only* thing wrong with this record is that its key epoch
                // has been retired (R-5.4).  Using a stale seq as well would
                // make R-4.3 and R-5.4 both apply and the verdict ambiguous.
                let seq = sess.send_seq;
                let f = sess
                    .seal_old_epoch(MsgType::AppData, b"\x01ping", seq)
                    .ok_or("no previous epoch")?;
                sess.send_labeled("APP_DATA(old-epoch)", &f);
                f.encode()
            }
            A::AppDataBadMac => {
                // Correct seq, correct epoch, but the tag is destroyed: the
                // only thing wrong is authenticity (R-4.2).
                let seq = sess.send_seq;
                let mut f = sess.seal_at(MsgType::AppData, b"\x01ping", seq).ok_or("no keys")?;
                let last = f.body.len() - 1;
                f.body[last] ^= 0xff;
                sess.send_labeled("APP_DATA(corrupted-tag)", &f);
                f.encode()
            }
            A::RekeyValid => {
                use rand_core::RngCore;
                let mut contrib = [0u8; 32];
                sess.client.rng().fill_bytes(&mut contrib);
                let f = sess.seal_at(MsgType::Rekey, &contrib, sess.send_seq).ok_or("no keys")?;
                sess.send_seq = 0;
                let cur = sess.keys.cur.take().ok_or("no keys")?;
                let next = scp_core::crypto::rekey_keys(&cur, &contrib);
                sess.keys = Keyset {
                    cur: Some(next),
                    prev: Some(cur),
                };
                sess.send_labeled("REKEY", &f);
                f.encode()
            }
            A::CloseValid => {
                let f = sess
                    .seal_at(MsgType::Close, &[], sess.send_seq)
                    .ok_or("no keys")?;
                sess.send_labeled("CLOSE", &f);
                f.encode()
            }
            A::WireUnknownType => {
                let b = vec![0, 0, 0, 2, 0x99, 0x00];
                sess.send_raw_labeled("wire(unknown-type)", &b);
                b
            }
            A::WireOversize => {
                let b = 20_000u32.to_be_bytes().to_vec();
                sess.send_raw_labeled("wire(oversize)", &b);
                b
            }
            A::ReflectedServerHello => {
                let sh = ServerHello {
                    version: VERSION,
                    random: [0u8; 32],
                    eph: [0u8; 32],
                    suite: scp_core::wire::SUITE,
                    ticket_ttl_ms: 0,
                };
                let f = sh.to_frame();
                sess.send_labeled("wire(reflected-SERVER_HELLO)", &f);
                f.encode()
            }
            A::IdlePastDeadline | A::IdlePastIdleTimeout => Vec::new(),
        };
        Ok(bytes)
    }

    /// Collect everything the target does after the last input.
    pub fn collect(&mut self, action: crate::model::Action) -> Vec<Observed> {
        use crate::model::Action as A;
        let quiet = match action {
            A::IdlePastDeadline => self.target.handshake_timeout,
            A::IdlePastIdleTimeout => Duration::from_millis(3200),
            _ => self.target.reply_timeout,
        };
        let keys = self.session.keys.clone();
        let mut o = self.session.client.observe_until_quiet(&keys, quiet);
        if o.is_empty() {
            o.push(Observed::Timeout);
        }
        o
    }
}

/// Execute one trial, honouring the connection context.
pub fn run_trial(
    target: &Target,
    trial: crate::explore::Trial,
    seed: u64,
) -> Result<(Reaction, Vec<u8>), String> {
    use crate::model::Action as A;
    let action = trial.action;
    let needs_ticket = matches!(
        action,
        A::SessionResumeValid | A::SessionResumeInvalidTicket | A::SessionResumeReusedTicket
    );
    let mut sc = if needs_ticket {
        Scenario::with_ticket(target, seed)?
    } else {
        Scenario::new(target, seed)?
    };
    let with_rekey = matches!(action, A::AppDataOldEpoch);
    sc.reach(trial.phase, with_rekey)?;
    if trial.context == crate::explore::Context::AfterActivity {
        sc.activity_roundtrip()?;
    }
    let sent = sc.present(action)?;
    let observed = sc.collect(action);
    Ok((Reaction::classify(observed, action), sent))
}

/// Execute one full case.  `with_rekey` is inferred from the action.
pub fn run_case(
    target: &Target,
    phase: crate::model::Phase,
    action: crate::model::Action,
    seed: u64,
) -> Result<(Reaction, Vec<u8>), String> {
    use crate::model::Action as A;
    let needs_ticket = matches!(
        action,
        A::SessionResumeValid | A::SessionResumeInvalidTicket | A::SessionResumeReusedTicket
    );
    let mut sc = if needs_ticket {
        Scenario::with_ticket(target, seed)?
    } else {
        Scenario::new(target, seed)?
    };
    let with_rekey = matches!(action, A::AppDataOldEpoch);
    sc.reach(phase, with_rekey)?;
    let sent = sc.present(action)?;
    let observed = sc.collect(action);
    Ok((Reaction::classify(observed, action), sent))
}

/// A conforming server says nothing on a fresh connection until the client
/// speaks.  This is the one check that must pass before any verdict is
/// attributed to a state-machine fault.
pub fn silent_on_connect(target: &Target, seed: u64) -> Vec<Observed> {
    let Ok(mut c) = Client::connect(target.addr, seed) else {
        return vec![];
    };
    c.observe_until_quiet(&Keyset::default(), Duration::from_millis(150))
}
