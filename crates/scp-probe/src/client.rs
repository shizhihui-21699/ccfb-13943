//! The probe's only view of the target: a scriptable SCP/1 client.
//!
//! It implements the client half of the protocol exactly (SPEC §3, §5, §6)
//! and also exposes raw-frame primitives so a test can send things a
//! conforming client never would: early records, replays, old-epoch
//! records, reflected server frames, malformed bodies, oversize length
//! prefixes.
//!
//! Everything the probe learns about the target comes back through
//! [`Observed`].  There is no other channel: the probe never reads the
//! target's source, files, or logs.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use scp_core::crypto::{rekey_keys, resume_keys, resume_psk, HandshakeState, Side, TrafficKeys};
use scp_core::wire::{
    ClientFinish, ClientHello, ErrorCode, Frame, FrameDecoder, MsgType, ResumeOk, Sealed,
    ServerFinish, ServerHello, SessionResume, TICKET_LEN, VERSION,
};
use x25519_dalek::{PublicKey, StaticSecret};

/// The directional keys a client currently believes are live, plus the
/// immediately preceding epoch's keys (so the observer can tell an
/// old-epoch record from a merely corrupt one).
#[derive(Clone, Default)]
pub struct Keyset {
    pub cur: Option<TrafficKeys>,
    pub prev: Option<TrafficKeys>,
}

impl Keyset {
    fn of(k: TrafficKeys) -> Self {
        Keyset {
            cur: Some(k),
            prev: None,
        }
    }
}

/// Anything the target sent, reduced to what a black-box observer can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observed {
    ServerHello {
        version: u16,
        suite: u16,
        ticket_ttl_ms: u32,
    },
    ServerFinish {
        verify_ok: bool,
        ticket: [u8; TICKET_LEN],
    },
    ResumeOk {
        ticket: [u8; TICKET_LEN],
    },
    /// A record that authenticated under the current key epoch.
    AppData(Vec<u8>),
    /// A record that authenticated only under the *previous* epoch's key.
    AppDataOldEpoch(Vec<u8>),
    Rekey {
        contribution: Vec<u8>,
        old_epoch: bool,
    },
    CloseRecv,
    Err(ErrorCode),
    /// Bytes that did not parse as a legal frame, or a record that did not
    /// authenticate under any key we hold.
    Garbage { len: usize },
    Closed,
    Timeout,
}

impl Observed {
    pub fn is_err(&self) -> bool {
        matches!(self, Observed::Err(_))
    }

    pub fn err_code(&self) -> Option<ErrorCode> {
        match self {
            Observed::Err(c) => Some(*c),
            _ => None,
        }
    }

    pub fn short(&self) -> String {
        match self {
            Observed::ServerHello { suite, .. } => format!("SERVER_HELLO(suite={suite})"),
            Observed::ServerFinish { verify_ok, .. } => {
                format!("SERVER_FINISH(verify_ok={verify_ok})")
            }
            Observed::ResumeOk { .. } => "RESUME_OK".into(),
            Observed::AppData(pt) => format!("APP_DATA({})", hex::encode(pt)),
            Observed::AppDataOldEpoch(pt) => {
                format!("APP_DATA_AT_OLD_EPOCH({})", hex::encode(pt))
            }
            Observed::Rekey { old_epoch, .. } => format!("REKEY(old_epoch={old_epoch})"),
            Observed::CloseRecv => "CLOSE".into(),
            Observed::Err(c) => format!("ERR({})", c.name()),
            Observed::Garbage { len } => format!("UNPARSED({len}B)"),
            Observed::Closed => "CLOSED".into(),
            Observed::Timeout => "SILENCE".into(),
        }
    }
}

/// One client-side TCP connection.
pub struct Client {
    stream: TcpStream,
    dec: FrameDecoder,
    rng: ChaCha20Rng,
    pub closed: bool,
    pub sent_bytes: usize,
    pub recv_bytes: usize,
    pub reply_timeout: Duration,
}

impl Client {
    pub fn connect(addr: SocketAddr, seed: u64) -> std::io::Result<Client> {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
        stream.set_nodelay(true)?;
        Ok(Client {
            stream,
            dec: FrameDecoder::new(),
            rng: ChaCha20Rng::seed_from_u64(seed),
            closed: false,
            sent_bytes: 0,
            recv_bytes: 0,
            reply_timeout: Duration::from_millis(200),
        })
    }

    pub fn rng(&mut self) -> &mut ChaCha20Rng {
        &mut self.rng
    }

    pub fn random32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.rng.fill_bytes(&mut b);
        b
    }

    pub fn random16(&mut self) -> [u8; 16] {
        let mut b = [0u8; 16];
        self.rng.fill_bytes(&mut b);
        b
    }

    pub fn send_frame(&mut self, f: &Frame) -> bool {
        self.send_raw(&f.encode())
    }

    pub fn send_raw(&mut self, bytes: &[u8]) -> bool {
        if self.closed {
            return false;
        }
        self.sent_bytes += bytes.len();
        match self.stream.write_all(bytes).and_then(|_| self.stream.flush()) {
            Ok(()) => true,
            Err(_) => {
                self.closed = true;
                false
            }
        }
    }

    fn fill(&mut self, timeout: Duration) -> bool {
        let _ = self.stream.set_read_timeout(Some(timeout));
        let mut buf = [0u8; 8192];
        match self.stream.read(&mut buf) {
            Ok(0) => {
                self.closed = true;
                false
            }
            Ok(n) => {
                self.recv_bytes += n;
                self.dec.push(&buf[..n]);
                true
            }
            Err(e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut
                    || e.kind() == ErrorKind::Interrupted =>
            {
                true
            }
            Err(_) => {
                self.closed = true;
                false
            }
        }
    }

    /// Read the next raw frame, waiting up to `timeout`.
    pub fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, Observed> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.closed {
                return Ok(None);
            }
            match self.dec.next_frame() {
                Ok(Some(f)) => return Ok(Some(f)),
                Ok(None) => {}
                Err(_) => return Err(Observed::Garbage { len: self.dec.buffered() }),
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            self.fill(deadline - now);
        }
    }

    /// Read and interpret one server message under `keys`.
    pub fn observe(&mut self, timeout: Duration, keys: &Keyset) -> Observed {
        let frame = match self.next_frame(timeout) {
            Ok(Some(f)) => f,
            Ok(None) => {
                return if self.closed {
                    Observed::Closed
                } else {
                    Observed::Timeout
                }
            }
            Err(o) => return o,
        };
        interpret(frame, keys)
    }

    /// Read until the target goes quiet for `quiet` or closes.
    pub fn observe_until_quiet(&mut self, keys: &Keyset, quiet: Duration) -> Vec<Observed> {
        let mut out = Vec::new();
        loop {
            match self.observe(quiet, keys) {
                Observed::Timeout => break,
                Observed::Closed => {
                    out.push(Observed::Closed);
                    break;
                }
                other => out.push(other),
            }
        }
        out
    }

    pub fn close(&mut self) {
        self.closed = true;
        let _ = self.stream.flush();
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Turn one frame into an [`Observed`] using whatever keys we believe are
/// live.  `Err` frames and plaintext handshake frames are interpreted
/// directly; records are authenticated.
pub fn interpret(frame: Frame, keys: &Keyset) -> Observed {
    match frame.mtype {
        MsgType::ServerHello => match ServerHello::parse(&frame.body) {
            Ok(sh) => Observed::ServerHello {
                version: sh.version,
                suite: sh.suite,
                ticket_ttl_ms: sh.ticket_ttl_ms,
            },
            Err(_) => Observed::Garbage {
                len: frame.encoded_len(),
            },
        },
        MsgType::ServerFinish => match ServerFinish::parse(&frame.body) {
            // The caller decides whether `verify` matched; shape-only here.
            Ok(sf) => Observed::ServerFinish {
                verify_ok: false,
                ticket: sf.ticket,
            },
            Err(_) => Observed::Garbage {
                len: frame.encoded_len(),
            },
        },
        MsgType::ResumeOk => match ResumeOk::parse(&frame.body) {
            Ok(r) => Observed::ResumeOk { ticket: r.ticket },
            Err(_) => Observed::Garbage {
                len: frame.encoded_len(),
            },
        },
        MsgType::Err => Observed::Err(frame.err_code()),
        MsgType::AppData | MsgType::Rekey | MsgType::Close => {
            let sealed = match Sealed::parse(&frame.body, "record") {
                Ok(s) => s,
                Err(_) => {
                    return Observed::Garbage {
                        len: frame.encoded_len(),
                    }
                }
            };
            let aad = [frame.mtype as u8];
            let try_at = |k: &TrafficKeys| {
                scp_core::crypto::open(k.recv(Side::Client), k.epoch, sealed.seq, &aad, &sealed.ct)
            };
            let (pt, old) = match keys.cur.as_ref().and_then(|k| try_at(k).map(|p| (p, false))) {
                Some(x) => x,
                None => match keys.prev.as_ref().and_then(|k| try_at(k).map(|p| (p, true))) {
                    Some(x) => x,
                    None => {
                        return Observed::Garbage {
                            len: frame.encoded_len(),
                        }
                    }
                },
            };
            match (frame.mtype, old) {
                (MsgType::AppData, true) => Observed::AppDataOldEpoch(pt),
                (MsgType::AppData, false) => Observed::AppData(pt),
                (MsgType::Rekey, old) => Observed::Rekey {
                    contribution: pt,
                    old_epoch: old,
                },
                (MsgType::Close, _) => Observed::CloseRecv,
                _ => Observed::Garbage {
                    len: frame.encoded_len(),
                },
            }
        }
        _ => Observed::Garbage {
            len: frame.encoded_len(),
        },
    }
}

// ---------------------------------------------------------------------------
// A scriptable session
// ---------------------------------------------------------------------------

/// A client session with real protocol state.  Every method that sends
/// also records the exact bytes, so a finding can replay them.
pub struct Session {
    pub client: Client,
    pub seed: u64,
    st: Option<HandshakeState>,
    pending_secret: Option<StaticSecret>,
    ch_body: Vec<u8>,
    sh_body: Vec<u8>,
    pub keys: Keyset,
    pub send_seq: u64,
    pub ticket: Option<[u8; TICKET_LEN]>,
    pub ticket_base: Option<[u8; 32]>,
    pub established: bool,
    /// Every frame the probe put on the wire, in order, with a label.
    pub transcript: Vec<(String, Vec<u8>)>,
}

impl Session {
    pub fn new(addr: SocketAddr, seed: u64) -> std::io::Result<Session> {
        Ok(Session {
            client: Client::connect(addr, seed)?,
            seed,
            st: None,
            pending_secret: None,
            ch_body: Vec::new(),
            sh_body: Vec::new(),
            keys: Keyset::default(),
            send_seq: 0,
            ticket: None,
            ticket_base: None,
            established: false,
            transcript: Vec::new(),
        })
    }

    pub fn record(&mut self, label: impl Into<String>, bytes: &[u8]) {
        self.transcript.push((label.into(), bytes.to_vec()));
    }

    pub fn send_labeled(&mut self, label: impl Into<String>, f: &Frame) -> bool {
        let bytes = f.encode();
        self.record(label, &bytes);
        self.client.send_frame(f)
    }

    pub fn send_raw_labeled(&mut self, label: impl Into<String>, bytes: &[u8]) -> bool {
        self.record(label, bytes);
        self.client.send_raw(bytes)
    }

    /// Build and send CLIENT_HELLO; wait for SERVER_HELLO; derive early
    /// (epoch-0) keys.  Does **not** send CLIENT_FINISH.  This is the state
    /// from which early-data attacks are launched.
    pub fn hello_flight(&mut self, version: u16) -> Result<(), String> {
        let secret = StaticSecret::from(self.client.random32());
        let random = self.client.random32();
        let ch = ClientHello {
            version,
            random,
            eph: PublicKey::from(&secret).to_bytes(),
        };
        let chf = ch.to_frame();
        self.ch_body = chf.body.clone();
        self.pending_secret = Some(secret);
        if !self.send_labeled("CLIENT_HELLO", &chf) {
            return Err("send CLIENT_HELLO failed".into());
        }
        let sh = match self.client.next_frame(self.client.reply_timeout) {
            Ok(Some(f)) if f.mtype == MsgType::ServerHello => f,
            Ok(Some(f)) => return Err(format!("expected SERVER_HELLO, got {}", f.mtype.name())),
            Ok(None) => return Err("no SERVER_HELLO".into()),
            Err(o) => return Err(format!("unparsed bytes: {o:?}")),
        };
        let parsed = ServerHello::parse(&sh.body).map_err(|e| format!("bad SERVER_HELLO: {e}"))?;
        self.sh_body = sh.body.clone();
        let secret = self.pending_secret.take().expect("secret");
        let st = HandshakeState::new_hello(
            Side::Client,
            secret,
            random,
            parsed.eph,
            parsed.random,
            &self.ch_body,
            &self.sh_body,
        );
        self.keys = Keyset::of(st.app_keys());
        self.st = Some(st);
        Ok(())
    }

    /// Send CLIENT_FINISH and wait for SERVER_FINISH; installs app keys and
    /// stores the issued ticket.
    pub fn finish_flight(&mut self) -> Result<Observed, String> {
        let st = self.st.as_ref().ok_or("hello not done")?;
        let cf = ClientFinish {
            verify: st.client_verify,
        };
        if !self.send_labeled("CLIENT_FINISH", &cf.to_frame()) {
            return Err("send CLIENT_FINISH failed".into());
        }
        let sf = match self.client.next_frame(self.client.reply_timeout) {
            Ok(Some(f)) if f.mtype == MsgType::ServerFinish => f,
            Ok(Some(f)) => return Ok(interpret(f, &self.keys)),
            Ok(None) => {
                return Ok(if self.client.closed {
                    Observed::Closed
                } else {
                    Observed::Timeout
                })
            }
            Err(o) => return Ok(o),
        };
        let parsed = match ServerFinish::parse(&sf.body) {
            Ok(p) => p,
            Err(_) => {
                return Ok(Observed::Garbage {
                    len: sf.encoded_len(),
                })
            }
        };
        let st = self.st.as_ref().unwrap();
        let verify_ok = parsed.verify == st.server_verify;
        self.ticket = Some(parsed.ticket);
        self.ticket_base = Some(st.ticket_base());
        self.send_seq = 0;
        self.established = true;
        Ok(Observed::ServerFinish {
            verify_ok,
            ticket: parsed.ticket,
        })
    }

    /// A complete, conforming handshake.
    pub fn handshake(&mut self) -> Result<(), String> {
        self.hello_flight(VERSION)?;
        match self.finish_flight()? {
            Observed::ServerFinish { verify_ok: true, .. } => Ok(()),
            other => Err(format!("handshake did not complete: {}", other.short())),
        }
    }

    // ---- record production ------------------------------------------------

    pub fn seal_at(&self, mtype: MsgType, plaintext: &[u8], seq: u64) -> Option<Frame> {
        let k = self.keys.cur.as_ref()?;
        Some(self.seal_with_keys(k, mtype, plaintext, seq))
    }

    pub fn seal_with_keys(
        &self,
        keys: &TrafficKeys,
        mtype: MsgType,
        plaintext: &[u8],
        seq: u64,
    ) -> Frame {
        let ct = scp_core::crypto::seal(
            keys.send(Side::Client),
            keys.epoch,
            seq,
            &[mtype as u8],
            plaintext,
        );
        Sealed { seq, ct }.to_frame(mtype)
    }

    /// Seal under the *retired* epoch (must have done a rekey first).
    pub fn seal_old_epoch(&self, mtype: MsgType, plaintext: &[u8], seq: u64) -> Option<Frame> {
        let k = self.keys.prev.as_ref()?;
        Some(self.seal_with_keys(k, mtype, plaintext, seq))
    }

    /// Send APP_DATA with the next receive-sequence the server expects.
    pub fn send_app(&mut self, plaintext: &[u8]) -> bool {
        let Some(f) = self.seal_at(MsgType::AppData, plaintext, self.send_seq) else {
            return false;
        };
        self.send_seq += 1;
        self.send_labeled("APP_DATA", &f)
    }

    /// Perform a rekey: send REKEY with a fresh contribution and rotate the
    /// client's keys to the next epoch.
    pub fn rekey(&mut self) -> Option<Vec<Observed>> {
        let mut contrib = [0u8; 32];
        self.client.rng.fill_bytes(&mut contrib);
        let f = self.seal_at(MsgType::Rekey, &contrib, self.send_seq)?;
        self.send_seq = 0;
        let cur = self.keys.cur.take()?;
        let next = rekey_keys(&cur, &contrib);
        self.keys = Keyset {
            cur: Some(next),
            prev: Some(cur),
        };
        if !self.send_labeled("REKEY", &f) {
            return Some(vec![Observed::Closed]);
        }
        Some(self.client.observe_until_quiet(&self.keys, self.client.reply_timeout))
    }

    /// The CLIENT_FINISH verifier for the current handshake (needed to
    /// present a *valid* finish in phases where the probe did not send one
    /// as part of setup).
    pub fn client_verify(&self) -> Option<[u8; 32]> {
        self.st.as_ref().map(|s| s.client_verify)
    }

    /// Send SESSION_RESUME.  Deliberately does **not** consume the reply:
    /// the caller's `collect` step reads it, so a reply can never be
    /// swallowed and mistaken for silence.
    pub fn resume(
        &mut self,
        ticket: &[u8; TICKET_LEN],
        _psk_base: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let cr = self.client.random32();
        let secret = StaticSecret::from(self.client.random32());
        let eph = PublicKey::from(&secret).to_bytes();
        let sr = SessionResume {
            ticket: *ticket,
            client_random: cr,
            eph,
        };
        let frame = sr.to_frame();
        let bytes = frame.encode();
        if !self.send_labeled("SESSION_RESUME", &frame) {
            return Err("send failed".into());
        }
        Ok(bytes)
    }

    /// Send SESSION_RESUME and consume RESUME_OK, installing resumed keys.
    /// Used only for setup paths that must actually establish a session.
    pub fn resume_established(
        &mut self,
        ticket: &[u8; TICKET_LEN],
        psk_base: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let cr = self.client.random32();
        let secret = StaticSecret::from(self.client.random32());
        let eph = PublicKey::from(&secret).to_bytes();
        let sr = SessionResume {
            ticket: *ticket,
            client_random: cr,
            eph,
        };
        let frame = sr.to_frame();
        let bytes = frame.encode();
        if !self.send_labeled("SESSION_RESUME", &frame) {
            return Err("send failed".into());
        }
        let ok = match self.client.next_frame(self.client.reply_timeout) {
            Ok(Some(f)) if f.mtype == MsgType::ResumeOk => f,
            _ => return Ok(bytes),
        };
        let parsed = ResumeOk::parse(&ok.body).map_err(|e| format!("bad RESUME_OK: {e}"))?;
        let shared_dh = secret
            .diffie_hellman(&PublicKey::from(parsed.eph))
            .to_bytes();
        let psk = resume_psk(psk_base, ticket_first16(ticket), ticket_expiry(ticket));
        let rk = resume_keys(
            &psk,
            ticket,
            &cr,
            &parsed.server_random,
            &eph,
            &parsed.eph,
            &shared_dh,
        );
        self.keys = Keyset::of(rk.keys);
        self.ticket = Some(parsed.ticket);
        self.ticket_base = Some(rk.base);
        self.send_seq = 0;
        self.established = true;
        Ok(bytes)
    }
}

/// Ticket helpers the probe legitimately needs: the id and expiry are
/// public parts of the opaque blob (SPEC R-6.1).
pub fn ticket_first16(t: &[u8; TICKET_LEN]) -> &[u8; 16] {
    t[..16].try_into().unwrap()
}

pub fn ticket_expiry(t: &[u8; TICKET_LEN]) -> u64 {
    u64::from_be_bytes(t[16..24].try_into().unwrap())
}
