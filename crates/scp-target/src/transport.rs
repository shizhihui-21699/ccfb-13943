//! Shared plumbing for every target implementation: byte channels, a framed
//! link, clock helpers, and classification of wire-level failures.
//!
//! **No ordering rules live here.** Each implementation in `impls/` writes
//! its own state machine; that is the whole point of the exercise.

use std::collections::HashSet;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use scp_core::crypto::KEY_LEN;
use scp_core::wire::{ErrorCode, Frame, FrameDecoder, MsgType, WireError};

pub const DEFAULT_MAX_FRAME: usize = scp_core::wire::MAX_FRAME;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn fresh_ticket_root(rng: &mut impl rand_core::RngCore) -> [u8; KEY_LEN] {
    let mut k = [0u8; KEY_LEN];
    rng.fill_bytes(&mut k);
    k
}

// ---------------------------------------------------------------------------
// Byte channels
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ChanRecv {
    Data(Vec<u8>),
    Timeout,
    Eof,
}

pub trait Channel: Send {
    fn recv(&mut self, timeout: Duration) -> ChanRecv;
    fn send(&mut self, data: &[u8]) -> bool;
    fn close(&mut self);
    fn peer(&self) -> String;
}

pub struct TcpChannel {
    stream: TcpStream,
    peer: String,
    closed: bool,
}

impl TcpChannel {
    pub fn new(stream: TcpStream) -> Self {
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "<unknown>".into());
        TcpChannel {
            stream,
            peer,
            closed: false,
        }
    }
}

impl Channel for TcpChannel {
    fn recv(&mut self, timeout: Duration) -> ChanRecv {
        if self.closed {
            return ChanRecv::Eof;
        }
        if self.stream.set_read_timeout(Some(timeout)).is_err() {
            return ChanRecv::Eof;
        }
        let mut buf = [0u8; 8192];
        match self.stream.read(&mut buf) {
            Ok(0) => {
                self.closed = true;
                ChanRecv::Eof
            }
            Ok(n) => ChanRecv::Data(buf[..n].to_vec()),
            Err(e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut
                    || e.kind() == ErrorKind::Interrupted =>
            {
                ChanRecv::Timeout
            }
            Err(_) => {
                self.closed = true;
                ChanRecv::Eof
            }
        }
    }

    fn send(&mut self, data: &[u8]) -> bool {
        if self.closed {
            return false;
        }
        match self.stream.write_all(data).and_then(|_| self.stream.flush()) {
            Ok(()) => true,
            Err(_) => {
                self.closed = true;
                false
            }
        }
    }

    fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            let _ = self.stream.flush();
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
        }
    }

    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// In-memory duplex pipe. Used to run the reference server in-process.
pub struct MemChannel {
    tx: Option<Sender<Vec<u8>>>,
    rx: Receiver<Vec<u8>>,
    peer: String,
    closed: bool,
}

impl MemChannel {
    pub fn pair() -> (MemChannel, MemChannel) {
        let (a_tx, a_rx) = std::sync::mpsc::channel();
        let (b_tx, b_rx) = std::sync::mpsc::channel();
        (
            MemChannel {
                tx: Some(a_tx),
                rx: b_rx,
                peer: "mem:a".into(),
                closed: false,
            },
            MemChannel {
                tx: Some(b_tx),
                rx: a_rx,
                peer: "mem:b".into(),
                closed: false,
            },
        )
    }
}

impl Channel for MemChannel {
    fn recv(&mut self, timeout: Duration) -> ChanRecv {
        if self.closed {
            return ChanRecv::Eof;
        }
        match self.rx.recv_timeout(timeout) {
            Ok(v) => ChanRecv::Data(v),
            Err(RecvTimeoutError::Timeout) => ChanRecv::Timeout,
            Err(RecvTimeoutError::Disconnected) => {
                self.closed = true;
                ChanRecv::Eof
            }
        }
    }

    fn send(&mut self, data: &[u8]) -> bool {
        match &self.tx {
            Some(tx) => tx.send(data.to_vec()).is_ok(),
            None => false,
        }
    }

    fn close(&mut self) {
        self.closed = true;
        self.tx = None;
    }

    fn peer(&self) -> String {
        self.peer.clone()
    }
}

// ---------------------------------------------------------------------------
// Shared process state
// ---------------------------------------------------------------------------

/// State shared by all connections of one server process: the ticket root
/// (so a ticket issued on one connection is valid on the next), the set of
/// already-redeemed ticket ids (SPEC R-6.4), and a counter for logging.
#[derive(Clone)]
pub struct Shared {
    pub ticket_root: Arc<[u8; KEY_LEN]>,
    pub redeemed: Arc<Mutex<HashSet<[u8; 16]>>>,
    pub conn_id: Arc<AtomicU64>,
}

impl Shared {
    pub fn new(rng: &mut impl rand_core::RngCore) -> Self {
        Shared {
            ticket_root: Arc::new(fresh_ticket_root(rng)),
            redeemed: Arc::new(Mutex::new(HashSet::new())),
            conn_id: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn next_conn(&self) -> u64 {
        self.conn_id.fetch_add(1, Ordering::Relaxed)
    }
}

/// The configuration of one target server process.
#[derive(Clone)]
pub struct ServerCfg {
    pub max_frame: usize,
    pub handshake_deadline: Duration,
    pub idle_timeout: Duration,
    pub ticket_ttl_ms: u64,
}

impl Default for ServerCfg {
    fn default() -> Self {
        ServerCfg {
            max_frame: DEFAULT_MAX_FRAME,
            handshake_deadline: Duration::from_millis(scp_core::wire::HANDSHAKE_DEADLINE_MS),
            idle_timeout: Duration::from_millis(scp_core::wire::IDLE_TIMEOUT_MS),
            ticket_ttl_ms: scp_core::wire::TICKET_TTL_MS as u64,
        }
    }
}

// ---------------------------------------------------------------------------
// Framed link
// ---------------------------------------------------------------------------

pub enum Recv {
    Frame(Frame),
    TimedOut,
    Closed,
    Bad(WireError),
}

pub struct Link {
    chan: Box<dyn Channel>,
    dec: FrameDecoder,
    pub closed: bool,
}

impl Link {
    pub fn new(chan: Box<dyn Channel>, max_frame: usize) -> Self {
        Link {
            chan,
            dec: FrameDecoder::with_max(max_frame),
            closed: false,
        }
    }

    pub fn peer(&self) -> String {
        self.chan.peer()
    }

    pub fn send(&mut self, frame: &Frame) -> bool {
        if self.closed {
            return false;
        }
        if !self.chan.send(&frame.encode()) {
            self.closed = true;
            return false;
        }
        true
    }

    pub fn send_err(&mut self, code: ErrorCode) -> bool {
        self.send(&Frame::err(code))
    }

    /// Send `ERR(code)` then close. Callers return immediately.
    pub fn fail(&mut self, code: ErrorCode) {
        self.send_err(code);
        self.close();
    }

    pub fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.chan.close();
        }
    }

    pub fn recv(&mut self, timeout: Duration) -> Recv {
        if self.closed {
            return Recv::Closed;
        }
        let deadline = Instant::now() + timeout;
        loop {
            match self.dec.next_frame() {
                Ok(Some(f)) => return Recv::Frame(f),
                Ok(None) => {}
                Err(e) => return Recv::Bad(e),
            }
            let now = Instant::now();
            if now >= deadline {
                return Recv::TimedOut;
            }
            match self.chan.recv(deadline - now) {
                ChanRecv::Data(b) => self.dec.push(&b),
                ChanRecv::Timeout => return Recv::TimedOut,
                ChanRecv::Eof => {
                    self.closed = true;
                    return Recv::Closed;
                }
            }
        }
    }
}

pub fn wire_error_code(e: &WireError) -> ErrorCode {
    match e {
        WireError::TooLarge(_) | WireError::Truncated => ErrorCode::TooLarge,
        WireError::UnknownType(_) | WireError::Malformed(_) => ErrorCode::DecodeError,
    }
}

/// Message types only a server may send; receiving one is reflection
/// (SPEC R-1.4).
pub fn is_server_type(m: MsgType) -> bool {
    matches!(
        m,
        MsgType::ServerHello | MsgType::ServerFinish | MsgType::ResumeOk | MsgType::Err
    )
}
