//! Wire format for SCP/1 (Secure Channel Protocol, version 1).
//!
//! A frame is `body_len: u32` (big-endian, number of bytes that follow),
//! then `mtype: u8`, then the message body.  `body_len` includes the type
//! byte, so the smallest legal frame is 1 byte of length + 1 byte of type.
//!
//! Nothing in this module depends on which side is speaking: the same
//! encoders are used by the reference server, by every target under test,
//! and by the probe client.

use thiserror::Error;

pub const MAX_FRAME: usize = 16 * 1024;

pub const VERSION: u16 = 1;
pub const UNSUPPORTED_VERSION: u16 = 0x0200;
pub const SUITE: u16 = 1;

pub const RANDOM_LEN: usize = 32;
pub const PUB_LEN: usize = 32;
pub const VERIFY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const TICKET_ID_LEN: usize = 16;
pub const TICKET_EXPIRY_LEN: usize = 8;
pub const TICKET_SEALED_LEN: usize = 32 + TAG_LEN;
/// `ticket_id || expiry_ms || AEAD(psk)`. Opaque to the peer.
pub const TICKET_LEN: usize = TICKET_ID_LEN + TICKET_EXPIRY_LEN + TICKET_SEALED_LEN;

/// Ticket lifetime advertised by the reference implementation (logical ms).
pub const TICKET_TTL_MS: u32 = 60_000;

/// Handshake deadline, in milliseconds, measured from TCP accept.
/// SPEC.md R-7.1: if the handshake has not completed by then the server must
/// send `ERR(DeadlineExceeded)` and close.
pub const HANDSHAKE_DEADLINE_MS: u64 = 400;

/// Idle timeout for an established connection, in milliseconds.
/// SPEC.md R-7.2: the server closes silently after 1500–3000 ms idle.
pub const IDLE_TIMEOUT_MS: u64 = 1500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum MsgType {
    ClientHello = 0x01,
    ServerHello = 0x02,
    ClientFinish = 0x03,
    ServerFinish = 0x04,
    AppData = 0x10,
    Rekey = 0x20,
    Close = 0x30,
    SessionResume = 0x40,
    ResumeOk = 0x41,
    Err = 0x7f,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => MsgType::ClientHello,
            0x02 => MsgType::ServerHello,
            0x03 => MsgType::ClientFinish,
            0x04 => MsgType::ServerFinish,
            0x10 => MsgType::AppData,
            0x20 => MsgType::Rekey,
            0x30 => MsgType::Close,
            0x40 => MsgType::SessionResume,
            0x41 => MsgType::ResumeOk,
            0x7f => MsgType::Err,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            MsgType::ClientHello => "CLIENT_HELLO",
            MsgType::ServerHello => "SERVER_HELLO",
            MsgType::ClientFinish => "CLIENT_FINISH",
            MsgType::ServerFinish => "SERVER_FINISH",
            MsgType::AppData => "APP_DATA",
            MsgType::Rekey => "REKEY",
            MsgType::Close => "CLOSE",
            MsgType::SessionResume => "SESSION_RESUME",
            MsgType::ResumeOk => "RESUME_OK",
            MsgType::Err => "ERR",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ErrorCode {
    UnexpectedMessage = 1,
    BadVersion = 2,
    BadMac = 3,
    BadState = 4,
    Replay = 5,
    TicketInvalid = 6,
    TooLarge = 7,
    Internal = 8,
    DeadlineExceeded = 9,
    /// Frame could not be decoded, or was sent by the wrong party.
    DecodeError = 10,
}

impl ErrorCode {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => ErrorCode::UnexpectedMessage,
            2 => ErrorCode::BadVersion,
            3 => ErrorCode::BadMac,
            4 => ErrorCode::BadState,
            5 => ErrorCode::Replay,
            6 => ErrorCode::TicketInvalid,
            7 => ErrorCode::TooLarge,
            8 => ErrorCode::Internal,
            9 => ErrorCode::DeadlineExceeded,
            _ => ErrorCode::DecodeError,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ErrorCode::UnexpectedMessage => "UnexpectedMessage",
            ErrorCode::BadVersion => "BadVersion",
            ErrorCode::BadMac => "BadMac",
            ErrorCode::BadState => "BadState",
            ErrorCode::Replay => "Replay",
            ErrorCode::TicketInvalid => "TicketInvalid",
            ErrorCode::TooLarge => "TooLarge",
            ErrorCode::Internal => "Internal",
            ErrorCode::DeadlineExceeded => "DeadlineExceeded",
            ErrorCode::DecodeError => "DecodeError",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
    #[error("truncated frame")]
    Truncated,
    #[error("unknown message type {0:#04x}")]
    UnknownType(u8),
    #[error("malformed body for {0}")]
    Malformed(&'static str),
}

/// A decoded frame. Bodies stay as raw bytes; typed views are provided by the
/// `msg` structs below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub mtype: MsgType,
    pub body: Vec<u8>,
}

impl Frame {
    pub fn new(mtype: MsgType, body: Vec<u8>) -> Self {
        Frame { mtype, body }
    }

    pub fn err(code: ErrorCode) -> Self {
        Frame::new(MsgType::Err, (code as u16).to_be_bytes().to_vec())
    }

    pub fn encode(&self) -> Vec<u8> {
        let total = 1 + self.body.len();
        let mut out = Vec::with_capacity(4 + total);
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.push(self.mtype as u8);
        out.extend_from_slice(&self.body);
        out
    }

    pub fn encoded_len(&self) -> usize {
        4 + 1 + self.body.len()
    }
}

/// Byte-level reader with bounds checking, so a hostile frame can never panic
/// a parser.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8], what: &'static str) -> Self {
        Reader { buf, pos: 0, what }
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        let b = *self.buf.get(self.pos).ok_or(WireError::Malformed(self.what))?;
        self.pos += 1;
        Ok(b)
    }

    pub fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let end = self.pos + N;
        if end > self.buf.len() {
            return Err(WireError::Malformed(self.what));
        }
        let mut a = [0u8; N];
        a.copy_from_slice(&self.buf[self.pos..end]);
        self.pos = end;
        Ok(a)
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos + n;
        if end > self.buf.len() {
            return Err(WireError::Malformed(self.what));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    pub fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Incremental frame decoder for a byte stream.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    /// Largest legal `body_len` (inclusive). SPEC.md R-1.1/R-1.2.
    max: usize,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::with_max(MAX_FRAME)
    }

    pub fn with_max(max: usize) -> Self {
        FrameDecoder {
            buf: Vec::new(),
            max,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Try to pop one complete frame.
    ///
    /// Returns `Ok(None)` when more bytes are needed.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, WireError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len == 0 {
            return Err(WireError::Truncated);
        }
        if len > self.max {
            return Err(WireError::TooLarge(len));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let mtype = MsgType::from_u8(self.buf[4]).ok_or(WireError::UnknownType(self.buf[4]))?;
        let body = self.buf[5..4 + len].to_vec();
        self.buf.drain(..4 + len);
        Ok(Some(Frame::new(mtype, body)))
    }
}

// ---------------------------------------------------------------------------
// Typed messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub version: u16,
    pub random: [u8; RANDOM_LEN],
    pub eph: [u8; PUB_LEN],
}

impl ClientHello {
    pub fn to_frame(&self) -> Frame {
        let mut b = Vec::with_capacity(2 + RANDOM_LEN + PUB_LEN);
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&self.random);
        b.extend_from_slice(&self.eph);
        Frame::new(MsgType::ClientHello, b)
    }

    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body, "CLIENT_HELLO");
        let m = ClientHello {
            version: r.u16()?,
            random: r.array()?,
            eph: r.array()?,
        };
        if !r.at_end() {
            return Err(WireError::Malformed("CLIENT_HELLO"));
        }
        Ok(m)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub version: u16,
    pub random: [u8; RANDOM_LEN],
    pub eph: [u8; PUB_LEN],
    pub suite: u16,
    pub ticket_ttl_ms: u32,
}

impl ServerHello {
    pub const BODY_LEN: usize = 2 + RANDOM_LEN + PUB_LEN + 2 + 4;

    pub fn to_frame(&self) -> Frame {
        let mut b = Vec::with_capacity(Self::BODY_LEN);
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&self.random);
        b.extend_from_slice(&self.eph);
        b.extend_from_slice(&self.suite.to_be_bytes());
        b.extend_from_slice(&self.ticket_ttl_ms.to_be_bytes());
        Frame::new(MsgType::ServerHello, b)
    }

    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body, "SERVER_HELLO");
        let m = ServerHello {
            version: r.u16()?,
            random: r.array()?,
            eph: r.array()?,
            suite: r.u16()?,
            ticket_ttl_ms: r.u32()?,
        };
        if !r.at_end() {
            return Err(WireError::Malformed("SERVER_HELLO"));
        }
        Ok(m)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFinish {
    pub verify: [u8; VERIFY_LEN],
}

impl ClientFinish {
    pub fn to_frame(&self) -> Frame {
        Frame::new(MsgType::ClientFinish, self.verify.to_vec())
    }

    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body, "CLIENT_FINISH");
        let verify = r.array()?;
        if !r.at_end() {
            return Err(WireError::Malformed("CLIENT_FINISH"));
        }
        Ok(ClientFinish { verify })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFinish {
    pub verify: [u8; VERIFY_LEN],
    pub ticket: [u8; TICKET_LEN],
}

impl ServerFinish {
    pub fn to_frame(&self) -> Frame {
        let mut b = Vec::with_capacity(VERIFY_LEN + TICKET_LEN);
        b.extend_from_slice(&self.verify);
        b.extend_from_slice(&self.ticket);
        Frame::new(MsgType::ServerFinish, b)
    }

    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body, "SERVER_FINISH");
        let verify = r.array()?;
        let ticket = r.array()?;
        Ok(ServerFinish { verify, ticket })
    }
}

/// APP_DATA / REKEY / CLOSE share a shape: `seq: u64` then ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub seq: u64,
    pub ct: Vec<u8>,
}

impl Sealed {
    pub fn to_frame(&self, mtype: MsgType) -> Frame {
        let mut b = Vec::with_capacity(8 + self.ct.len());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.ct);
        Frame::new(mtype, b)
    }

    pub fn parse(body: &[u8], what: &'static str) -> Result<Self, WireError> {
        if body.len() < 8 {
            return Err(WireError::Malformed(what));
        }
        let seq = u64::from_be_bytes(body[..8].try_into().unwrap());
        Ok(Sealed {
            seq,
            ct: body[8..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResume {
    pub ticket: [u8; TICKET_LEN],
    pub client_random: [u8; RANDOM_LEN],
    pub eph: [u8; PUB_LEN],
}

impl SessionResume {
    pub fn to_frame(&self) -> Frame {
        let mut b = Vec::with_capacity(TICKET_LEN + RANDOM_LEN + PUB_LEN);
        b.extend_from_slice(&self.ticket);
        b.extend_from_slice(&self.client_random);
        b.extend_from_slice(&self.eph);
        Frame::new(MsgType::SessionResume, b)
    }

    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body, "SESSION_RESUME");
        let ticket = r.array()?;
        let client_random = r.array()?;
        let eph = r.array()?;
        if !r.at_end() {
            return Err(WireError::Malformed("SESSION_RESUME"));
        }
        Ok(SessionResume {
            ticket,
            client_random,
            eph,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeOk {
    pub server_random: [u8; RANDOM_LEN],
    pub eph: [u8; PUB_LEN],
    pub ticket: [u8; TICKET_LEN],
}

impl ResumeOk {
    pub fn to_frame(&self) -> Frame {
        let mut b = Vec::with_capacity(RANDOM_LEN + PUB_LEN + TICKET_LEN);
        b.extend_from_slice(&self.server_random);
        b.extend_from_slice(&self.eph);
        b.extend_from_slice(&self.ticket);
        Frame::new(MsgType::ResumeOk, b)
    }

    pub fn parse(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body, "RESUME_OK");
        let server_random = r.array()?;
        let eph = r.array()?;
        let ticket = r.array()?;
        if !r.at_end() {
            return Err(WireError::Malformed("RESUME_OK"));
        }
        Ok(ResumeOk {
            server_random,
            eph,
            ticket,
        })
    }
}

impl Frame {
    pub fn err_code(&self) -> ErrorCode {
        if self.body.len() < 2 {
            return ErrorCode::DecodeError;
        }
        ErrorCode::from_u16(u16::from_be_bytes([self.body[0], self.body[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_hello() {
        let ch = ClientHello {
            version: VERSION,
            random: [7u8; 32],
            eph: [9u8; 32],
        };
        let f = ch.to_frame();
        let enc = f.encode();
        let mut dec = FrameDecoder::new();
        dec.push(&enc[..10]);
        assert!(dec.next_frame().unwrap().is_none());
        dec.push(&enc[10..]);
        let got = dec.next_frame().unwrap().unwrap();
        assert_eq!(got.mtype, MsgType::ClientHello);
        assert_eq!(ClientHello::parse(&got.body).unwrap(), ch);
    }

    #[test]
    fn decoder_handles_multiple_frames_and_eof() {
        let mut dec = FrameDecoder::new();
        dec.push(&Frame::err(ErrorCode::BadMac).encode());
        dec.push(&Frame::err(ErrorCode::BadState).encode());
        assert_eq!(dec.next_frame().unwrap().unwrap().err_code(), ErrorCode::BadMac);
        assert_eq!(dec.next_frame().unwrap().unwrap().err_code(), ErrorCode::BadState);
        assert!(dec.next_frame().unwrap().is_none());
    }

    #[test]
    fn rejects_oversize_and_unknown() {
        let mut dec = FrameDecoder::new();
        dec.push(&(100_000u32).to_be_bytes());
        assert_eq!(dec.next_frame(), Err(WireError::TooLarge(100_000)));

        let mut dec = FrameDecoder::new();
        dec.push(&(1u32).to_be_bytes());
        dec.push(&0x99u8.to_be_bytes());
        assert_eq!(dec.next_frame(), Err(WireError::UnknownType(0x99)));
    }

    #[test]
    fn parser_does_not_panic_on_truncation() {
        for n in 0..ServerHello::BODY_LEN {
            assert!(ServerHello::parse(&vec![0u8; n]).is_err());
        }
        assert!(ServerHello::parse(&[0u8; ServerHello::BODY_LEN]).is_ok());
    }
}
