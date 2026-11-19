//! Key schedule for SCP/1.
//!
//! All key material is derived from (a) the X25519 shared secret and (b) a
//! transcript hash of the exact handshake bytes exchanged, so a peer that
//! replays a handshake with different bytes gets different keys.  The probe
//! implements the *client* half independently from the same public rules.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::wire::{TICKET_EXPIRY_LEN, TICKET_ID_LEN, TICKET_SEALED_LEN};

type HmacSha256 = Hmac<Sha256>;

pub const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

impl Side {
    pub fn peer(self) -> Side {
        match self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            Side::Client => "c",
            Side::Server => "s",
        }
    }
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("32 bytes is a valid HKDF length");
    out
}

pub fn transcript_hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update((p.len() as u32).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

/// One epoch's pair of directional keys.  `c2s` and `s2c` are stored
/// canonically (client→server, server→client) so both endpoints derive the
/// same successor keys; `send`/`recv` pick the right one for a side.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrafficKeys {
    pub c2s: [u8; KEY_LEN],
    pub s2c: [u8; KEY_LEN],
    pub epoch: u32,
}

impl TrafficKeys {
    pub fn send(&self, side: Side) -> &[u8; KEY_LEN] {
        match side {
            Side::Client => &self.c2s,
            Side::Server => &self.s2c,
        }
    }

    pub fn recv(&self, side: Side) -> &[u8; KEY_LEN] {
        match side {
            Side::Client => &self.s2c,
            Side::Server => &self.c2s,
        }
    }
}

impl std::fmt::Debug for TrafficKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficKeys")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// Secrets held by one endpoint for the duration of a connection.
pub struct HandshakeState {
    pub side: Side,
    #[allow(dead_code)]
    own_eph_secret: StaticSecret,
    pub own_eph_pub: [u8; 32],
    pub peer_eph_pub: [u8; 32],
    pub own_random: [u8; 32],
    pub peer_random: [u8; 32],
    pub shared: [u8; 32],
    /// Transcript covering the two HELLO messages in wire order.
    pub th_hello: [u8; 32],
    pub client_verify: [u8; 32],
    pub server_verify: [u8; 32],
    pub master: [u8; 32],
}

impl HandshakeState {
    #[allow(clippy::too_many_arguments)]
    pub fn new_hello(
        side: Side,
        own_eph_secret: StaticSecret,
        own_random: [u8; 32],
        peer_eph_pub: [u8; 32],
        peer_random: [u8; 32],
        client_hello_body: &[u8],
        server_hello_body: &[u8],
    ) -> Self {
        let own_eph_pub = PublicKey::from(&own_eph_secret).to_bytes();
        let shared = own_eph_secret
            .diffie_hellman(&PublicKey::from(peer_eph_pub))
            .to_bytes();
        let th_hello = transcript_hash(&[client_hello_body, server_hello_body]);
        let prk = hkdf(&th_hello, &shared, b"SCP1 hs");
        let c_hs = hkdf(&prk, b"", b"c hs");
        let s_hs = hkdf(&prk, b"", b"s hs");
        let client_verify = hmac(&c_hs, b"client verify");
        let server_verify = hmac(&s_hs, b"server verify");
        let master = hkdf(&prk, &[client_verify, server_verify].concat(), b"SCP1 master");
        HandshakeState {
            side,
            own_eph_secret,
            own_eph_pub,
            peer_eph_pub,
            own_random,
            peer_random,
            shared,
            th_hello,
            client_verify,
            server_verify,
            master,
        }
    }

    /// Derive the epoch-0 application traffic keys.
    ///
    /// SPEC.md §3.3: the key schedule takes *only* the HELLO transcript and
    /// the handshake verifier values as input.  Both verifiers are
    /// computable from the HELLO exchange alone, so a peer is able to
    /// encrypt application data before the FINISH flight has been sent.
    /// This is deliberate (it mirrors TLS 1.3 0-RTT): **the only thing that
    /// keeps early data out is the state machine**, which is precisely what
    /// this test bench is built to check.
    pub fn app_keys(&self) -> TrafficKeys {
        let prk = hkdf(&self.th_hello, &self.master, b"app");
        TrafficKeys {
            c2s: hkdf(&prk, b"", b"c2s"),
            s2c: hkdf(&prk, b"", b"s2c"),
            epoch: 0,
        }
    }

    /// Ticket-base secret for the end of this handshake.
    pub fn ticket_base(&self) -> [u8; 32] {
        hkdf(&self.master, b"", b"ticket base")
    }

    /// The ticket the server hands out at the end of this handshake.
    pub fn issue_ticket(
        &self,
        ticket_root: &[u8; KEY_LEN],
        id: [u8; TICKET_ID_LEN],
        expiry_ms: u64,
    ) -> [u8; crate::wire::TICKET_LEN] {
        Ticket::issue(ticket_root, &self.ticket_base(), id, expiry_ms)
    }
}

/// State for a resumed connection (ticket-based).
#[derive(Clone)]
pub struct ResumeKeys {
    pub th: [u8; 32],
    pub keys: TrafficKeys,
    /// Base secret for the next ticket, derived from this resume so ticket
    /// chains stay bound to the session that produced them (SPEC R-6.5).
    pub base: [u8; 32],
}

/// Derive application keys for a resumed session.
///
/// `ticket` is the opaque blob as transmitted, `psk` is recovered from it by
/// the server's ticket store.
#[allow(clippy::too_many_arguments)]
pub fn resume_keys(
    psk: &[u8; 32],
    ticket: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    client_eph: &[u8; 32],
    server_eph: &[u8; 32],
    shared: &[u8; 32],
) -> ResumeKeys {
    let th = transcript_hash(&[ticket, client_random, server_random, client_eph, server_eph]);
    let ikm = [psk.as_slice(), shared.as_slice()].concat();
    let prk = hkdf(&th, &ikm, b"SCP1 resume");
    ResumeKeys {
        th,
        keys: TrafficKeys {
            c2s: hkdf(&prk, b"", b"c2s app"),
            s2c: hkdf(&prk, b"", b"s2c app"),
            epoch: 0,
        },
        base: hkdf(&prk, b"", b"next base"),
    }
}

/// Compute the next epoch's keys after a REKEY.
///
/// `contribution` is the 32-byte value carried in the REKEY plaintext. Both
/// directions rotate at once, and the new keys depend on the old ones, so a
/// rekey cannot be replayed.
pub fn rekey_keys(cur: &TrafficKeys, contribution: &[u8; 32]) -> TrafficKeys {
    let prk = hkdf(
        b"SCP1 rekey",
        &[cur.c2s.as_slice(), cur.s2c.as_slice(), contribution.as_slice()].concat(),
        b"",
    );
    TrafficKeys {
        c2s: hkdf(&prk, b"", b"c2s next"),
        s2c: hkdf(&prk, b"", b"s2c next"),
        epoch: cur.epoch + 1,
    }
}

pub fn nonce_for(epoch: u32, seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&epoch.to_be_bytes());
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

pub fn seal(key: &[u8; KEY_LEN], epoch: u32, seq: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = nonce_for(epoch, seq);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("chacha20poly1305 encryption cannot fail for in-memory buffers")
}

pub fn open(
    key: &[u8; KEY_LEN],
    epoch: u32,
    seq: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = nonce_for(epoch, seq);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

/// The ticket as sent on the wire: `id || expiry_ms || sealed(psk)`.
///
/// Both parties can compute `psk`, but from *different* inputs:
///
/// * the **client** derives it from the `master` secret it kept from the
///   handshake, plus the ticket's public `(id, expiry_ms)`;
/// * the **server** recovers it by opening `sealed`, which is authenticated
///   under a per-id key derived from a process-wide `ticket_root` that no
///   client ever sees.
///
/// So a client cannot forge a ticket (it lacks the root), but a client that
/// genuinely received one can resume without the server storing per-session
/// state.  The sealed 32-byte payload is the only thing wrong tickets fail
/// to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub id: [u8; TICKET_ID_LEN],
    pub expiry_ms: u64,
    pub sealed: [u8; TICKET_SEALED_LEN],
}

pub fn ticket_key(ticket_root: &[u8; KEY_LEN], id: &[u8; TICKET_ID_LEN]) -> [u8; KEY_LEN] {
    hkdf(ticket_root, id, b"ticket")
}

/// Client-side derivation of the resumption secret.
///
/// `base` is the session's ticket-base secret: `master` for a fresh
/// handshake, or [`ResumeKeys::base`] after a resumption.  The client always
/// has it; the server recovers it by opening the ticket.
pub fn resume_psk(base: &[u8; 32], id: &[u8; TICKET_ID_LEN], expiry_ms: u64) -> [u8; 32] {
    hkdf(
        base,
        &[id.as_slice(), &expiry_ms.to_be_bytes()].concat(),
        b"resume psk",
    )
}

impl Ticket {
    pub fn issue(
        ticket_root: &[u8; KEY_LEN],
        base: &[u8; 32],
        id: [u8; TICKET_ID_LEN],
        expiry_ms: u64,
    ) -> [u8; crate::wire::TICKET_LEN] {
        // The sealed payload is the ticket *base* secret; the PSK used for
        // resumption is derived from it by both sides once the public
        // (id, expiry) fields are known (see `resume_psk`).
        let aad = [id.as_slice(), &expiry_ms.to_be_bytes()].concat();
        let tk = ticket_key(ticket_root, &id);
        let ct = seal(&tk, 2, 0, &aad, base);
        let mut out = [0u8; crate::wire::TICKET_LEN];
        out[..TICKET_ID_LEN].copy_from_slice(&id);
        out[TICKET_ID_LEN..TICKET_ID_LEN + TICKET_EXPIRY_LEN].copy_from_slice(&expiry_ms.to_be_bytes());
        out[TICKET_ID_LEN + TICKET_EXPIRY_LEN..].copy_from_slice(&ct);
        out
    }

    pub fn parse(raw: &[u8]) -> Option<Ticket> {
        if raw.len() != crate::wire::TICKET_LEN {
            return None;
        }
        let mut id = [0u8; TICKET_ID_LEN];
        id.copy_from_slice(&raw[..TICKET_ID_LEN]);
        let expiry_ms = u64::from_be_bytes(
            raw[TICKET_ID_LEN..TICKET_ID_LEN + TICKET_EXPIRY_LEN]
                .try_into()
                .ok()?,
        );
        let mut sealed = [0u8; TICKET_SEALED_LEN];
        sealed.copy_from_slice(&raw[TICKET_ID_LEN + TICKET_EXPIRY_LEN..]);
        Some(Ticket {
            id,
            expiry_ms,
            sealed,
        })
    }

    /// Server-side recovery of the resumption secret. Returns `None` if the
    /// ticket was not issued by this server (forged or corrupted).
    pub fn open_psk(&self, ticket_root: &[u8; KEY_LEN]) -> Option<[u8; 32]> {
        let aad = [self.id.as_slice(), &self.expiry_ms.to_be_bytes()].concat();
        let tk = ticket_key(ticket_root, &self.id);
        let pt = open(&tk, 2, 0, &aad, &self.sealed)?;
        pt.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_and_server() -> (HandshakeState, HandshakeState, Vec<u8>, Vec<u8>) {
        let c_secret = StaticSecret::from([1u8; 32]);
        let s_secret = StaticSecret::from([2u8; 32]);
        let c_pub = PublicKey::from(&c_secret).to_bytes();
        let s_pub = PublicKey::from(&s_secret).to_bytes();
        let ch = crate::wire::ClientHello {
            version: 1,
            random: [3u8; 32],
            eph: c_pub,
        }
        .to_frame();
        let sh = crate::wire::ServerHello {
            version: 1,
            random: [4u8; 32],
            eph: s_pub,
            suite: 1,
            ticket_ttl_ms: 1000,
        }
        .to_frame();
        let c = HandshakeState::new_hello(
            Side::Client,
            c_secret,
            [3u8; 32],
            s_pub,
            [4u8; 32],
            &ch.body,
            &sh.body,
        );
        let s = HandshakeState::new_hello(Side::Server, s_secret, [4u8; 32], c_pub, [3u8; 32], &ch.body, &sh.body);
        (c, s, ch.body, sh.body)
    }

    #[test]
    fn both_sides_derive_identical_keys() {
        let (c, s, _, _) = client_and_server();
        assert_eq!(c.client_verify, s.client_verify);
        assert_eq!(c.master, s.master);
        let ck = c.app_keys();
        let sk = s.app_keys();
        assert_eq!(ck.c2s, sk.c2s);
        assert_eq!(ck.c2s, *ck.send(Side::Client));
        assert_eq!(ck.c2s, *ck.recv(Side::Server));
    }

    #[test]
    fn aead_roundtrip_and_tamper() {
        let key = [9u8; 32];
        let ct = seal(&key, 0, 1, b"aad", b"hello");
        assert_eq!(open(&key, 0, 1, b"aad", &ct).unwrap(), b"hello");
        assert!(open(&key, 0, 2, b"aad", &ct).is_none());
        assert!(open(&key, 1, 1, b"aad", &ct).is_none());
        assert!(open(&key, 0, 1, b"other", &ct).is_none());
    }

    #[test]
    fn ticket_roundtrip() {
        let root = [5u8; 32];
        let master = [6u8; 32];
        let raw = Ticket::issue(&root, &master, [1u8; 16], 1234);
        let t = Ticket::parse(&raw).unwrap();
        assert_eq!(t.id, [1u8; 16]);
        assert_eq!(t.expiry_ms, 1234);
        // What the server recovers by opening the ticket is exactly the
        // base secret the client minted it from; the resumption PSK is then
        // derived identically on both sides.
        assert_eq!(t.open_psk(&root).unwrap(), master);
        assert_eq!(
            resume_psk(&t.open_psk(&root).unwrap(), &t.id, t.expiry_ms),
            resume_psk(&master, &[1u8; 16], 1234)
        );
        assert!(t.open_psk(&[7u8; 32]).is_none());
    }

    #[test]
    fn rekey_is_ordered() {
        let k = TrafficKeys {
            c2s: [1u8; 32],
            s2c: [2u8; 32],
            epoch: 0,
        };
        let a = rekey_keys(&k, &[3u8; 32]);
        let b = rekey_keys(&k, &[4u8; 32]);
        assert_eq!(a.epoch, 1);
        assert_ne!(a.c2s, b.c2s);
        assert_ne!(a.c2s, k.c2s);
        // Both sides compute the same successor from the same inputs.
        let b2 = rekey_keys(&k, &[4u8; 32]);
        assert_eq!(b.c2s, b2.c2s);
        assert_eq!(b.s2c, b2.s2c);
    }
}
