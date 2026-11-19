//! Target server library: the wire/crypto plumbing plus four SCP/1 server
//! implementations (one compliant reference, three deliberately faulty).

pub mod record;
pub mod transport;

pub mod impls;

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::impls::Impl;
use crate::transport::{Link, ServerCfg, Shared, TcpChannel};

pub use transport::ServerCfg as Cfg;

pub struct ServerHandle {
    pub port: u16,
    join: Option<std::thread::JoinHandle<()>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl ServerHandle {
    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn stop(mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // Unblock the accept loop.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Start a target server on an ephemeral loopback port.
///
/// Every connection is served on its own thread, with its own RNG seeded
/// from `seed`, so a whole run is reproducible from `(impl, seed)`.
pub fn spawn(which: Impl, seed: u64, cfg: ServerCfg) -> std::io::Result<ServerHandle> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let shared = Shared::new(&mut ChaCha20Rng::seed_from_u64(seed ^ 0x5EED_CAFE));
    let cfg = Arc::new(cfg);

    let join = std::thread::spawn(move || {
        for (i, conn) in listener.incoming().enumerate() {
            if stop2.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = conn else { continue };
            let _ = stream.set_nodelay(true);
            let shared = shared.clone();
            let cfg = cfg.clone();
            let conn_seed = seed.wrapping_add((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            std::thread::spawn(move || {
                let mut rng = ChaCha20Rng::seed_from_u64(conn_seed);
                let max = cfg.max_frame;
                let mut link = Link::new(Box::new(TcpChannel::new(stream)), max);
                serve_conn(which, &mut link, &shared, &cfg, &mut rng);
            });
        }
    });

    Ok(ServerHandle {
        port,
        join: Some(join),
        stop,
    })
}

/// Serve one already-connected link.
pub fn serve_conn(
    which: Impl,
    link: &mut Link,
    shared: &Shared,
    cfg: &ServerCfg,
    rng: &mut ChaCha20Rng,
) {
    match which {
        Impl::Reference => impls::reference::run(link, shared, cfg, rng.clone()),
        Impl::Eager => impls::eager::run(link, shared, cfg, rng.clone()),
        Impl::Lenient => impls::lenient_record::run(link, shared, cfg, rng.clone()),
        Impl::Sticky => impls::sticky::run(link, shared, cfg, rng.clone()),
    }
    link.close();
}

/// Run a target over an arbitrary link (used by in-process tests).
pub fn run_on_link(
    which: Impl,
    link: &mut Link,
    shared: &Shared,
    cfg: &ServerCfg,
    seed: u64,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    serve_conn(which, link, shared, cfg, &mut rng);
}

/// Convenience for in-process tests: a pair of in-memory endpoints.
pub fn mem_link_pair(max_frame: usize) -> (Link, Link) {
    let (a, b) = transport::MemChannel::pair();
    (
        Link::new(Box::new(a), max_frame),
        Link::new(Box::new(b), max_frame),
    )
}

#[allow(dead_code)]
fn _timeout_default() -> Duration {
    Duration::from_millis(scp_core::wire::HANDSHAKE_DEADLINE_MS)
}
