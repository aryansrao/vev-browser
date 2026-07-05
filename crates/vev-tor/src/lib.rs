//! Embedded Tor via Arti, exposed to the browser as a local SOCKS5 proxy.
//!
//! CEF/Chromium can route a request context through a SOCKS5 proxy, and a
//! SOCKS5 proxy resolves DNS at the proxy end (remote resolution) — so
//! pointing Tor tabs at this local proxy routes both their traffic and their
//! DNS through Tor, with no plaintext DNS leaving the machine.
//!
//! Only a minimal SOCKS5 CONNECT server is implemented (no BIND/UDP): that is
//! all a browser needs, and a smaller surface is easier to reason about.

use arti_client::{TorClient, TorClientConfig};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::sync::watch;

type Runtime = tor_rtcompat::PreferredRuntime;

/// Handle to the running Arti client + Tokio runtime, used to spin up
/// per-tab isolated SOCKS listeners after bootstrap.
struct TorCore {
    client: Arc<TorClient<Runtime>>,
    handle: Handle,
}

static CORE: OnceLock<Mutex<Option<Arc<TorCore>>>> = OnceLock::new();

fn core_slot() -> &'static Mutex<Option<Arc<TorCore>>> {
    CORE.get_or_init(|| Mutex::new(None))
}

/// Bootstrap state, surfaced to the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TorStatus {
    Bootstrapping,
    Ready,
    Failed,
}

pub struct TorProxy {
    /// Local address the SOCKS5 proxy listens on.
    pub socks_addr: SocketAddr,
    status_rx: watch::Receiver<TorStatus>,
}

impl TorProxy {
    pub fn status(&self) -> TorStatus {
        *self.status_rx.borrow()
    }

    pub fn proxy_url(&self) -> String {
        format!("socks5://{}", self.socks_addr)
    }
}

/// Start Arti and the local SOCKS5 bridge on a background Tokio runtime.
/// Returns once the listener is bound (bootstrap continues in the
/// background; check `status()`), or an error if the runtime/listener could
/// not be created.
pub fn start() -> io::Result<TorProxy> {
    let (status_tx, status_rx) = watch::channel(TorStatus::Bootstrapping);

    // Bind the SOCKS listener synchronously so the caller gets a real address
    // before returning. Use a std listener, then hand it to Tokio.
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    std_listener.set_nonblocking(true)?;
    let socks_addr = std_listener.local_addr()?;

    std::thread::Builder::new()
        .name("vev-tor".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("vev-tor: failed to build runtime: {e}");
                    let _ = status_tx.send(TorStatus::Failed);
                    return;
                }
            };
            let handle = rt.handle().clone();
            rt.block_on(async move {
                if let Err(e) = run(std_listener, status_tx.clone(), handle).await {
                    eprintln!("vev-tor: {e}");
                    let _ = status_tx.send(TorStatus::Failed);
                }
            });
        })?;

    Ok(TorProxy {
        socks_addr,
        status_rx,
    })
}

async fn run(
    std_listener: std::net::TcpListener,
    status_tx: watch::Sender<TorStatus>,
    handle: Handle,
) -> anyhow_lite::Result {
    eprintln!("vev-tor: bootstrapping Arti…");
    let config = TorClientConfig::default();
    let client = TorClient::create_bootstrapped(config)
        .await
        .map_err(|e| format!("Arti bootstrap failed: {e}"))?;
    let addr = std_listener.local_addr().map_err(|e| e.to_string())?;
    eprintln!("vev-tor: Arti bootstrapped, default SOCKS5 on {addr}");

    // Publish the core so per-tab isolated proxies can be created later.
    *core_slot().lock().map_err(|_| "core lock".to_string())? =
        Some(Arc::new(TorCore {
            client: client.clone(),
            handle,
        }));
    let _ = status_tx.send(TorStatus::Ready);

    // Serve the shared (default) proxy on this listener.
    serve(std_listener, client).await
}

/// A Tor client, either the shared bootstrapped one or an isolated clone.
type SharedClient = Arc<TorClient<Runtime>>;

/// Accept loop for one SOCKS listener bound to a specific Tor client.
async fn serve(
    std_listener: std::net::TcpListener,
    client: SharedClient,
) -> anyhow_lite::Result {
    let listener = TcpListener::from_std(std_listener).map_err(|e| e.to_string())?;
    loop {
        let (inbound, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("vev-tor: accept error: {e}");
                continue;
            }
        };
        let client = client.clone();
        tokio::spawn(async move {
            let _ = handle_socks(inbound, client).await;
        });
    }
}

/// Create a new SOCKS5 proxy backed by an **isolated** Tor client, so a tab
/// using it gets its own circuits (no linkability with other Tor tabs). Must
/// be called after `start()` has reached Ready. Returns the new proxy's
/// local address.
pub fn new_isolated_proxy() -> Result<SocketAddr, String> {
    let core = {
        let guard = core_slot().lock().map_err(|_| "core lock".to_string())?;
        guard.clone().ok_or("Tor not ready".to_string())?
    };
    let std_listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    std_listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let addr = std_listener.local_addr().map_err(|e| e.to_string())?;

    let client = core.client.isolated_client();
    core.handle.spawn(async move {
        let _ = serve(std_listener, client).await;
    });
    eprintln!("vev-tor: isolated SOCKS5 (own circuits) on {addr}");
    Ok(addr)
}

/// Minimal SOCKS5 handshake + CONNECT, dialing the target through Tor.
async fn handle_socks(
    mut inbound: tokio::net::TcpStream,
    client: SharedClient,
) -> Result<(), String> {
    // Greeting: VER, NMETHODS, METHODS…
    let mut head = [0u8; 2];
    inbound.read_exact(&mut head).await.map_err(e)?;
    if head[0] != 0x05 {
        return Err("not SOCKS5".into());
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    inbound.read_exact(&mut methods).await.map_err(e)?;
    // No authentication.
    inbound.write_all(&[0x05, 0x00]).await.map_err(e)?;

    // Request: VER, CMD, RSV, ATYP, ADDR, PORT
    let mut req = [0u8; 4];
    inbound.read_exact(&mut req).await.map_err(e)?;
    if req[1] != 0x01 {
        // Only CONNECT supported.
        reply(&mut inbound, 0x07).await;
        return Err("unsupported SOCKS command".into());
    }
    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            inbound.read_exact(&mut a).await.map_err(e)?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            inbound.read_exact(&mut len).await.map_err(e)?;
            let mut d = vec![0u8; len[0] as usize];
            inbound.read_exact(&mut d).await.map_err(e)?;
            String::from_utf8(d).map_err(|_| "bad domain".to_string())?
        }
        0x04 => {
            let mut a = [0u8; 16];
            inbound.read_exact(&mut a).await.map_err(e)?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => {
            reply(&mut inbound, 0x08).await;
            return Err("bad ATYP".into());
        }
    };
    let mut port = [0u8; 2];
    inbound.read_exact(&mut port).await.map_err(e)?;
    let port = u16::from_be_bytes(port);

    // Dial through Tor. The hostname is passed to Arti, which resolves it
    // inside the Tor network — no local DNS.
    let tor_stream = match client.connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(err) => {
            reply(&mut inbound, 0x05).await; // connection refused
            return Err(format!("tor connect {host}:{port}: {err}"));
        }
    };
    // Success reply with a dummy bound address.
    reply(&mut inbound, 0x00).await;

    // Splice the browser socket and the Tor stream in both directions.
    let (mut ci, mut co) = inbound.split();
    let (mut ti, mut to) = tor_stream.split();
    let c2t = async {
        let _ = tokio::io::copy(&mut ci, &mut to).await;
        let _ = to.flush().await;
    };
    let t2c = async {
        let _ = tokio::io::copy(&mut ti, &mut co).await;
        let _ = co.flush().await;
    };
    futures::future::join(c2t, t2c).await;
    Ok(())
}

async fn reply(inbound: &mut tokio::net::TcpStream, code: u8) {
    // VER, REP, RSV, ATYP=IPv4, 0.0.0.0:0
    let _ = inbound
        .write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await;
}

fn e(err: io::Error) -> String {
    err.to_string()
}

/// Tiny local Result alias so this crate needs no `anyhow` dependency.
mod anyhow_lite {
    pub type Result = std::result::Result<(), String>;
}
