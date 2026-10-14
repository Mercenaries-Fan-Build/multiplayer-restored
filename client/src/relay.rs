//! Relay shim: the game's gameplay UDP (ProtoTunnel), carried through the server's DTLS relay.
//!
//! Per game, one DTLS 1.2 client association (OpenSSL) to the relay in the [`RelayAssignment`], pinned to
//! `cert_sha256` (any other leaf certificate fails the handshake), authenticated by
//! `Datagram::Hello{session_token}` (`mercs2_mp_api::relay`). Every other player in the game is shown to the local
//! game as a loopback **alias** — relay slot `s` ↔ `alias_base + s` under the production [`AliasPlan`] —
//! with one UDP socket on the alias's tunnel port:
//!
//! * game → alias socket → `Data{slot, Tunnel}` → relay → that peer's shim;
//! * relay → `Data{slot, Tunnel}` → sent *from* the alias socket to the game's own tunnel socket
//!   (`127.0.0.1:<game tunnel port>`), so the game sees the datagram coming from the address Theater gave it
//!   for that peer.
//!
//! Why this needs no game patching (`multiplayer_rewrite_re.md` §6–§7): ProtoTunnel sends to the Theater
//! `I/P` / `INT-IP/INT-PORT` pair (the Theater adapter gives both the alias), its payloads are RC4-encrypted
//! end to end and carry their own clientId, so the relay forwards them opaquely.
//!
//! **Voice.** The game's GameSpy Voice is detoured off ([`crate::voice`]), so the game never sends voice and
//! this shim carries none: a `Data{.., Voice}` datagram from the relay means the peer runs a client that still
//! forwards in-game voice, and fails the session with a message saying so.
//!
//! **Ports.** The alias tunnel port is `[relay] alias_tunnel_port`, required to differ from the game's own
//! tunnel port (the game binds `0.0.0.0:10000`, `FUN_00844770`), so aliases never share a port with the
//! game's wildcard bind. A failed alias bind is a loud error naming the address, never a silent fallback.
//!
//! On Windows the alias sockets have `SIO_UDP_CONNRESET` turned off: otherwise one datagram sent to a game
//! port that is not (or no longer) bound makes the next `recvfrom` fail with `WSAECONNRESET`.
//!
//! Threads: the relay thread resolves the relay, runs the handshake (driving OpenSSL's retransmission timer
//! over an in-memory datagram BIO), sends `Hello`, then receives from the relay and sends keepalives (a
//! third of the relay's idle timeout). Each alias socket has a thread blocking in `recv_from`. The DTLS
//! session is shared under a mutex. Any failure (handshake timeout, certificate mismatch, socket error) is
//! recorded as [`RelayState::Failed`], which the Theater adapter turns into a failed connection the game
//! sees. An orderly close by the relay (DTLS close_notify — the server revokes associations when a game is
//! closed or a player leaves) is [`RelayState::ClosedByRelay`]: the lobby's own notice of why (GREM/KICK,
//! or the answer to the game's RGAM/ECNL) travels on the WebSocket and may arrive a moment later, so the
//! Theater adapter waits for it for a bounded, configured time before failing. Datagrams the game sends before the association is up are dropped and
//! counted; the count is logged when it comes up.

use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use foreign_types::ForeignTypeRef;
use mercs2_mp_api::GameId;
use mercs2_mp_api::relay::{Channel, Datagram};
use mercs2_mp_api::ws::RelayAssignment;
use openssl::hash::MessageDigest;
use openssl::ssl::{ErrorCode, Ssl, SslContext, SslMethod, SslStream, SslVerifyMode, SslVersion};

use crate::log::Logger;

/// `DTLS_CTRL_HANDLE_TIMEOUT` from OpenSSL's `ssl.h` (`DTLSv1_handle_timeout` is a macro over `SSL_ctrl`).
const DTLS_CTRL_HANDLE_TIMEOUT: std::os::raw::c_int = 74;

const MAX_DATAGRAM: usize = 65535;

/// Where peer aliases live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliasPlan {
    /// Production: slot `s` is `base + s` on `tunnel_port`.
    Loopback { base: Ipv4Addr, tunnel_port: u16 },
    /// Tests on hosts where only 127.0.0.1 exists (macOS): every alias on `ip`, slot `s` on `base_port + s`.
    #[cfg(test)]
    Ports { ip: Ipv4Addr, base_port: u16 },
}

impl AliasPlan {
    /// The alias the game sees for the peer in `slot`.
    pub fn alias(&self, slot: u8) -> Result<SocketAddrV4, String> {
        match *self {
            AliasPlan::Loopback { base, tunnel_port } => {
                let o = base.octets();
                let last = o[3]
                    .checked_add(slot)
                    .ok_or_else(|| format!("relay slot {slot} does not fit an alias above {base} (last octet overflows)"))?;
                Ok(SocketAddrV4::new(Ipv4Addr::new(o[0], o[1], o[2], last), tunnel_port))
            }
            #[cfg(test)]
            AliasPlan::Ports { ip, base_port } => Ok(SocketAddrV4::new(ip, base_port + u16::from(slot))),
        }
    }
}

/// What the Theater adapter tells the game about a peer (EGRQ `IP/PORT`, EGEG `I/P`, both `INT-*` too).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerAddr {
    pub ip: Ipv4Addr,
    pub tunnel_port: u16,
}

/// One game's relay session as the Theater adapter uses it.
pub trait RelayLink: Send {
    /// Bind the aliases for the peer in `slot` and start forwarding its datagrams.
    fn add_peer(&mut self, slot: u8) -> Result<PeerAddr, String>;
    /// Stop forwarding for `slot` and release its alias sockets.
    fn remove_peer(&mut self, slot: u8);
    fn state(&self) -> RelayState;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayState {
    /// Handshaking or carrying datagrams.
    Up,
    /// The relay ended the association with close_notify.
    ClosedByRelay,
    /// The session failed; the reason.
    Failed(String),
}

pub trait RelayFactory: Send + Sync {
    /// Start the relay session for `game`; `game_tunnel_port` is the port the local game reported for its
    /// ProtoTunnel socket (CGAM / EGAM `PORT`).
    fn start(&self, game: GameId, assignment: &RelayAssignment, game_tunnel_port: u16) -> Result<Box<dyn RelayLink>, String>;
}

#[derive(Clone, Copy, Debug)]
pub struct ShimSettings {
    pub plan: AliasPlan,
    /// The game's address (it binds its sockets to 0.0.0.0; loopback reaches them).
    pub game_ip: Ipv4Addr,
    pub mtu: u32,
    pub handshake_timeout: Duration,
    pub poll: Duration,
}

/// The production [`RelayFactory`].
pub struct ShimFactory {
    pub settings: ShimSettings,
    pub log: Logger,
}

impl RelayFactory for ShimFactory {
    fn start(&self, game: GameId, a: &RelayAssignment, game_tunnel_port: u16) -> Result<Box<dyn RelayLink>, String> {
        let game_tunnel = SocketAddrV4::new(self.settings.game_ip, game_tunnel_port);
        Ok(Box::new(RelayShim::start(game, a, game_tunnel, self.settings, self.log.clone())?))
    }
}

/// In-memory datagram transport under the DTLS session (the relay thread moves datagrams in and out).
#[derive(Default)]
struct DgramIo {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
}

impl Read for DgramIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inbound.pop_front() {
            None => Err(ErrorKind::WouldBlock.into()),
            Some(d) if d.len() > buf.len() => Err(io::Error::new(ErrorKind::InvalidData, "datagram larger than the DTLS read buffer")),
            Some(d) => {
                buf[..d.len()].copy_from_slice(&d);
                Ok(d.len())
            }
        }
    }
}

impl Write for DgramIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbound.push(buf.to_vec());
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Session {
    stream: SslStream<DgramIo>,
    udp: Arc<UdpSocket>,
    last_sent: Instant,
}

impl Session {
    /// Send everything OpenSSL has written.
    fn flush(&mut self) -> Result<(), String> {
        for d in std::mem::take(&mut self.stream.get_mut().outbound) {
            self.udp.send(&d).map_err(|e| format!("sending to the relay: {e}"))?;
            self.last_sent = Instant::now();
        }
        Ok(())
    }

    fn write(&mut self, d: &Datagram) -> Result<(), String> {
        let bytes = d.encode().map_err(|e| e.to_string())?;
        self.stream.ssl_write(&bytes).map_err(|e| format!("DTLS write: {e}"))?;
        self.flush()
    }
}

struct Inner {
    game: GameId,
    log: Logger,
    stop: AtomicBool,
    failure: Mutex<Option<String>>,
    closed_by_relay: AtomicBool,
    session: Mutex<Option<Session>>,
    early_drops: AtomicU64,
    aliases: Mutex<HashMap<u8, Arc<UdpSocket>>>,
    /// The game's own tunnel socket, where relay datagrams are delivered.
    game_tunnel: SocketAddrV4,
}

impl Inner {
    fn fail(&self, why: String) {
        if let Ok(mut f) = self.failure.lock()
            && f.is_none()
        {
            self.log.error(format!("relay session for game {} failed: {why}", self.game.0));
            *f = Some(why);
        }
        self.stop.store(true, Ordering::Release);
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// A gameplay datagram from the game for the peer in `slot`.
    fn game_datagram(&self, slot: u8, payload: &[u8]) -> Result<(), String> {
        let mut guard = self.session.lock().map_err(|_| "relay session lock poisoned".to_string())?;
        match guard.as_mut() {
            None => {
                self.early_drops.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Some(s) => s.write(&Datagram::Data { slot, channel: Channel::Tunnel, payload }),
        }
    }

    /// A plaintext datagram from the relay.
    fn relay_datagram(&self, bytes: &[u8]) -> Result<(), String> {
        match Datagram::decode(bytes).map_err(|e| format!("malformed datagram from the relay: {e}"))? {
            Datagram::Data { slot, channel: Channel::Voice, payload } => Err(format!(
                "relay slot {slot} sent a voice datagram ({} bytes) in game {}: that player's multiplayer_restored still \
                 forwards in-game voice, which this version disables; both players need multiplayer_restored {}",
                payload.len(),
                self.game.0,
                crate::ASI_VERSION
            )),
            Datagram::Data { slot, channel: Channel::Tunnel, payload } => {
                let sock = self.aliases.lock().map_err(|_| "alias table lock poisoned".to_string())?.get(&slot).cloned();
                match sock {
                    Some(s) => {
                        let to = self.game_tunnel;
                        s.send_to(payload, to).map_err(|e| format!("delivering a datagram from slot {slot} to the game at {to}: {e}"))?;
                    }
                    None => self.log.warn(format!(
                        "relay datagram ({} bytes) from slot {slot}, which has no alias in game {}; dropped",
                        payload.len(),
                        self.game.0
                    )),
                }
                Ok(())
            }
            Datagram::Hello { .. } | Datagram::Keepalive => Err("the relay sent a client-only datagram (hello/keepalive)".into()),
        }
    }
}

struct Peer {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

pub struct RelayShim {
    inner: Arc<Inner>,
    plan: AliasPlan,
    local_slot: u8,
    poll: Duration,
    peers: HashMap<u8, Peer>,
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

#[cfg(windows)]
fn disable_connreset(sock: &UdpSocket) -> Result<(), String> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{SIO_UDP_CONNRESET, WSAIoctl};
    let off: u32 = 0;
    let mut returned: u32 = 0;
    // SAFETY: valid socket handle owned by `sock`; in-buffer is a 4-byte BOOL; no overlapped I/O.
    let rc = unsafe {
        WSAIoctl(
            sock.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            (&off as *const u32).cast(),
            4,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if rc != 0 {
        return Err(format!("SIO_UDP_CONNRESET off: {}", io::Error::last_os_error()));
    }
    Ok(())
}

/// Only Winsock reports ICMP port-unreachable on later receives of an unconnected UDP socket.
#[cfg(not(windows))]
fn disable_connreset(_sock: &UdpSocket) -> Result<(), String> {
    Ok(())
}

impl RelayShim {
    pub fn start(game: GameId, a: &RelayAssignment, game_tunnel: SocketAddrV4, s: ShimSettings, log: Logger) -> Result<Self, String> {
        match s.plan {
            AliasPlan::Loopback { tunnel_port, .. } if tunnel_port == game_tunnel.port() => {
                return Err(format!(
                    "[relay] alias_tunnel_port {tunnel_port} equals the game's own tunnel port; aliases must use another port"
                ));
            }
            _ => {}
        }
        let pinned = a.cert_sha256.to_ascii_lowercase();
        if pinned.len() != 64 || !pinned.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("relay cert_sha256 {:?} is not 64 hex characters", a.cert_sha256));
        }
        if a.idle_timeout_secs == 0 {
            return Err("relay idle_timeout_secs is 0; no keepalive interval can satisfy it".into());
        }
        let keepalive = Duration::from_secs(a.idle_timeout_secs) / 3;
        let inner = Arc::new(Inner {
            game,
            log: log.clone(),
            stop: AtomicBool::new(false),
            failure: Mutex::new(None),
            closed_by_relay: AtomicBool::new(false),
            session: Mutex::new(None),
            early_drops: AtomicU64::new(0),
            aliases: Mutex::new(HashMap::new()),
            game_tunnel,
        });
        let (thread_inner, assignment) = (inner.clone(), a.clone());
        // Not joined on drop: it may be resolving the relay host name; it exits within one poll interval of
        // `stop` otherwise, and owns nothing the next game needs (alias sockets are released by `Drop`).
        std::thread::Builder::new()
            .name(format!("mp-restored-relay-{}", game.0))
            .spawn(move || {
                if let Err(e) = relay_thread(&thread_inner, &assignment, &s, &pinned, keepalive)
                    && !thread_inner.stopped()
                {
                    thread_inner.fail(e);
                }
            })
            .map_err(|e| format!("cannot start the relay thread: {e}"))?;
        log.info(format!("relay session for game {}: {}:{} slot {}, game tunnel {game_tunnel}", game.0, a.host, a.port, a.local_slot));
        Ok(RelayShim { inner, plan: s.plan, local_slot: a.local_slot, poll: s.poll, peers: HashMap::new() })
    }
}

fn dtls_handle_timeout(stream: &SslStream<DgramIo>) -> Result<(), String> {
    // SAFETY: the pointer is the live SSL owned by `stream`; DTLS_CTRL_HANDLE_TIMEOUT takes no argument and
    // only drives OpenSSL's retransmission timer, writing through our BIO.
    let rc = unsafe { openssl_sys::SSL_ctrl(stream.ssl().as_ptr(), DTLS_CTRL_HANDLE_TIMEOUT, 0, std::ptr::null_mut()) };
    if rc < 0 { Err("DTLS retransmission failed".into()) } else { Ok(()) }
}

fn relay_thread(inner: &Inner, a: &RelayAssignment, s: &ShimSettings, pinned: &str, keepalive: Duration) -> Result<(), String> {
    let target = (a.host.as_str(), a.port)
        .to_socket_addrs()
        .map_err(|e| format!("resolving relay {}:{}: {e}", a.host, a.port))?
        .next()
        .ok_or_else(|| format!("relay {}:{} resolved to no address", a.host, a.port))?;
    let local: SocketAddr = if target.is_ipv4() { "0.0.0.0:0".parse() } else { "[::]:0".parse() }.map_err(|e| format!("{e}"))?;
    let udp = UdpSocket::bind(local).map_err(|e| format!("binding the relay socket: {e}"))?;
    udp.connect(target).map_err(|e| format!("connecting the relay socket to {target}: {e}"))?;
    udp.set_read_timeout(Some(s.poll)).map_err(|e| format!("relay socket timeout: {e}"))?;
    let udp = Arc::new(udp);

    let mismatch: Arc<Mutex<Option<String>>> = Arc::default();
    let leaf_ok = Arc::new(AtomicBool::new(false));
    let mut ctx = SslContext::builder(SslMethod::dtls()).map_err(|e| e.to_string())?;
    ctx.set_min_proto_version(Some(SslVersion::DTLS1_2)).map_err(|e| e.to_string())?;
    {
        let (pinned, mismatch, leaf_ok) = (pinned.to_owned(), mismatch.clone(), leaf_ok.clone());
        ctx.set_verify_callback(SslVerifyMode::PEER, move |_preverified, store| {
            // Only the leaf is pinned; issuers above it carry no trust here.
            if store.error_depth() != 0 {
                return true;
            }
            let Some(cert) = store.current_cert() else { return false };
            let Ok(digest) = cert.digest(MessageDigest::sha256()) else { return false };
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            if hex == pinned {
                leaf_ok.store(true, Ordering::Release);
                true
            } else {
                if let Ok(mut m) = mismatch.lock() {
                    *m = Some(hex);
                }
                false
            }
        });
    }
    let mut ssl = Ssl::new(&ctx.build()).map_err(|e| e.to_string())?;
    ssl.set_mtu(s.mtu).map_err(|e| format!("DTLS MTU {}: {e}", s.mtu))?;
    let mut stream = SslStream::new(ssl, DgramIo::default()).map_err(|e| e.to_string())?;

    let deadline = Instant::now() + s.handshake_timeout;
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        if inner.stopped() {
            return Ok(());
        }
        match stream.connect() {
            Ok(()) => break,
            Err(e) if matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => {}
            Err(e) => {
                let detail = match mismatch.lock().ok().and_then(|m| m.clone()) {
                    Some(got) => format!("relay certificate sha256 {got} does not match the pinned {pinned}"),
                    None => format!("DTLS handshake with the relay {target} failed: {e}"),
                };
                return Err(detail);
            }
        }
        for d in std::mem::take(&mut stream.get_mut().outbound) {
            udp.send(&d).map_err(|e| format!("sending to the relay {target}: {e}"))?;
        }
        if Instant::now() >= deadline {
            return Err(format!("DTLS handshake with the relay {target} did not finish within {} ms", s.handshake_timeout.as_millis()));
        }
        match udp.recv(&mut buf) {
            Ok(n) => stream.get_mut().inbound.push_back(buf[..n].to_vec()),
            Err(e) if is_timeout(&e) => dtls_handle_timeout(&stream)?,
            Err(e) => return Err(format!("relay {target} unreachable: {e}")),
        }
    }
    if !leaf_ok.load(Ordering::Acquire) {
        return Err(format!("relay {target} completed the handshake without the pinned certificate being checked"));
    }
    let mut session = Session { stream, udp: udp.clone(), last_sent: Instant::now() };
    session.write(&Datagram::Hello { token: a.session_token.as_bytes() })?;
    let early = inner.early_drops.swap(0, Ordering::Relaxed);
    inner.log.info(format!(
        "relay association for game {} up ({target}, certificate pinned); {early} game datagram(s) were dropped before it was",
        inner.game.0
    ));
    *inner.session.lock().map_err(|_| "relay session lock poisoned".to_string())? = Some(session);

    loop {
        if inner.stopped() {
            if let Ok(mut g) = inner.session.lock()
                && let Some(s) = g.as_mut()
            {
                // close_notify, best effort: the relay also drops the association when the lobby says so.
                let _shutdown = s.stream.shutdown();
                let _flushed = s.flush();
            }
            return Ok(());
        }
        let received = udp.recv(&mut buf);
        let mut plain = Vec::new();
        {
            let mut g = inner.session.lock().map_err(|_| "relay session lock poisoned".to_string())?;
            let s = g.as_mut().ok_or("relay session vanished")?;
            match received {
                Ok(n) => {
                    s.stream.get_mut().inbound.push_back(buf[..n].to_vec());
                    let mut closed = false;
                    loop {
                        let mut p = vec![0u8; MAX_DATAGRAM];
                        match s.stream.ssl_read(&mut p) {
                            Ok(n) => {
                                p.truncate(n);
                                plain.push(p);
                            }
                            Err(e) if e.code() == ErrorCode::WANT_READ => break,
                            Err(e) if e.code() == ErrorCode::ZERO_RETURN => {
                                closed = true;
                                break;
                            }
                            Err(e) => return Err(format!("DTLS read from the relay: {e}")),
                        }
                    }
                    s.flush()?;
                    if closed {
                        inner.log.info(format!("relay closed the association for game {} (close_notify)", inner.game.0));
                        inner.closed_by_relay.store(true, Ordering::Release);
                        inner.stop.store(true, Ordering::Release);
                        return Ok(());
                    }
                }
                Err(e) if is_timeout(&e) => {}
                Err(e) => return Err(format!("relay {target} unreachable: {e}")),
            }
            if s.last_sent.elapsed() >= keepalive {
                s.write(&Datagram::Keepalive)?;
            }
        }
        for p in plain {
            inner.relay_datagram(&p)?;
        }
    }
}

fn alias_thread(inner: Arc<Inner>, stop: Arc<AtomicBool>, sock: Arc<UdpSocket>, slot: u8) {
    let from_game = inner.game_tunnel.port();
    let mut buf = vec![0u8; MAX_DATAGRAM];
    while !stop.load(Ordering::Acquire) && !inner.stopped() {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if !src.ip().is_loopback() || src.port() != from_game {
                    inner.log.warn(format!("alias for slot {slot} got a datagram from {src}, not the game; dropped"));
                    continue;
                }
                if let Err(e) = inner.game_datagram(slot, &buf[..n]) {
                    inner.fail(e);
                    return;
                }
            }
            Err(e) if is_timeout(&e) => {}
            Err(e) => {
                inner.fail(format!("alias socket for slot {slot}: {e}"));
                return;
            }
        }
    }
}

impl RelayLink for RelayShim {
    fn add_peer(&mut self, slot: u8) -> Result<PeerAddr, String> {
        if slot == self.local_slot {
            return Err(format!("relay slot {slot} is this client's own slot"));
        }
        if self.peers.contains_key(&slot) {
            return Err(format!("relay slot {slot} already has an alias"));
        }
        let addr = self.plan.alias(slot)?;
        let sock = UdpSocket::bind(addr).map_err(|e| format!("binding alias {addr} for relay slot {slot}: {e}"))?;
        sock.set_read_timeout(Some(self.poll)).map_err(|e| format!("alias {addr} timeout: {e}"))?;
        disable_connreset(&sock).map_err(|e| format!("alias {addr}: {e}"))?;
        let sock = Arc::new(sock);
        self.inner.aliases.lock().map_err(|_| "alias table lock poisoned".to_string())?.insert(slot, sock.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let (inner, thread_stop) = (self.inner.clone(), stop.clone());
        let thread = std::thread::Builder::new()
            .name(format!("mp-restored-alias-{slot}"))
            .spawn(move || alias_thread(inner, thread_stop, sock, slot))
            .map_err(|e| format!("cannot start the alias thread for slot {slot}: {e}"))?;
        self.peers.insert(slot, Peer { stop, thread });
        self.inner.log.info(format!("relay slot {slot} of game {} is {addr} for the game", self.inner.game.0));
        Ok(PeerAddr { ip: *addr.ip(), tunnel_port: addr.port() })
    }

    fn remove_peer(&mut self, slot: u8) {
        if let Some(p) = self.peers.remove(&slot) {
            p.stop.store(true, Ordering::Release);
            if let Ok(mut a) = self.inner.aliases.lock() {
                a.remove(&slot);
            }
            // Bounded by the alias socket's read timeout; the thread never panics (panic = abort).
            let _joined = p.thread.join();
            self.inner.log.info(format!("relay slot {slot} of game {} released", self.inner.game.0));
        }
    }

    fn state(&self) -> RelayState {
        match self.inner.failure.lock() {
            Ok(f) => match f.clone() {
                Some(why) => RelayState::Failed(why),
                None if self.inner.closed_by_relay.load(Ordering::Acquire) => RelayState::ClosedByRelay,
                None => RelayState::Up,
            },
            Err(_) => RelayState::Failed("relay failure lock poisoned".into()),
        }
    }
}

impl Drop for RelayShim {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::Release);
        let slots: Vec<u8> = self.peers.keys().copied().collect();
        for s in slots {
            self.remove_peer(s);
        }
        self.inner.log.info(format!("relay session for game {} closed", self.inner.game.0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lobby::{Lobby, LobbyProvider};
    use crate::log::capture;
    use crate::testserver::{TestServer, call, next_push, wait};
    use mercs2_mp_api::ws::{CreateGame, GameCreated, JoinAccepted, Joinability, Privacy, Push, Request, Response};

    /// Host + joiner logged in, game created and the join accepted, through the real server.
    /// The lobby connections stay open for the test's lifetime: closing one removes that player.
    struct Game {
        _lobbies: (Box<dyn Lobby>, Box<dyn Lobby>, crate::ws::WsLobbyProvider),
        host_lobby_provider: crate::ws::WsLobbyProvider,
        created: GameCreated,
        accepted: JoinAccepted,
    }

    fn game(srv: &TestServer, tag: &str) -> Game {
        let (hp, _) = srv.provider(&format!("H{tag}"));
        let (jp, _) = srv.provider(&format!("J{tag}"));
        let mut host = hp.handle(true).unwrap();
        let mut joiner = jp.handle(true).unwrap();
        let create = CreateGame {
            name: format!("relay {tag}"),
            max_players: 2,
            version: "1.1".into(),
            joinable: Joinability::Open,
            attrs: Default::default(),
            privacy: Privacy::default(),
        };
        let (Ok(Response::GameCreated(created)), _) = call(&mut *host, Request::GamesCreate(create)) else { panic!("create") };
        let (Ok(Response::JoinPending { join_id }), _) = call(&mut *joiner, Request::GamesJoin { game_id: created.game_id, room_key: None }) else {
            panic!("join")
        };
        assert!(matches!(next_push(&mut *host), Push::JoinRequest { .. }));
        let (r, _) = call(&mut *host, Request::JoinRespond { join_id, allowed: true, reason: None });
        assert_eq!(r, Ok(Response::Ok));
        let Push::JoinAccepted(accepted) = next_push(&mut *joiner) else { panic!("accepted") };
        Game { _lobbies: (host, joiner, jp), host_lobby_provider: hp, created, accepted }
    }

    fn failed(s: &RelayShim) -> Option<String> {
        match s.state() {
            RelayState::Failed(why) => Some(why),
            RelayState::Up | RelayState::ClosedByRelay => None,
        }
    }

    /// Two consecutive free UDP ports on 127.0.0.1 for a `Ports` plan (aliases for slots 0 and 1).
    fn free_base() -> u16 {
        loop {
            let base = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
            if base > 65000 {
                continue;
            }
            if (0..2).all(|i| UdpSocket::bind(("127.0.0.1", base + i)).is_ok()) {
                return base;
            }
        }
    }

    /// A fake game: its tunnel socket.
    struct FakeGame {
        tunnel: UdpSocket,
    }

    impl FakeGame {
        fn new() -> Self {
            let tunnel = UdpSocket::bind("127.0.0.1:0").unwrap();
            tunnel.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            FakeGame { tunnel }
        }
        fn tunnel_addr(&self) -> SocketAddrV4 {
            match self.tunnel.local_addr().unwrap() {
                SocketAddr::V4(a) => a,
                SocketAddr::V6(_) => unreachable!("bound to 127.0.0.1"),
            }
        }
    }

    fn settings(base_port: u16) -> ShimSettings {
        ShimSettings {
            plan: AliasPlan::Ports { ip: Ipv4Addr::LOCALHOST, base_port },
            game_ip: Ipv4Addr::LOCALHOST,
            mtu: 1200,
            handshake_timeout: Duration::from_secs(5),
            poll: Duration::from_millis(20),
        }
    }

    /// Send `payload` from `from` to `to` until `rx` receives it (datagrams before the association is up
    /// are dropped by design); returns the source address `rx` saw.
    fn deliver(from: &UdpSocket, to: SocketAddrV4, rx: &UdpSocket, payload: &[u8]) -> SocketAddr {
        let mut buf = [0u8; 2048];
        wait("a datagram through the relay", || {
            from.send_to(payload, to).unwrap();
            match rx.recv_from(&mut buf) {
                Ok((n, src)) if &buf[..n] == payload => Some(src),
                Ok((n, _)) => panic!("unexpected datagram {:?}", &buf[..n]),
                Err(e) if is_timeout(&e) => None,
                Err(e) => panic!("{e}"),
            }
        })
    }

    #[test]
    fn two_shims_carry_tunnel_datagrams_through_the_real_relay() {
        let srv = TestServer::start();
        let g = game(&srv, "relay1");
        let (log, _) = capture::logger();
        let (host_game, joiner_game) = (FakeGame::new(), FakeGame::new());
        let (hb, jb) = (free_base(), free_base());
        let mut host = RelayShim::start(g.created.game_id, &g.created.relay, host_game.tunnel_addr(), settings(hb), log.clone()).unwrap();
        let mut joiner = RelayShim::start(g.accepted.game_id, &g.accepted.relay, joiner_game.tunnel_addr(), settings(jb), log).unwrap();
        let joiner_slot = g.accepted.relay.local_slot;
        let host_slot = g.accepted.host_slot;
        // What the Theater adapter would advertise: EGRQ IP/PORT on the host, EGEG I/P on the joiner.
        let joiner_seen_by_host = host.add_peer(joiner_slot).unwrap();
        let host_seen_by_joiner = joiner.add_peer(host_slot).unwrap();
        assert!(host.add_peer(joiner_slot).unwrap_err().contains("already has an alias"));
        assert!(host.add_peer(g.created.relay.local_slot).unwrap_err().contains("own slot"));

        let host_alias_tunnel = SocketAddrV4::new(joiner_seen_by_host.ip, joiner_seen_by_host.tunnel_port);
        let joiner_alias_tunnel = SocketAddrV4::new(host_seen_by_joiner.ip, host_seen_by_joiner.tunnel_port);

        // Tunnel host → joiner: arrives from the joiner's alias for the host (what the joiner's EGEG named).
        let src = deliver(&host_game.tunnel, host_alias_tunnel, &joiner_game.tunnel, b"tunnel from host");
        assert_eq!(src, SocketAddr::V4(joiner_alias_tunnel));
        let src = deliver(&joiner_game.tunnel, joiner_alias_tunnel, &host_game.tunnel, b"tunnel from joiner");
        assert_eq!(src, SocketAddr::V4(host_alias_tunnel));
        assert_eq!(host.state(), RelayState::Up);
        assert_eq!(joiner.state(), RelayState::Up);

        // The host closes the game: the relay sends close_notify to the joiner's shim.
        let mut lobby = g.host_lobby_provider.handle(false).unwrap();
        let (r, _) = call(&mut *lobby, Request::GamesClose { game_id: g.created.game_id });
        assert_eq!(r, Ok(Response::Ok));
        wait("the joiner's relay session to be closed", || (joiner.state() == RelayState::ClosedByRelay).then_some(()));
    }

    #[test]
    fn a_voice_datagram_from_a_peer_fails_the_session() {
        // A peer whose client still forwards in-game voice sends Data{.., Voice}; this client carries none.
        let srv = TestServer::start();
        let g = game(&srv, "relay4");
        let (log, _) = capture::logger();
        let (host_game, joiner_game) = (FakeGame::new(), FakeGame::new());
        let mut host = RelayShim::start(g.created.game_id, &g.created.relay, host_game.tunnel_addr(), settings(free_base()), log.clone()).unwrap();
        let mut joiner = RelayShim::start(g.accepted.game_id, &g.accepted.relay, joiner_game.tunnel_addr(), settings(free_base()), log).unwrap();
        let to_joiner = host.add_peer(g.accepted.relay.local_slot).unwrap();
        joiner.add_peer(g.accepted.host_slot).unwrap();
        // Both associations are up once a tunnel datagram has crossed.
        deliver(&host_game.tunnel, SocketAddrV4::new(to_joiner.ip, to_joiner.tunnel_port), &joiner_game.tunnel, b"up");
        {
            let mut session = joiner.inner.session.lock().unwrap();
            let voice = Datagram::Data { slot: g.accepted.host_slot, channel: Channel::Voice, payload: b"voice" };
            session.as_mut().unwrap().write(&voice).unwrap();
        }
        let why = wait("the host to fail on the voice datagram", || failed(&host));
        assert!(why.contains(&format!("relay slot {} sent a voice datagram (5 bytes)", g.accepted.relay.local_slot)), "{why}");
        assert!(why.contains("still forwards in-game voice"), "{why}");
    }

    #[test]
    fn keepalives_hold_a_quiet_association_open() {
        // Relay idle timeout 2 s → keepalive every 666 ms; 5 s of game silence must not end it.
        let srv = TestServer::start_with_relay_idle(2);
        let g = game(&srv, "relay2");
        let (log, _) = capture::logger();
        let (host_game, joiner_game) = (FakeGame::new(), FakeGame::new());
        let (hb, jb) = (free_base(), free_base());
        let mut host = RelayShim::start(g.created.game_id, &g.created.relay, host_game.tunnel_addr(), settings(hb), log.clone()).unwrap();
        let mut joiner = RelayShim::start(g.accepted.game_id, &g.accepted.relay, joiner_game.tunnel_addr(), settings(jb), log).unwrap();
        let to_joiner = host.add_peer(g.accepted.relay.local_slot).unwrap();
        joiner.add_peer(g.accepted.host_slot).unwrap();
        let to_joiner = SocketAddrV4::new(to_joiner.ip, to_joiner.tunnel_port);
        deliver(&host_game.tunnel, to_joiner, &joiner_game.tunnel, b"first");
        std::thread::sleep(Duration::from_secs(5));
        assert_eq!(host.state(), RelayState::Up);
        assert_eq!(joiner.state(), RelayState::Up);
        deliver(&host_game.tunnel, to_joiner, &joiner_game.tunnel, b"after five quiet seconds");
    }

    #[test]
    fn a_different_relay_certificate_fails_the_session() {
        let srv = TestServer::start();
        let g = game(&srv, "relay3");
        let (log, _) = capture::logger();
        let mut a = g.created.relay.clone();
        a.cert_sha256 = "00".repeat(32);
        let shim = RelayShim::start(g.created.game_id, &a, FakeGame::new().tunnel_addr(), settings(free_base()), log).unwrap();
        let why = wait("the pin check to fail", || failed(&shim));
        assert!(why.contains(&format!("does not match the pinned {}", "00".repeat(32))), "{why}");
    }

    #[test]
    fn unreachable_relay_and_bad_inputs_are_named() {
        let (log, _) = capture::logger();
        let mut a = RelayAssignment {
            host: "127.0.0.1".into(),
            port: UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port(),
            cert_sha256: "ab".repeat(32),
            session_token: "t".into(),
            local_slot: 0,
            idle_timeout_secs: 30,
        };
        let mut s = settings(free_base());
        s.handshake_timeout = Duration::from_millis(500);
        let shim = RelayShim::start(GameId(1), &a, FakeGame::new().tunnel_addr(), s, log.clone()).unwrap();
        let why = wait("the handshake to fail", || failed(&shim));
        assert!(why.contains("unreachable") || why.contains("did not finish within 500 ms"), "{why}");

        a.cert_sha256 = "zz".into();
        assert!(RelayShim::start(GameId(1), &a, FakeGame::new().tunnel_addr(), s, log.clone()).err().unwrap().contains("not 64 hex"));
        a.cert_sha256 = "ab".repeat(32);
        a.idle_timeout_secs = 0;
        assert!(RelayShim::start(GameId(1), &a, FakeGame::new().tunnel_addr(), s, log.clone()).err().unwrap().contains("idle_timeout_secs is 0"));
        a.idle_timeout_secs = 30;
        s.plan = AliasPlan::Loopback { base: Ipv4Addr::new(127, 0, 0, 2), tunnel_port: 10000 };
        let game_tunnel = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10000);
        assert!(RelayShim::start(GameId(1), &a, game_tunnel, s, log).err().unwrap().contains("equals the game's own tunnel port"));
    }

    #[test]
    fn production_alias_plan() {
        let p = AliasPlan::Loopback { base: Ipv4Addr::new(127, 0, 0, 2), tunnel_port: 10010 };
        assert_eq!(p.alias(0).unwrap(), "127.0.0.2:10010".parse().unwrap());
        assert_eq!(p.alias(1).unwrap(), "127.0.0.3:10010".parse().unwrap());
        assert!(p.alias(254).unwrap_err().contains("overflows"));
    }
}
