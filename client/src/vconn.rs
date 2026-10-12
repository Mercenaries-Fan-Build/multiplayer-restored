//! Virtual ProtoSSL connections: what each replaced ProtoSSL entry does to a ref.
//!
//! Every outbound TCP connection the game makes goes through ProtoSSLConnect (SocketConnect's only caller
//! is ProtoSSLUpdate, `multiplayer_rewrite_re.md` §4). [`classify`] routes it by `(name, ip, port, secure)`:
//!
//! * FESL — the name is one of `[fesl] intercept_names` and `secure` is 1;
//! * Theater / Messenger — the effective `ip:port` is the loopback endpoint the ASI advertised in the Hello
//!   reply, with `secure` 0 (Theater/Messenger connect plain, §4 "Who connects how");
//! * UPnP — any other plain connect: the router fetch of the game's UPnP firewall detector, refused (below);
//! * anything else — refused.
//!
//! A routed connection never opens a socket: the ref keeps `socket = NULL`, Connect leaves state 3
//! ("connecting", the value ProtoSSL itself uses while the TCP connect is in flight), the next Update
//! moves it to 0x1e (secure) / 0x1f (plain) and clears the closed flag, exactly as the real Update does
//! when the socket connects (`0x9da5c2`–`0x9da5d4`). A refused connection gets state 0x1002 (connect
//! failed), which Stat reports as −1, so ProtoAries tears it down (§4 return-code contract). Failures after
//! connecting (bad framing from the game, server unreachable) also set 0x1002 and make Send/Recv return −1.
//!
//! Refs that never went through our Connect are "foreign". With no socket they are idle refs and behave as
//! the original would (Stat −1, Send/Recv −1, Update no-op). With a live socket they can only have come
//! from ProtoSSLAccept (inbound TCP); those are refused (logged once, state 0x1002) because every
//! multiplayer path in this design is outbound through the ASI.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::time::Instant;

use crate::config::Config;
use crate::fesl::FeslAdapter;
use crate::log::Logger;
use crate::theater::TheaterAdapter;
use crate::protossl::{
    RefView, SEL_STAT, ST_CONNECTING, ST_FAIL_CONNECT, ST_IDLE, ST_PLAIN, ST_SECURE, recv_into, selector_name,
    send_accepts, split_connect_name, stat_value,
};
use crate::worker::Backend;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    Fesl,
    Theater,
    Messenger,
    /// The UPnP firewall detector fetching the router's description (`FUN_009b2ed0` → ProtoUPnP `FUN_009d6990`
    /// → ProtoHttp `FUN_009ce730` → Connect, `secure` 0). Every direct caller of ProtoHttp's connect paths
    /// (`FUN_009ce730`, `FUN_009cde20`) is ProtoUPnP or the detector, while FESL, Theater and Messenger connect
    /// through ProtoAries (`FUN_009cd3f0`), so a plain connect to no advertised endpoint is this one. Refused:
    /// the relay carries game traffic, so no router port is opened. The detector's result is written only to
    /// the `HDWR` survey (`NNAT`, `UPNP` in `FUN_009b3230`), which nothing else reads.
    Upnp(String),
    Refused(String),
}

/// The address Connect would actually use: a dotted-quad host overrides `ip`, a `:port` suffix overrides
/// `port` (`0x9d9a96` → `0x9d3d40`, `0x9d9aeb`).
pub fn effective_target(host: &[u8], port_override: Option<u16>, ip: u32, port: i32) -> Result<(u32, u16), String> {
    let ip = std::str::from_utf8(host).ok().and_then(|h| h.parse::<Ipv4Addr>().ok()).map(u32::from).unwrap_or(ip);
    let port = match port_override {
        Some(p) => p,
        None => u16::try_from(port).map_err(|_| format!("port argument {port} is not a TCP port"))?,
    };
    Ok((ip, port))
}

pub fn classify(cfg: &Config, secure: bool, host: &[u8], ip: u32, port: u16) -> Route {
    let at = |e: &crate::config::Endpoint| u32::from(e.ip) == ip && e.port == port;
    let host_text = String::from_utf8_lossy(host);
    let target = format!("name={host_text:?} ip={} port={port} secure={}", Ipv4Addr::from(ip), secure as u8);
    if at(&cfg.theater) {
        return if secure {
            Route::Refused(format!("Theater endpoint requested with TLS ({target}); the game connects Theater in plain mode"))
        } else {
            Route::Theater
        };
    }
    if at(&cfg.messenger) {
        return if secure {
            Route::Refused(format!("Messenger endpoint requested with TLS ({target})"))
        } else {
            Route::Messenger
        };
    }
    if cfg.fesl_names.iter().any(|n| n.as_bytes() == host) {
        return if secure {
            Route::Fesl
        } else {
            Route::Refused(format!("FESL name requested without TLS ({target}); the game connects FESL with secure=1"))
        };
    }
    if !secure {
        return Route::Upnp(target);
    }
    Route::Refused(format!("no route for {target}: not a configured FESL name and not an advertised endpoint"))
}

/// A service behind a virtual connection.
pub trait Service: Send {
    fn on_game_bytes(&mut self, bytes: &[u8], now: Instant) -> Result<(), String>;
    fn pump(&mut self, now: Instant) -> Result<(), String>;
    fn outbound(&mut self) -> &mut VecDeque<u8>;
}

impl<B: Backend + Send> Service for FeslAdapter<B> {
    fn on_game_bytes(&mut self, bytes: &[u8], now: Instant) -> Result<(), String> {
        FeslAdapter::on_game_bytes(self, bytes, now).map_err(|e| e.to_string())
    }
    fn pump(&mut self, now: Instant) -> Result<(), String> {
        FeslAdapter::pump(self, now).map_err(|e| e.to_string())
    }
    fn outbound(&mut self) -> &mut VecDeque<u8> {
        FeslAdapter::outbound(self)
    }
}

impl Service for TheaterAdapter {
    fn on_game_bytes(&mut self, bytes: &[u8], now: Instant) -> Result<(), String> {
        TheaterAdapter::on_game_bytes(self, bytes, now)
    }
    fn pump(&mut self, now: Instant) -> Result<(), String> {
        TheaterAdapter::pump(self, now)
    }
    fn outbound(&mut self) -> &mut VecDeque<u8> {
        TheaterAdapter::outbound(self)
    }
}

/// Creates the service for a routed connection.
pub trait ServiceFactory {
    fn fesl(&self) -> Box<dyn Service>;
    /// `Err` names why Theater cannot be served (e.g. the game connects before FESL Login, so there is no
    /// lobby session to serve it from).
    fn theater(&self) -> Result<Box<dyn Service>, String>;
}

/// Everything a Connect call needs besides the ref.
pub struct ConnectEnv<'a> {
    pub cfg: &'a Config,
    pub factory: &'a dyn ServiceFactory,
    pub log: &'a Logger,
}

/// ProtoSSLConnect's arguments after the ref: `(secure, name, ip, port)`.
pub struct ConnectArgs<'a> {
    pub secure: bool,
    pub name: &'a [u8],
    pub ip: u32,
    pub port: i32,
}

enum Entry {
    Virtual { service: Box<dyn Service>, secure: bool, label: &'static str },
    Refused,
}

/// Per-ref state, keyed by the ref's address.
#[derive(Default)]
pub struct Table {
    entries: HashMap<usize, Entry>,
    foreign_logged: HashSet<usize>,
}

impl Table {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_ours(&self, key: usize) -> bool {
        self.entries.contains_key(&key)
    }

    fn refuse(&mut self, key: usize, r: &mut RefView, log: &Logger, why: &str) {
        log.error(format!("ProtoSSL ref {key:#x}: connection refused: {why}"));
        r.set_state(ST_FAIL_CONNECT);
        self.entries.insert(key, Entry::Refused);
    }

    /// A refusal the design intends, logged at INFO: the game handles the failed connect as it would any.
    fn refuse_expected(&mut self, key: usize, r: &mut RefView, log: &Logger, why: &str) {
        log.info(format!("ProtoSSL ref {key:#x}: {why}"));
        r.set_state(ST_FAIL_CONNECT);
        self.entries.insert(key, Entry::Refused);
    }

    /// A ref with a live socket that did not come from our Connect.
    fn foreign(&mut self, key: usize, r: &mut RefView, log: &Logger) -> bool {
        if r.socket() == 0 {
            return false;
        }
        if self.foreign_logged.insert(key) {
            log.error(format!(
                "ProtoSSL ref {key:#x} has a socket ({:#x}) that was not opened through ProtoSSLConnect \
                 (inbound/accepted TCP); refused",
                r.socket()
            ));
        }
        r.set_state(ST_FAIL_CONNECT);
        true
    }

    fn fail(&mut self, key: usize, r: &mut RefView, log: &Logger, what: &str, err: &str) {
        let label = match self.entries.get(&key) {
            Some(Entry::Virtual { label, .. }) => *label,
            _ => "connection",
        };
        log.error(format!("ProtoSSL ref {key:#x}: virtual {label} failed during {what}: {err}"));
        r.set_state(ST_FAIL_CONNECT);
        self.entries.insert(key, Entry::Refused);
    }

    /// ProtoSSLConnect(ref, secure, name, ip, port). Always returns 0, like the original once its socket
    /// exists; refusals surface through the state field.
    pub fn connect(&mut self, key: usize, r: &mut RefView, env: &ConnectEnv, a: ConnectArgs) -> i32 {
        let log = env.log;
        self.entries.remove(&key);
        self.foreign_logged.remove(&key);
        let (host, port_override) = split_connect_name(a.name);
        r.set_closed(true);
        if r.socket() != 0 {
            let why = format!("ref already owns socket {:#x} not opened by this ASI", r.socket());
            self.refuse(key, r, log, &why);
            return 0;
        }
        let (ip, port) = match effective_target(host, port_override, a.ip, a.port) {
            Ok(t) => t,
            Err(why) => {
                self.refuse(key, r, log, &why);
                return 0;
            }
        };
        r.write_target(host, ip, port);
        match classify(env.cfg, a.secure, host, ip, port) {
            Route::Fesl => {
                log.info(format!(
                    "ProtoSSL ref {key:#x}: FESL connect to {:?}:{port} served in-process",
                    String::from_utf8_lossy(host)
                ));
                r.set_state(ST_CONNECTING);
                let service = env.factory.fesl();
                self.entries.insert(key, Entry::Virtual { service, secure: a.secure, label: "FESL" });
            }
            Route::Theater => match env.factory.theater() {
                Ok(service) => {
                    log.info(format!("ProtoSSL ref {key:#x}: Theater connect served in-process"));
                    r.set_state(ST_CONNECTING);
                    self.entries.insert(key, Entry::Virtual { service, secure: a.secure, label: "Theater" });
                }
                Err(why) => self.refuse(key, r, log, &format!("Theater: {why}")),
            },
            Route::Messenger => {
                self.refuse(key, r, log, "Messenger connections are refused by design (friends use FESL asso)")
            }
            Route::Upnp(target) => self.refuse_expected(
                key,
                r,
                log,
                &format!(
                    "UPnP router request refused ({target}): the relay carries game traffic, so no router port \
                     is opened; the detector times out as on a router without UPnP"
                ),
            ),
            Route::Refused(why) => self.refuse(key, r, log, &why),
        }
        0
    }

    /// ProtoSSLUpdate(ref).
    pub fn update(&mut self, key: usize, r: &mut RefView, now: Instant, log: &Logger) {
        let result = match self.entries.get_mut(&key) {
            Some(Entry::Virtual { service, secure, label }) => {
                if r.state() == ST_CONNECTING {
                    r.set_state(if *secure { ST_SECURE } else { ST_PLAIN });
                    r.set_closed(false);
                    log.info(format!("ProtoSSL ref {key:#x}: virtual {label} connected (state {:#x})", r.state()));
                }
                service.pump(now)
            }
            Some(Entry::Refused) => Ok(()),
            None => {
                self.foreign(key, r, log);
                Ok(())
            }
        };
        if let Err(e) = result {
            self.fail(key, r, log, "update", &e);
        }
    }

    /// ProtoSSLSend(ref, buf, len) with `len < 0` already resolved to `strlen(buf)` by the caller.
    pub fn send(&mut self, key: usize, r: &mut RefView, buf: &[u8], now: Instant, log: &Logger) -> i32 {
        let result = match self.entries.get_mut(&key) {
            Some(Entry::Virtual { service, .. }) => {
                let n = send_accepts(r.state(), buf.len());
                if n <= 0 {
                    return n;
                }
                service.on_game_bytes(&buf[..n as usize], now).map(|_| n)
            }
            Some(Entry::Refused) => return -1,
            None => {
                self.foreign(key, r, log);
                return -1;
            }
        };
        result.unwrap_or_else(|e| {
            self.fail(key, r, log, "send", &e);
            -1
        })
    }

    /// ProtoSSLRecv(ref, buf, len).
    pub fn recv(&mut self, key: usize, r: &mut RefView, buf: &mut [u8], now: Instant, log: &Logger) -> i32 {
        let result = match self.entries.get_mut(&key) {
            Some(Entry::Virtual { service, .. }) => match service.pump(now) {
                Ok(()) => Ok(recv_into(r.state(), service.outbound(), false, buf)),
                Err(e) => Err(e),
            },
            Some(Entry::Refused) => return -1,
            None => {
                self.foreign(key, r, log);
                return -1;
            }
        };
        result.unwrap_or_else(|e| {
            self.fail(key, r, log, "recv", &e);
            -1
        })
    }

    /// ProtoSSLStat(ref, sel, buf, len). Only `'stat'` has a meaning without a socket; every other selector
    /// is answered −1 (what the original returns for a ref without a socket) and logged.
    pub fn stat(&mut self, key: usize, r: &mut RefView, sel: u32, log: &Logger) -> i32 {
        let ours = self.entries.contains_key(&key);
        if !ours && self.foreign(key, r, log) {
            return -1;
        }
        if sel == SEL_STAT {
            return if ours { stat_value(r.state()) } else { -1 };
        }
        if ours {
            log.info(format!("ProtoSSL ref {key:#x}: Stat {} has no value on a virtual connection; -1", selector_name(sel)));
        }
        -1
    }

    /// ProtoSSLDisconnect(ref) for a ref we serve: drop the service, leave the ref as Reset does (state 0,
    /// closed). `None` = not ours; the caller runs the original.
    pub fn disconnect(&mut self, key: usize, r: &mut RefView, log: &Logger) -> Option<i32> {
        let entry = self.entries.remove(&key)?;
        if let Entry::Virtual { label, .. } = entry {
            log.info(format!("ProtoSSL ref {key:#x}: virtual {label} disconnected by the game"));
        }
        r.set_state(ST_IDLE);
        r.set_closed(true);
        Some(0)
    }

    /// ProtoSSLDestroy(ref): forget it. The caller then runs the original, which frees the memory.
    pub fn destroy(&mut self, key: usize) {
        self.entries.remove(&key);
        self.foreign_logged.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::sample;
    use crate::log::capture;
    use crate::protossl::{REF_SIZE, SEL_PEER};
    use std::sync::{Arc, Mutex};

    /// Echo service: answers every chunk with its bytes reversed; fails on "FAIL".
    struct Echo {
        out: VecDeque<u8>,
        pumped: Arc<Mutex<u32>>,
    }

    impl Service for Echo {
        fn on_game_bytes(&mut self, b: &[u8], _: Instant) -> Result<(), String> {
            if b == b"FAIL" {
                return Err("bad bytes".into());
            }
            self.out.extend(b.iter().rev());
            Ok(())
        }
        fn pump(&mut self, _: Instant) -> Result<(), String> {
            *self.pumped.lock().unwrap() += 1;
            Ok(())
        }
        fn outbound(&mut self) -> &mut VecDeque<u8> {
            &mut self.out
        }
    }

    struct Factory {
        pumped: Arc<Mutex<u32>>,
        theater: bool,
    }

    impl ServiceFactory for Factory {
        fn fesl(&self) -> Box<dyn Service> {
            Box::new(Echo { out: VecDeque::new(), pumped: self.pumped.clone() })
        }
        fn theater(&self) -> Result<Box<dyn Service>, String> {
            if self.theater {
                Ok(self.fesl())
            } else {
                Err("no lobby session: the game has not logged in through FESL".into())
            }
        }
    }

    struct Rig {
        t: Table,
        mem: Box<[u8; REF_SIZE]>,
        cfg: Config,
        f: Factory,
        log: Logger,
        cap: capture::Captured,
    }

    const KEY: usize = 0x1234_5678;

    fn rig() -> Rig {
        let (log, cap) = capture::logger();
        // A ref as ProtoSSLCreate leaves it: zero-filled, memgroup at +8.
        let mut mem = Box::new([0u8; REF_SIZE]);
        mem[8] = 0x42;
        Rig { t: Table::new(), mem, cfg: sample(), f: Factory { pumped: Arc::default(), theater: false }, log, cap }
    }

    impl Rig {
        fn connect(&mut self, secure: bool, name: &[u8], ip: u32, port: i32) -> i32 {
            let env = ConnectEnv { cfg: &self.cfg, factory: &self.f, log: &self.log };
            self.t.connect(KEY, &mut RefView(&mut self.mem), &env, ConnectArgs { secure, name, ip, port })
        }
        fn update(&mut self) {
            self.t.update(KEY, &mut RefView(&mut self.mem), Instant::now(), &self.log)
        }
        fn stat(&mut self) -> i32 {
            self.t.stat(KEY, &mut RefView(&mut self.mem), SEL_STAT, &self.log)
        }
        fn state(&mut self) -> u32 {
            RefView(&mut self.mem).state()
        }
        fn send(&mut self, b: &[u8]) -> i32 {
            self.t.send(KEY, &mut RefView(&mut self.mem), b, Instant::now(), &self.log)
        }
        fn recv(&mut self, buf: &mut [u8]) -> i32 {
            self.t.recv(KEY, &mut RefView(&mut self.mem), buf, Instant::now(), &self.log)
        }
    }

    #[test]
    fn fesl_lifecycle_follows_the_protossl_contract() {
        let mut g = rig();
        // FESL connect site: secure=1, name "fesl.ea.com" (FUN_00977370 → FUN_009cdab0 → 0x9d9a00).
        assert_eq!(g.connect(true, b"fesl.ea.com\0", 0, 18710), 0);
        assert_eq!(g.state(), ST_CONNECTING);
        assert_eq!(RefView(&mut g.mem).closed(), 1);
        assert_eq!(RefView(&mut g.mem).socket(), 0, "no socket is opened");
        assert_eq!(RefView(&mut g.mem).hostname(), b"fesl.ea.com");
        assert_eq!(RefView(&mut g.mem).sockaddr_port(), 18710);
        assert_eq!(g.mem[8], 0x42, "memgroup untouched");
        assert_eq!(g.stat(), 0, "connecting");
        assert_eq!(g.send(b"x"), -1, "send before connected");
        assert_eq!(g.recv(&mut [0u8; 4]), -1, "recv before connected");

        g.update();
        assert_eq!(g.state(), ST_SECURE);
        assert_eq!(RefView(&mut g.mem).closed(), 0);
        assert_eq!(g.stat(), 1);

        assert_eq!(g.send(b"abc"), 3);
        let mut buf = [0xffu8; 8];
        assert_eq!(g.recv(&mut buf), 3);
        assert_eq!(&buf[..4], b"cba\0");
        assert_eq!(g.recv(&mut buf), 0);

        // Secure Send cap: 16000 bytes per call.
        let big = vec![7u8; 20000];
        assert_eq!(g.send(&big), 16000);

        assert_eq!(g.t.stat(KEY, &mut RefView(&mut g.mem), SEL_PEER, &g.log), -1);
        assert!(g.cap.text().contains("Stat 'peer' has no value on a virtual connection"));

        assert_eq!(g.t.disconnect(KEY, &mut RefView(&mut g.mem), &g.log), Some(0));
        assert_eq!(g.state(), ST_IDLE);
        assert!(!g.t.is_ours(KEY));
        assert!(*g.f.pumped.lock().unwrap() >= 1);
    }

    #[test]
    fn service_failure_tears_the_connection_down() {
        let mut g = rig();
        g.connect(true, b"fesl.ea.com", 0, 18710);
        g.update();
        assert_eq!(g.send(b"FAIL"), -1);
        assert_eq!(g.state(), ST_FAIL_CONNECT);
        assert_eq!(g.stat(), -1);
        assert_eq!(g.recv(&mut [0u8; 4]), -1);
        assert!(g.cap.text().contains("virtual FESL failed during send: bad bytes"));
    }

    #[test]
    fn unknown_targets_are_refused_with_a_named_error() {
        let mut g = rig();
        g.connect(true, b"locate.madserver.net", 0, 80);
        assert_eq!(g.state(), ST_FAIL_CONNECT);
        assert_eq!(g.stat(), -1);
        g.update();
        assert_eq!(g.state(), ST_FAIL_CONNECT, "update does not revive a refused ref");
        let log = g.cap.text();
        assert!(log.contains("connection refused: no route for name=\"locate.madserver.net\" ip=0.0.0.0 port=80 secure=1"), "{log}");
    }

    #[test]
    fn the_upnp_router_fetch_is_refused_at_info() {
        // The 2026-10-11 capture: name="192.168.1.1" ip=192.168.1.1 port=34569 secure=0.
        let mut g = rig();
        g.connect(false, b"192.168.1.1", 0xc0a8_0101, 34569);
        assert_eq!(g.state(), ST_FAIL_CONNECT);
        assert_eq!(g.stat(), -1);
        let log = g.cap.text();
        assert!(log.contains("INFO  ProtoSSL ref"), "{log}");
        assert!(log.contains("UPnP router request refused (name=\"192.168.1.1\" ip=192.168.1.1 port=34569 secure=0)"), "{log}");
        assert!(!log.contains("ERROR"), "{log}");
    }

    #[test]
    fn fesl_name_without_tls_is_refused() {
        let mut g = rig();
        g.connect(false, b"fesl.ea.com", 0, 18710);
        assert_eq!(g.state(), ST_FAIL_CONNECT);
    }

    #[test]
    fn theater_routes_by_advertised_endpoint_even_with_the_fesl_name() {
        // ProtoAries passes the literal "fesl.ea.com" for every service it connects (FUN_00977370), so
        // Theater must be recognised by ip:port first.
        let mut g = rig();
        g.f.theater = true;
        g.connect(false, b"fesl.ea.com", 0x7f00_0001, 14300);
        assert_eq!(g.state(), ST_CONNECTING);
        g.update();
        assert_eq!(g.state(), ST_PLAIN);
        assert_eq!(g.send(&vec![1u8; 20000]), 20000, "plain send is not capped");
    }

    #[test]
    fn theater_the_factory_cannot_serve_is_refused() {
        let mut g = rig();
        g.connect(false, b"127.0.0.1", 0, 14300);
        assert_eq!(g.state(), ST_FAIL_CONNECT);
        assert!(g.cap.text().contains("Theater: no lobby session: the game has not logged in through FESL"));
    }

    #[test]
    fn messenger_is_refused_by_design() {
        let mut g = rig();
        g.connect(false, b"", 0x7f00_0001, 13505);
        assert_eq!(g.state(), ST_FAIL_CONNECT);
        assert!(g.cap.text().contains("Messenger connections are refused by design"));
    }

    #[test]
    fn name_port_suffix_and_dotted_host_override_arguments() {
        assert_eq!(effective_target(b"127.0.0.1", Some(14300), 0, 1), Ok((0x7f00_0001, 14300)));
        assert_eq!(effective_target(b"fesl.ea.com", None, 5, 18710), Ok((5, 18710)));
        assert!(effective_target(b"x", None, 0, 70000).is_err());
        let mut g = rig();
        g.f.theater = true;
        g.connect(false, b"127.0.0.1:14300", 0, 0);
        assert_eq!(g.state(), ST_CONNECTING);
    }

    #[test]
    fn foreign_refs() {
        let mut g = rig();
        // Idle ref from Create: behaves like the original with no socket.
        assert_eq!(g.stat(), -1);
        assert_eq!(g.send(b"x"), -1);
        g.update();
        assert_eq!(g.state(), ST_IDLE);
        assert_eq!(g.t.disconnect(KEY, &mut RefView(&mut g.mem), &g.log), None, "original Disconnect runs");
        // Accepted ref with a live socket: refused once, loudly.
        g.mem[0] = 0x10;
        g.update();
        assert_eq!(g.state(), ST_FAIL_CONNECT);
        assert_eq!(g.stat(), -1);
        assert_eq!(g.cap.text().matches("was not opened through ProtoSSLConnect").count(), 1);
    }

    #[test]
    fn reconnect_replaces_the_previous_virtual_connection() {
        let mut g = rig();
        g.connect(true, b"fesl.ea.com", 0, 18710);
        g.update();
        g.send(b"abc");
        g.connect(true, b"fesl.ea.com", 0, 18710);
        g.update();
        assert_eq!(g.recv(&mut [0u8; 8]), 0, "old service's bytes are gone");
        g.t.destroy(KEY);
        assert!(!g.t.is_ours(KEY));
    }
}
