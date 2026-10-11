//! Test-only: the real `mercs2_mp_server` started in-process (proxied TLS mode, generated self-signed
//! certificates, ephemeral HTTPS port, a free UDP port for the relay that is also its advertised port) plus
//! helpers that log in through this crate's own REST client and open its own lobby WebSocket.

use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use mercs2_mp_api::rest::{ClientInfo, CreateAccount, CreateSession};
use mercs2_mp_server::config::*;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509, X509NameBuilder};

use mercs2_mp_api::ApiError;
use mercs2_mp_api::ws::{Push, Request, Response};

use crate::config::BaseUrl;
use crate::lobby::{Lobby, LobbyEvent};
use crate::http::HttpsClient;
use crate::log::{Logger, capture};
use crate::session::LoggedIn;
use crate::worker::{BackendFailure, BackendReply, BackendRequest, RestApi};
use crate::ws::{WsLobbyProvider, WsSettings};

fn self_signed(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key: PKey<Private> = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_nid(Nid::COMMONNAME, "localhost").unwrap();
    let subject = subject.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    b.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
    b.set_subject_name(&subject).unwrap();
    b.set_issuer_name(&subject).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap()).unwrap();
    let san = SubjectAlternativeName::new().dns("localhost").build(&b.x509v3_context(None, None)).unwrap();
    b.append_extension(san).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let cert_path = dir.join(format!("{name}-cert.pem"));
    let key_path = dir.join(format!("{name}-key.pem"));
    std::fs::write(&cert_path, b.build().to_pem().unwrap()).unwrap();
    std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    (cert_path, key_path)
}

pub struct TestServer {
    pub https: SocketAddr,
    pub https_ca_pem: Vec<u8>,
    log: Logger,
}

impl TestServer {
    pub fn start() -> TestServer {
        Self::start_with_relay_idle(30)
    }

    /// `relay_idle_secs`: the relay's `idle_timeout_secs` (what the clients' keepalive must beat).
    pub fn start_with_relay_idle(relay_idle_secs: u64) -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let (https_cert, https_key) = self_signed(dir.path(), "https");
        let (relay_cert, relay_key) = self_signed(dir.path(), "relay");
        // The shim dials the advertised relay address, so the relay must listen on the port it advertises.
        let relay_port = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let cfg = Config {
            log: LogConfig { filter: "info".into(), format: LogFormat::Text },
            server: ServerConfig { https_listen: "127.0.0.1:0".parse().unwrap(), tls_handshake_timeout_secs: 5 },
            database: DatabaseConfig { path: dir.path().join("mp.sqlite") },
            accounts: AccountsConfig {
                session_ttl_secs: 3600,
                argon2_memory_kib: 256,
                argon2_iterations: 1,
                argon2_parallelism: 1,
            },
            rate_limit: RateLimitConfig {
                accounts: BucketConfig { burst: 1000, refill_per_minute: 1000 },
                sessions: BucketConfig { burst: 1000, refill_per_minute: 1000 },
            },
            websocket: WebSocketConfig {
                max_message_bytes: 65536,
                outbound_queue: 64,
                ping_interval_secs: 5,
                idle_timeout_secs: 30,
            },
            games: GamesConfig { max_players_limit: 4 },
            relay: RelayConfig {
                listen: SocketAddr::from(([127, 0, 0, 1], relay_port)),
                public_host: "127.0.0.1".into(),
                public_port: relay_port,
                cert_pem: relay_cert,
                key_pem: relay_key,
                idle_timeout_secs: relay_idle_secs,
                handshake_timeout_secs: 5,
                max_pending_handshakes: 16,
                mtu: 1200,
                tick_millis: 100,
            },
            tls: TlsConfig::Proxied(ProxiedConfig {
                cert_pem: https_cert.clone(),
                key_pem: https_key,
                // Proxied mode requires a proxy range; TEST-NET-1 keeps 127.0.0.1 a direct client, as a player is.
                trusted_proxies: vec!["192.0.2.0/24".parse().unwrap()],
            }),
        };
        cfg.validate().unwrap();
        let https_ca_pem = std::fs::read(&https_cert).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _dir = dir;
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let running = mercs2_mp_server::start(cfg).await.unwrap();
                tx.send(running.https_addr).unwrap();
                panic!("test server stopped: {}", running.wait().await);
            })
        });
        let https = rx.recv_timeout(Duration::from_secs(30)).unwrap();
        let (log, _text) = capture::logger();
        TestServer { https, https_ca_pem, log }
    }

    pub fn base(&self) -> BaseUrl {
        BaseUrl { host: "localhost".into(), port: self.https.port(), prefix: String::new() }
    }

    pub fn log(&self) -> Logger {
        self.log.clone()
    }

    pub fn ws_settings(&self) -> WsSettings {
        WsSettings {
            base: self.base(),
            connector: crate::tls::connector(&self.https_ca_pem).unwrap(),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(2),
            idle_timeout: Duration::from_secs(20),
        }
    }

    fn rest(&self) -> RestApi {
        RestApi::new(HttpsClient::new(
            crate::tls::connector(&self.https_ca_pem).unwrap(),
            self.base(),
            Duration::from_secs(5),
            Duration::from_secs(5),
        ))
    }

    /// Create the account `name` (password `password-<name>`) and log in through the REST client.
    pub fn login(&self, name: &str) -> LoggedIn {
        let rest = self.rest();
        let password = format!("password-{name}");
        match rest.execute(&BackendRequest::CreateAccount(CreateAccount { username: name.into(), password: password.clone() })) {
            Ok(BackendReply::AccountCreated(_)) => {}
            Err(BackendFailure::Api(e)) if e.code == mercs2_mp_api::ErrorCode::NameTaken => {}
            other => panic!("create account {name}: {other:?}"),
        }
        let req = CreateSession {
            username: name.into(),
            password,
            client: ClientInfo { build_sha256: "ab".repeat(32), asi_version: crate::ASI_VERSION.into() },
        };
        let Ok(BackendReply::SessionCreated(s)) = rest.execute(&BackendRequest::CreateSession(req)) else {
            panic!("login {name} failed")
        };
        LoggedIn { token: s.token, user_id: s.user_id, display_name: s.display_name, expires_at: s.expires_at, lkey: format!("lkey-{name}") }
    }

    /// Log in and open the lobby WebSocket for `name`.
    pub fn provider(&self, name: &str) -> (WsLobbyProvider, LoggedIn) {
        let session = self.login(name);
        let p = WsLobbyProvider::new(self.ws_settings(), self.log());
        crate::lobby::LobbyProvider::start(&p, &session).unwrap();
        (p, session)
    }
}

/// Poll `f` until it yields, failing the test after 10 s.
pub fn wait<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(std::time::Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Send `req` and wait for its answer; pushes seen meanwhile are returned too.
pub fn call(l: &mut dyn Lobby, req: Request) -> (Result<Response, ApiError>, Vec<Push>) {
    let id = l.request(req).unwrap();
    let mut pushes = Vec::new();
    let result = wait("a lobby reply", || {
        let mut found = None;
        for e in l.poll().unwrap() {
            match e {
                LobbyEvent::Reply { id: rid, result } if rid == id => found = Some(result),
                LobbyEvent::Reply { id: other, .. } => panic!("reply for request {other} while waiting for {id}"),
                LobbyEvent::Push(p) => pushes.push(p),
            }
        }
        found
    });
    (result, pushes)
}

/// Wait for the next push on `l`.
pub fn next_push(l: &mut dyn Lobby) -> Push {
    wait("a lobby push", || {
        l.poll().unwrap().into_iter().map(|e| match e {
            LobbyEvent::Push(p) => p,
            LobbyEvent::Reply { id, .. } => panic!("unexpected reply {id}"),
        }).next()
    })
}
