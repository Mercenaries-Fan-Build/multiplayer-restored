//! The lobby WebSocket (`GET <base>/v1/ws`, `mp_api::ws`) on its own thread.
//!
//! Transport: the same TLS policy as the REST client ([`crate::tls`]: TLS ≥ 1.2, SNI, chain verification
//! against the embedded Mozilla bundle, hostname verification), `Authorization: Bearer <session token>` on
//! the upgrade request, RFC 6455 framing by `tungstenite`. The TCP connect, TLS handshake and upgrade run
//! blocking with the `[http]` timeouts; after that the socket is switched to non-blocking and the thread
//! services it every `[websocket] poll_interval_ms` (sends queued requests, reads frames). `tungstenite`
//! answers the server's pings itself; those pongs are what keeps the server's idle timer fed.
//!
//! Correlation: each request gets a process-unique id; the reply or error frame carrying that id is routed
//! to the handle that sent it. Pushes go to the one handle that subscribed ([`LobbyProvider::handle`] with
//! `pushes`); a push with no subscriber is logged as an error (it has nowhere to go in the game).
//!
//! Ending: any failure — connect/TLS/upgrade error (e.g. HTTP 401 for an expired token), a close frame, a
//! transport error, a frame that is not valid `ServerFrame` JSON, a reply for an id nobody sent, or no frame
//! from the server for `[websocket] idle_timeout_secs` — ends the lobby with a named reason: logged, and
//! returned by every handle from then on. Nothing reconnects.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mp_api::ApiError;
use mp_api::ws::{ClientFrame, Push, Request, Response, ServerFrame};
use openssl::ssl::{SslConnector, SslStream};
use tungstenite::client::IntoClientRequest;
use tungstenite::{HandshakeError, Message, WebSocket};

use crate::config::BaseUrl;
use crate::lobby::{Lobby, LobbyEvent, LobbyProvider};
use crate::log::Logger;
use crate::session::LoggedIn;

/// What the WebSocket thread needs besides the token.
#[derive(Clone)]
pub struct WsSettings {
    pub base: BaseUrl,
    pub connector: SslConnector,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub poll_interval: Duration,
    pub idle_timeout: Duration,
}

type ReplyTx = Sender<(u64, Result<Response, ApiError>)>;

struct Shared {
    /// Set exactly once, when the lobby ends; the reason every handle reports from then on.
    dead: Mutex<Option<String>>,
    routes: Mutex<HashMap<u64, ReplyTx>>,
    pushes: Mutex<Option<Sender<Push>>>,
    next_id: AtomicU64,
    outbound: Mutex<Sender<ClientFrame>>,
    stop: AtomicBool,
}

impl Shared {
    fn dead_reason(&self) -> Option<String> {
        match self.dead.lock() {
            Ok(d) => d.clone(),
            Err(_) => Some("lobby state lock poisoned".into()),
        }
    }

    /// Record the end (first reason wins).
    fn end(&self, reason: String) {
        if let Ok(mut d) = self.dead.lock()
            && d.is_none()
        {
            *d = Some(reason);
        }
    }
}

/// The thread is not joined: it may be inside a blocking connect bounded only by the `[http]` timeouts, and
/// `start` runs on the game thread. It notices `stop` within one poll interval once connected.
struct Connection {
    shared: Arc<Shared>,
}

/// The production [`LobbyProvider`].
pub struct WsLobbyProvider {
    settings: WsSettings,
    log: Logger,
    current: Mutex<Option<Connection>>,
}

impl WsLobbyProvider {
    pub fn new(settings: WsSettings, log: Logger) -> Self {
        WsLobbyProvider { settings, log, current: Mutex::new(None) }
    }
}

impl Drop for WsLobbyProvider {
    fn drop(&mut self) {
        if let Ok(mut cur) = self.current.lock()
            && let Some(old) = cur.take()
        {
            stop(old, "the ASI is shutting the lobby down");
        }
    }
}

fn stop(c: Connection, why: &str) {
    c.shared.end(why.to_owned());
    c.shared.stop.store(true, Ordering::Release);
}

impl LobbyProvider for WsLobbyProvider {
    fn start(&self, session: &LoggedIn) -> Result<(), String> {
        let mut cur = self.current.lock().map_err(|_| "lobby provider lock poisoned".to_string())?;
        if let Some(old) = cur.take() {
            self.log.info("lobby WebSocket: closing the previous session's connection (new login)");
            stop(old, "superseded by a new login");
        }
        let (out_tx, out_rx) = channel();
        let shared = Arc::new(Shared {
            dead: Mutex::new(None),
            routes: Mutex::new(HashMap::new()),
            pushes: Mutex::new(None),
            next_id: AtomicU64::new(1),
            outbound: Mutex::new(out_tx),
            stop: AtomicBool::new(false),
        });
        let (s, settings, log, token) = (shared.clone(), self.settings.clone(), self.log.clone(), session.token.clone());
        let user = session.display_name.clone();
        std::thread::Builder::new()
            .name("mp-restored-lobby".into())
            .spawn(move || {
                let result = run(&s, &settings, &log, &token, out_rx);
                let reason = match result {
                    Ok(()) => s.dead_reason().unwrap_or_else(|| "lobby WebSocket stopped".into()),
                    Err(e) => e,
                };
                s.end(reason.clone());
                if !s.stop.load(Ordering::Acquire) {
                    log.error(format!("lobby WebSocket for {user:?} ended: {reason}"));
                }
                // Replies that will never come: drop their routes so nothing waits on them.
                if let Ok(mut r) = s.routes.lock() {
                    r.clear();
                }
            })
            .map_err(|e| format!("cannot start the lobby thread: {e}"))?;
        *cur = Some(Connection { shared });
        Ok(())
    }

    fn handle(&self, pushes: bool) -> Result<Box<dyn Lobby>, String> {
        let cur = self.current.lock().map_err(|_| "lobby provider lock poisoned".to_string())?;
        let c = cur.as_ref().ok_or("no lobby session: the game has not logged in through FESL")?;
        if let Some(d) = c.shared.dead_reason() {
            return Err(format!("the lobby session ended: {d}"));
        }
        let (reply_tx, reply_rx) = channel();
        let push_rx = if pushes {
            let (tx, rx) = channel();
            let mut slot = c.shared.pushes.lock().map_err(|_| "lobby push lock poisoned".to_string())?;
            if slot.replace(tx).is_some() {
                self.log.info("lobby pushes: a new Theater connection takes over from the previous one");
            }
            Some(rx)
        } else {
            None
        };
        Ok(Box::new(WsLobby { shared: c.shared.clone(), reply_tx, reply_rx, push_rx }))
    }
}

struct WsLobby {
    shared: Arc<Shared>,
    reply_tx: ReplyTx,
    reply_rx: Receiver<(u64, Result<Response, ApiError>)>,
    push_rx: Option<Receiver<Push>>,
}

impl Lobby for WsLobby {
    fn request(&mut self, request: Request) -> Result<u64, String> {
        if let Some(d) = self.shared.dead_reason() {
            return Err(format!("the lobby session ended: {d}"));
        }
        let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
        self.shared.routes.lock().map_err(|_| "lobby route lock poisoned".to_string())?.insert(id, self.reply_tx.clone());
        let out = self.shared.outbound.lock().map_err(|_| "lobby outbound lock poisoned".to_string())?;
        out.send(ClientFrame { id, request }).map_err(|_| "the lobby thread is not running".to_string())?;
        Ok(id)
    }

    fn poll(&mut self) -> Result<Vec<LobbyEvent>, String> {
        if let Some(d) = self.shared.dead_reason() {
            return Err(format!("the lobby session ended: {d}"));
        }
        let mut out: Vec<LobbyEvent> = self.reply_rx.try_iter().map(|(id, result)| LobbyEvent::Reply { id, result }).collect();
        if let Some(rx) = &self.push_rx {
            out.extend(rx.try_iter().map(LobbyEvent::Push));
        }
        Ok(out)
    }
}

type Ws = WebSocket<SslStream<TcpStream>>;

/// URL of the WebSocket route for `base`.
pub fn ws_url(base: &BaseUrl) -> String {
    if base.port == 443 {
        format!("wss://{}{}", base.host, base.path("/v1/ws"))
    } else {
        format!("wss://{}:{}{}", base.host, base.port, base.path("/v1/ws"))
    }
}

fn connect(settings: &WsSettings, token: &str) -> Result<Ws, String> {
    let base = &settings.base;
    let tcp = crate::http::connect_tcp(base, settings.connect_timeout, settings.io_timeout).map_err(|e| e.to_string())?;
    let tls = settings
        .connector
        .connect(&base.host, tcp)
        .map_err(|e| format!("TLS handshake with {} failed: {e}", base.host))?;
    let url = ws_url(base);
    let mut req = url.as_str().into_client_request().map_err(|e| format!("WebSocket request for {url}: {e}"))?;
    let auth = format!("Bearer {token}").parse().map_err(|e| format!("Authorization header: {e}"))?;
    req.headers_mut().insert("authorization", auth);
    let (ws, _) = tungstenite::client::client(req, tls).map_err(|e| match e {
        HandshakeError::Failure(tungstenite::Error::Http(rsp)) => {
            let body = rsp.body().as_ref().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
            format!("WebSocket upgrade refused with HTTP {}: {body}", rsp.status())
        }
        HandshakeError::Failure(e) => format!("WebSocket upgrade failed: {e}"),
        HandshakeError::Interrupted(_) => "WebSocket upgrade interrupted on a blocking socket".to_string(),
    })?;
    ws.get_ref().get_ref().set_nonblocking(true).map_err(|e| format!("cannot make the lobby socket non-blocking: {e}"))?;
    Ok(ws)
}

fn would_block(e: &tungstenite::Error) -> bool {
    matches!(e, tungstenite::Error::Io(io) if io.kind() == ErrorKind::WouldBlock)
}

fn run(shared: &Shared, settings: &WsSettings, log: &Logger, token: &str, outbound: Receiver<ClientFrame>) -> Result<(), String> {
    let mut ws = connect(settings, token)?;
    log.info(format!("lobby WebSocket connected to {}", ws_url(&settings.base)));
    let mut last_inbound = Instant::now();
    loop {
        if shared.stop.load(Ordering::Acquire) {
            // Best effort: the session is over either way and the reason is already recorded.
            let _close = ws.close(None).and_then(|_| ws.flush());
            return Ok(());
        }
        loop {
            match outbound.try_recv() {
                Ok(frame) => {
                    let text = serde_json::to_string(&frame).map_err(|e| format!("encode request {}: {e}", frame.id))?;
                    match ws.write(Message::text(text)) {
                        Ok(()) => {}
                        Err(e) if would_block(&e) => {}
                        Err(e) => return Err(format!("sending request {}: {e}", frame.id)),
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Err("request queue closed".into()),
            }
        }
        match ws.flush() {
            Ok(()) => {}
            Err(e) if would_block(&e) => {}
            Err(e) => return Err(format!("writing to the server: {e}")),
        }
        loop {
            match ws.read() {
                Ok(msg) => {
                    last_inbound = Instant::now();
                    inbound(shared, log, msg)?;
                }
                Err(e) if would_block(&e) => break,
                Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                    return Err("the server closed the connection".into());
                }
                Err(e) => return Err(format!("reading from the server: {e}")),
            }
        }
        if last_inbound.elapsed() > settings.idle_timeout {
            return Err(format!("no frame from the server for {} s", settings.idle_timeout.as_secs()));
        }
        std::thread::sleep(settings.poll_interval);
    }
}

fn inbound(shared: &Shared, log: &Logger, msg: Message) -> Result<(), String> {
    let text = match msg {
        Message::Text(t) => t,
        Message::Close(Some(f)) => return Err(format!("the server closed the session: {} {}", u16::from(f.code), f.reason)),
        Message::Close(None) => return Err("the server closed the session without a reason".into()),
        // Pings are answered by tungstenite on the next write/flush; pongs carry nothing.
        Message::Ping(_) | Message::Pong(_) => return Ok(()),
        Message::Binary(_) | Message::Frame(_) => return Err("the server sent a non-text frame".into()),
    };
    let frame: ServerFrame =
        serde_json::from_str(text.as_str()).map_err(|e| format!("server frame is not mp_api v1 JSON ({e}): {}", text.as_str()))?;
    let (id, result) = match frame {
        ServerFrame::Reply { id, response } => (id, Ok(response)),
        ServerFrame::Error { id, error } => (id, Err(error)),
        ServerFrame::Push { push } => {
            let sink = shared.pushes.lock().map_err(|_| "lobby push lock poisoned".to_string())?;
            let delivered = sink.as_ref().is_some_and(|tx| tx.send(push.clone()).is_ok());
            if !delivered {
                log.error(format!("lobby push with no Theater connection to deliver it to: {push:?}"));
            }
            return Ok(());
        }
    };
    let route = shared
        .routes
        .lock()
        .map_err(|_| "lobby route lock poisoned".to_string())?
        .remove(&id)
        .ok_or_else(|| format!("the server answered request id {id}, which this client never sent"))?;
    // The handle that asked may have been dropped with its connection; its answers are no longer wanted.
    let _delivered = route.send((id, result));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testserver::{TestServer, wait};
    use mp_api::ws::{CreateGame, Joinability, Privacy};
    use mp_api::{ErrorCode, GameId};

    fn reply(l: &mut dyn Lobby, id: u64) -> Result<Response, ApiError> {
        wait("a reply", || {
            l.poll().unwrap().into_iter().find_map(|e| match e {
                LobbyEvent::Reply { id: rid, result } if rid == id => Some(result),
                _ => None,
            })
        })
    }

    fn create(name: &str) -> Request {
        Request::GamesCreate(CreateGame {
            name: name.into(),
            max_players: 2,
            version: "1.1".into(),
            joinable: Joinability::Open,
            attrs: Default::default(),
            privacy: Privacy::default(),
        })
    }

    #[test]
    fn requests_replies_and_pushes_against_the_real_server() {
        let srv = TestServer::start();
        let (host_p, host_s) = srv.provider("WsHost");
        let (join_p, _) = srv.provider("WsJoiner");
        let mut host = host_p.handle(true).unwrap();
        let mut joiner = join_p.handle(true).unwrap();
        let mut other = host_p.handle(false).unwrap();

        // Two handles on one connection: each gets only its own replies.
        let a = host.request(Request::Ping).unwrap();
        let b = other.request(Request::Ping).unwrap();
        assert_eq!(reply(&mut *other, b), Ok(Response::Pong));
        assert_eq!(reply(&mut *host, a), Ok(Response::Pong));

        let id = host.request(create("ws test")).unwrap();
        let Ok(Response::GameCreated(game)) = reply(&mut *host, id) else { panic!("expected game_created") };
        let id = joiner.request(Request::GamesJoin { game_id: game.game_id, room_key: None }).unwrap();
        assert!(matches!(reply(&mut *joiner, id), Ok(Response::JoinPending { .. })));
        let push = wait("join request push", || {
            host.poll().unwrap().into_iter().find_map(|e| match e {
                LobbyEvent::Push(p) => Some(p),
                LobbyEvent::Reply { .. } => None,
            })
        });
        assert!(matches!(push, Push::JoinRequest { game_id, .. } if game_id == game.game_id), "{push:?}");

        // Server-side errors come back as ApiError on the same id.
        let id = joiner.request(Request::GamesGet { game_id: GameId(999), room_key: None }).unwrap();
        assert_eq!(reply(&mut *joiner, id).unwrap_err().code, ErrorCode::NotFound);

        // A new login replaces the connection; the old handles report the end, loudly and for good.
        host_p.start(&host_s).unwrap();
        let e = host.poll().unwrap_err();
        assert!(e.contains("superseded by a new login"), "{e}");
        assert!(host.request(Request::Ping).is_err());
    }

    #[test]
    fn bad_token_ends_the_lobby_with_the_http_status() {
        let srv = TestServer::start();
        let p = WsLobbyProvider::new(srv.ws_settings(), srv.log());
        let mut s = srv.login("WsBadToken");
        s.token = "not-a-token".into();
        p.start(&s).unwrap();
        let mut h = p.handle(false).unwrap();
        let e = wait("the lobby to end", || h.poll().err());
        assert!(e.contains("HTTP 401"), "{e}");
        assert!(p.handle(false).err().unwrap().contains("HTTP 401"));
    }

    #[test]
    fn server_silence_ends_the_lobby() {
        let srv = TestServer::start();
        let mut settings = srv.ws_settings();
        // The test server pings every 5 s; a 1 s idle limit must trip first.
        settings.idle_timeout = Duration::from_secs(1);
        let p = WsLobbyProvider::new(settings, srv.log());
        p.start(&srv.login("WsQuiet")).unwrap();
        let mut h = p.handle(false).unwrap();
        let e = wait("the idle timeout", || h.poll().err());
        assert!(e.contains("no frame from the server for 1 s"), "{e}");
    }

    #[test]
    fn handle_before_login_is_refused() {
        let srv = TestServer::start();
        let p = WsLobbyProvider::new(srv.ws_settings(), srv.log());
        assert!(p.handle(true).err().unwrap().contains("has not logged in"));
    }

    #[test]
    fn url_shape() {
        let b = BaseUrl { host: "mp.example.org".into(), port: 443, prefix: "/api".into() };
        assert_eq!(ws_url(&b), "wss://mp.example.org/api/v1/ws");
        let b = BaseUrl { host: "localhost".into(), port: 8443, prefix: String::new() };
        assert_eq!(ws_url(&b), "wss://localhost:8443/v1/ws");
    }
}
