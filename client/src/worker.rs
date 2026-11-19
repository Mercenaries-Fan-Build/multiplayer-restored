//! Backend requests run off the game thread.
//!
//! The FESL adapter (on the game thread, inside ProtoSSL Update/Recv) submits a [`BackendRequest`] and
//! later polls for its [`Outcome`]; a single worker thread executes requests in order with the blocking
//! [`HttpsClient`]. The adapter is generic over [`Backend`] so tests can drive it without a network. The
//! leaderboard bindings ([`crate::leaderboard`]) submit their two requests through a handle of the same worker.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use mercs2_mp_api::ApiError;
use mercs2_mp_api::rest::{AccountCreated, CreateAccount, CreateSession, LeaderboardEntry, PushScore, SessionCreated};
use serde::de::DeserializeOwned;

use mercs2_https::{HttpsClient, Method};

/// A session token, sent as `Authorization: Bearer <token>`. Its `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct Bearer(pub String);

impl std::fmt::Debug for Bearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Bearer(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendRequest {
    CreateAccount(CreateAccount),
    CreateSession(CreateSession),
    /// `GET /v1/leaderboards/{board}/me`; `board` is the Lua string's bytes, sent as one encoded path segment.
    LeaderboardMe { board: Vec<u8>, token: Bearer },
    /// `PUT /v1/leaderboards/{board}/score` with `{"score": score}`.
    LeaderboardPush { board: Vec<u8>, score: u32, token: Bearer },
}

impl BackendRequest {
    pub fn describe(&self) -> String {
        match self {
            BackendRequest::CreateAccount(c) => format!("POST /v1/accounts (username {:?})", c.username),
            BackendRequest::CreateSession(c) => format!("POST /v1/sessions (username {:?})", c.username),
            BackendRequest::LeaderboardMe { board, .. } => format!("GET /v1/leaderboards/{}/me", crate::leaderboard::path_segment(board)),
            BackendRequest::LeaderboardPush { board, score, .. } => {
                format!("PUT /v1/leaderboards/{}/score (score {score})", crate::leaderboard::path_segment(board))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendReply {
    AccountCreated(AccountCreated),
    SessionCreated(SessionCreated),
    /// The player's standing on a board, after a push or as asked.
    LeaderboardEntry(LeaderboardEntry),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendFailure {
    /// The server answered with an `ApiError` body.
    Api(ApiError),
    /// No usable answer: DNS, connect, TLS verification, I/O, or a malformed/unexpected response.
    Transport(String),
}

pub type Outcome = Result<BackendReply, BackendFailure>;

pub type JobId = u64;

pub trait Backend {
    fn submit(&mut self, id: JobId, req: BackendRequest);
    fn poll(&mut self) -> Vec<(JobId, Outcome)>;
}

/// Largest REST response body accepted (`mercs2_https::Limits::max_body`). The largest success body the API
/// defines is `SessionCreated`: a 64-hex-digit token, two i64 numbers and a display name of at most
/// `rules::USERNAME_MAX` (31) ASCII characters, about 190 bytes of JSON. An `ApiError` body is a code and a
/// server-written message, which the contract does not bound; the server's messages are a fixed text, or a fixed
/// text plus a JSON or request-parsing error string, and an internal error is always the fixed "internal error".
/// 64 KiB is over 300 times the largest defined body.
pub const MAX_RESPONSE_BODY: usize = 64 * 1024;

/// Typed REST calls on top of [`HttpsClient`]: `http` for the account and session routes, `boards` (the same
/// server, with the leaderboards' own request deadline, [`crate::leaderboard::TIMEOUT`]) for the two
/// leaderboard routes.
pub struct RestApi {
    http: HttpsClient,
    boards: HttpsClient,
}

impl RestApi {
    pub fn new(http: HttpsClient, boards: HttpsClient) -> Self {
        RestApi { http, boards }
    }

    fn call<T: DeserializeOwned>(&self, route: &str, body: &impl serde::Serialize, expect: u16) -> Result<T, BackendFailure> {
        let json = serde_json::to_vec(body).map_err(|e| BackendFailure::Transport(format!("encode {route}: {e}")))?;
        self.send(&self.http, Method::Post, route, &[], Some(&json), expect)
    }

    /// `method route` on `client` with `headers` and an optional JSON body; the decoded body of an `expect`
    /// answer, the `ApiError` of an error status, or why neither arrived.
    fn send<T: DeserializeOwned>(
        &self,
        client: &HttpsClient,
        method: Method,
        route: &str,
        headers: &[(&str, &str)],
        json: Option<&[u8]>,
        expect: u16,
    ) -> Result<T, BackendFailure> {
        let resp = client.request(method, route, headers, json).map_err(|e| BackendFailure::Transport(e.to_string()))?;
        let snippet = || String::from_utf8_lossy(&resp.body[..resp.body.len().min(200)]).into_owned();
        if resp.status == expect {
            return serde_json::from_slice(&resp.body).map_err(|e| {
                BackendFailure::Transport(format!("{route}: HTTP {} body is not the expected JSON ({e}): {}", resp.status, snippet()))
            });
        }
        match serde_json::from_slice::<ApiError>(&resp.body) {
            Ok(api) if !(200..300).contains(&resp.status) => Err(BackendFailure::Api(api)),
            _ => Err(BackendFailure::Transport(format!(
                "{route}: unexpected HTTP {} (expected {expect}): {}",
                resp.status,
                snippet()
            ))),
        }
    }

    pub fn execute(&self, req: &BackendRequest) -> Outcome {
        match req {
            BackendRequest::CreateAccount(c) => self.call("/v1/accounts", c, 201).map(BackendReply::AccountCreated),
            BackendRequest::CreateSession(c) => self.call("/v1/sessions", c, 200).map(BackendReply::SessionCreated),
            BackendRequest::LeaderboardMe { board, token } => {
                let route = format!("/v1/leaderboards/{}/me", crate::leaderboard::path_segment(board));
                let auth = format!("Bearer {}", token.0);
                self.send(&self.boards, Method::Get, &route, &[("Authorization", auth.as_str())], None, 200)
                    .map(BackendReply::LeaderboardEntry)
            }
            BackendRequest::LeaderboardPush { board, score, token } => {
                let route = format!("/v1/leaderboards/{}/score", crate::leaderboard::path_segment(board));
                let auth = format!("Bearer {}", token.0);
                let json = serde_json::to_vec(&PushScore { score: *score })
                    .map_err(|e| BackendFailure::Transport(format!("encode {route}: {e}")))?;
                self.send(&self.boards, Method::Put, &route, &[("Authorization", auth.as_str())], Some(&json), 200)
                    .map(BackendReply::LeaderboardEntry)
            }
        }
    }
}

struct Job {
    id: JobId,
    req: BackendRequest,
    reply: Sender<(JobId, Outcome)>,
}

/// The worker thread. Dropping every [`WorkerHandle`] and the `Worker` ends it.
pub struct Worker {
    tx: Sender<Job>,
    _thread: JoinHandle<()>,
}

impl Worker {
    pub fn spawn(exec: impl Fn(&BackendRequest) -> Outcome + Send + 'static) -> std::io::Result<Self> {
        let (tx, rx) = channel::<Job>();
        let thread = std::thread::Builder::new().name("mp-restored-worker".into()).spawn(move || {
            for job in rx {
                let outcome = exec(&job.req);
                // The connection that asked may be gone; its results are no longer wanted.
                let _ = job.reply.send((job.id, outcome));
            }
        })?;
        Ok(Worker { tx, _thread: thread })
    }

    /// A per-connection handle with its own result queue.
    pub fn handle(&self) -> WorkerHandle {
        let (reply, results) = channel();
        WorkerHandle { tx: self.tx.clone(), reply, results, failed: Vec::new() }
    }
}

pub struct WorkerHandle {
    tx: Sender<Job>,
    reply: Sender<(JobId, Outcome)>,
    results: Receiver<(JobId, Outcome)>,
    failed: Vec<(JobId, Outcome)>,
}

impl Backend for WorkerHandle {
    fn submit(&mut self, id: JobId, req: BackendRequest) {
        if self.tx.send(Job { id, req, reply: self.reply.clone() }).is_err() {
            self.failed.push((id, Err(BackendFailure::Transport("the worker thread is not running".into()))));
        }
    }

    fn poll(&mut self) -> Vec<(JobId, Outcome)> {
        let mut out = std::mem::take(&mut self.failed);
        out.extend(self.results.try_iter());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mercs2_https::testing::{client_for, serve_once, test_pki};
    use mercs2_mp_api::rest::ClientInfo;
    use mercs2_mp_api::{ErrorCode, UserId};
    use std::time::{Duration, Instant};

    fn session_req() -> BackendRequest {
        BackendRequest::CreateSession(CreateSession {
            username: "mattias".into(),
            password: "correct horse".into(),
            client: ClientInfo { build_sha256: "ab".repeat(32), asi_version: "0.1.0".into() },
        })
    }

    fn run(response: &[u8], req: BackendRequest) -> (Outcome, String) {
        let pki = test_pki();
        let (port, server) = serve_once(&pki, response.to_vec());
        let api = RestApi::new(client_for(&pki.ca_pem, "localhost", port), client_for(&pki.ca_pem, "localhost", port));
        let out = api.execute(&req);
        let (raw, _) = server.join().unwrap().unwrap();
        (out, String::from_utf8(raw).unwrap())
    }

    #[test]
    fn session_success_parses_and_sends_only_the_contract_fields() {
        let body = br#"{"token":"t0k","user_id":42,"display_name":"Mattias","expires_at":1800000000}"#;
        let resp = [format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(), body].concat();
        let (out, raw) = run(&resp, session_req());
        assert_eq!(
            out,
            Ok(BackendReply::SessionCreated(SessionCreated {
                token: "t0k".into(),
                user_id: UserId(42),
                display_name: "Mattias".into(),
                expires_at: 1_800_000_000
            }))
        );
        let json = &raw[raw.find("\r\n\r\n").unwrap() + 4..];
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"username":"mattias","password":"correct horse",
                "client":{"build_sha256":"ab".repeat(32),"asi_version":"0.1.0"}})
        );
    }

    #[test]
    fn account_create_sends_only_username_and_password() {
        let body = br#"{"user_id":7,"username":"newbie"}"#;
        let resp = [format!("HTTP/1.1 201 Created\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(), body].concat();
        let req = BackendRequest::CreateAccount(CreateAccount { username: "newbie".into(), password: "longenough".into() });
        let (out, raw) = run(&resp, req);
        assert!(matches!(out, Ok(BackendReply::AccountCreated(AccountCreated { user_id: UserId(7), .. }))));
        assert!(raw.starts_with("POST /api/v1/accounts HTTP/1.1"));
        let json = &raw[raw.find("\r\n\r\n").unwrap() + 4..];
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(v, serde_json::json!({"username":"newbie","password":"longenough"}));
    }

    #[test]
    fn api_errors_and_unexpected_responses() {
        let body = br#"{"code":"bad_credentials","message":"nope"}"#;
        let resp = [format!("HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(), body].concat();
        let (out, _) = run(&resp, session_req());
        assert_eq!(out, Err(BackendFailure::Api(ApiError::new(ErrorCode::BadCredentials, "nope"))));

        let (out, _) = run(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 3\r\n\r\nbad", session_req());
        assert!(matches!(out, Err(BackendFailure::Transport(m)) if m.contains("unexpected HTTP 502")));

        let (out, _) = run(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", session_req());
        assert!(matches!(out, Err(BackendFailure::Transport(m)) if m.contains("not the expected JSON")));
    }

    fn ok_json(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }

    fn push(board: &str, score: u32) -> BackendRequest {
        BackendRequest::LeaderboardPush { board: board.as_bytes().to_vec(), score, token: Bearer("t0k".into()) }
    }

    fn me(board: &str) -> BackendRequest {
        BackendRequest::LeaderboardMe { board: board.as_bytes().to_vec(), token: Bearer("t0k".into()) }
    }

    #[test]
    fn leaderboard_push_puts_the_score_with_the_bearer_token() {
        let (out, raw) = run(&ok_json(r#"{"rank":4,"score":200000}"#), push("DlcCon004", 123456));
        assert_eq!(out, Ok(BackendReply::LeaderboardEntry(LeaderboardEntry { rank: 4, score: 200000 })));
        assert!(raw.starts_with("PUT /api/v1/leaderboards/DlcCon004/score HTTP/1.1\r\n"), "{raw}");
        assert!(raw.contains("\r\nAuthorization: Bearer t0k\r\n"), "{raw}");
        let json = &raw[raw.find("\r\n\r\n").unwrap() + 4..];
        assert_eq!(serde_json::from_str::<serde_json::Value>(json).unwrap(), serde_json::json!({"score": 123456}));
    }

    #[test]
    fn leaderboard_me_gets_the_standing_without_a_body() {
        let (out, raw) = run(&ok_json(r#"{"rank":0,"score":0}"#), me("DlcCon001"));
        assert_eq!(out, Ok(BackendReply::LeaderboardEntry(LeaderboardEntry { rank: 0, score: 0 })));
        assert!(raw.starts_with("GET /api/v1/leaderboards/DlcCon001/me HTTP/1.1\r\n"), "{raw}");
        assert!(raw.contains("\r\nAuthorization: Bearer t0k\r\n"), "{raw}");
        assert!(raw.ends_with("\r\n\r\n") && !raw.contains("Content-Length"), "{raw}");
    }

    #[test]
    fn leaderboard_refusals_are_api_errors() {
        for (status, code, req) in [
            ("401 Unauthorized", ErrorCode::Unauthorized, me("DlcCon001")),
            ("401 Unauthorized", ErrorCode::Unauthorized, push("DlcCon001", 1)),
            ("403 Forbidden", ErrorCode::Forbidden, push("DlcCon001", 1)),
            ("422 Unprocessable Entity", ErrorCode::InvalidField, push("Dlc-Con", 1)),
            ("422 Unprocessable Entity", ErrorCode::InvalidField, me("Dlc-Con")),
        ] {
            let body = serde_json::to_string(&ApiError::new(code, "refused")).unwrap();
            let resp = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}", body.len());
            let (out, _) = run(resp.as_bytes(), req.clone());
            assert_eq!(out, Err(BackendFailure::Api(ApiError::new(code, "refused"))), "{status} {}", req.describe());
        }
    }

    #[test]
    fn leaderboard_routes_against_the_real_server() {
        let srv = crate::testserver::TestServer::start();
        let rest = srv.rest();
        let who = srv.login("BoardPlayer");
        let token = || Bearer(who.token.clone());
        let me = |board: &str| BackendRequest::LeaderboardMe { board: board.as_bytes().to_vec(), token: token() };
        let push = |board: &str, score| BackendRequest::LeaderboardPush { board: board.as_bytes().to_vec(), score, token: token() };
        let entry = |rank, score| Ok(BackendReply::LeaderboardEntry(LeaderboardEntry { rank, score }));
        assert_eq!(rest.execute(&me("DlcCon001")), entry(0, 0), "no entry yet");
        assert_eq!(rest.execute(&push("DlcCon001", 500)), entry(1, 500));
        assert_eq!(rest.execute(&push("DlcCon001", 100)), entry(1, 500), "a lower push keeps the best");
        assert_eq!(rest.execute(&me("DlcCon001")), entry(1, 500));
        let code = |o: Outcome| match o {
            Err(BackendFailure::Api(e)) => e.code,
            other => panic!("expected an ApiError, got {other:?}"),
        };
        assert_eq!(code(rest.execute(&push("Dlc-Con", 1))), ErrorCode::InvalidField);
        assert_eq!(code(rest.execute(&push("DlcCon001", 1_000_000_001))), ErrorCode::InvalidField);
        let stale = BackendRequest::LeaderboardMe { board: b"DlcCon001".to_vec(), token: Bearer("not-a-token".into()) };
        assert_eq!(code(rest.execute(&stale)), ErrorCode::Unauthorized);
        let db_path = srv.db_path.clone();
        let user = who.user_id;
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
            let db = mercs2_mp_server::db::Db::open(&db_path).await.unwrap();
            assert!(db.ban_from_leaderboards(user, "test", 1).await.unwrap());
        });
        assert_eq!(code(rest.execute(&push("DlcCon001", 600))), ErrorCode::Forbidden);
    }

    #[test]
    fn a_leaderboard_request_never_formats_its_token() {
        for req in [push("DlcCon001", 5), me("DlcCon001")] {
            assert!(!format!("{req:?}").contains("t0k") && !req.describe().contains("t0k"), "{req:?}");
        }
        assert_eq!(push("a/b c", 1).describe(), "PUT /v1/leaderboards/a%2Fb%20c/score (score 1)");
    }

    #[test]
    fn worker_runs_off_thread_and_routes_results_per_handle() {
        let caller = std::thread::current().id();
        let w = Worker::spawn(move |req| {
            assert_ne!(std::thread::current().id(), caller);
            Err(BackendFailure::Transport(req.describe()))
        })
        .unwrap();
        let mut a = w.handle();
        let mut b = w.handle();
        a.submit(1, session_req());
        b.submit(9, session_req());
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut ra, mut rb) = (Vec::new(), Vec::new());
        while (ra.is_empty() || rb.is_empty()) && Instant::now() < deadline {
            ra.extend(a.poll());
            rb.extend(b.poll());
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(ra.len(), 1);
        assert_eq!(ra[0].0, 1);
        assert_eq!(rb[0].0, 9);
        assert!(matches!(&ra[0].1, Err(BackendFailure::Transport(m)) if m.contains("/v1/sessions")));
    }
}
