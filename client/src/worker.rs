//! Backend requests run off the game thread.
//!
//! The FESL adapter (on the game thread, inside ProtoSSL Update/Recv) submits a [`BackendRequest`] and
//! later polls for its [`Outcome`]; a single worker thread executes requests in order with the blocking
//! [`HttpsClient`]. The adapter is generic over [`Backend`] so tests can drive it without a network.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use mercs2_mp_api::ApiError;
use mercs2_mp_api::rest::{AccountCreated, CreateAccount, CreateSession, SessionCreated};
use serde::de::DeserializeOwned;

use crate::http::HttpsClient;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendRequest {
    CreateAccount(CreateAccount),
    CreateSession(CreateSession),
}

impl BackendRequest {
    pub fn describe(&self) -> String {
        match self {
            BackendRequest::CreateAccount(c) => format!("POST /v1/accounts (username {:?})", c.username),
            BackendRequest::CreateSession(c) => format!("POST /v1/sessions (username {:?})", c.username),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendReply {
    AccountCreated(AccountCreated),
    SessionCreated(SessionCreated),
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

/// Typed REST calls on top of [`HttpsClient`].
pub struct RestApi {
    http: HttpsClient,
}

impl RestApi {
    pub fn new(http: HttpsClient) -> Self {
        RestApi { http }
    }

    fn call<T: DeserializeOwned>(&self, route: &str, body: &impl serde::Serialize, expect: u16) -> Result<T, BackendFailure> {
        let json = serde_json::to_vec(body).map_err(|e| BackendFailure::Transport(format!("encode {route}: {e}")))?;
        let resp = self.http.post_json(route, &json).map_err(|e| BackendFailure::Transport(e.to_string()))?;
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
    use crate::http::tests::{client_for, serve_once, test_pki};
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
        let api = RestApi::new(client_for(&pki.ca_pem, "localhost", port));
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
