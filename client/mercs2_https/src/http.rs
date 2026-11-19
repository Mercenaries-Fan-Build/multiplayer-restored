//! Blocking HTTPS/1.1 JSON client for a server's REST endpoints. Once the host name has resolved (the system
//! resolver's own timeouts bound the lookup), a request blocks for at most its [`Limits::request_timeout`], so
//! run it on a worker thread, never on the game thread.
//!
//! One request per connection (`Connection: close`). Response framing: `Content-Length`, or
//! `Transfer-Encoding: chunked`, or (neither) read to a clean TLS close. Anything else is an error. The header
//! block may be at most [`MAX_HEAD`] bytes, a chunk-size line at most [`MAX_CHUNK_LINE`], and the body (after
//! chunked decoding) at most [`Limits::max_body`]; a response over any of them is an error.
//!
//! The client writes `Host`, `User-Agent`, `Accept: application/json`, `Connection: close` and, with a
//! body, `Content-Type: application/json` and `Content-Length` itself. A caller header with one of those
//! names, a header name that is not an RFC 9110 token, or a value with a control character is refused
//! before anything is sent. Error messages name a refused header but never print its value, so an
//! `Authorization` token never reaches a log.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use openssl::ssl::SslConnector;
use thiserror::Error;

use crate::url::BaseUrl;

/// Upper bound on a response's status line and header block: a policy bound, far above the few short headers a
/// JSON API response carries, with room for a reverse proxy's own.
pub const MAX_HEAD: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
/// Upper bound on one chunk-size line (the hex size and any chunk extensions, without its CRLF).
pub const MAX_CHUNK_LINE: usize = 256;
/// Significant hex digits in a chunk size: 16 hold any `u64`.
const MAX_CHUNK_SIZE_DIGITS: usize = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpError {
    #[error("cannot resolve {host}:{port}: {msg}")]
    Resolve { host: String, port: u16, msg: String },
    #[error("cannot connect to {host}:{port}: {msg}")]
    Connect { host: String, port: u16, msg: String },
    #[error("TLS handshake with {host} failed: {msg}")]
    Tls { host: String, msg: String },
    #[error("I/O with {host}: {msg}")]
    Io { host: String, msg: String },
    #[error("malformed HTTP response from {host}: {msg}")]
    Malformed { host: String, msg: String },
    /// The request was refused before anything was sent.
    #[error("invalid request: {msg}")]
    Request { msg: String },
    /// Connecting, the TLS handshake, sending and the whole response together took longer than
    /// [`Limits::request_timeout`].
    #[error("request to {host} did not finish within {} ms", after.as_millis())]
    Deadline { host: String, after: Duration },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

/// How long a request may take and how large its response may be. Every field is required and must be
/// non-zero; the client has no values of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Longest wait for one TCP connect (the resolved addresses are tried in turn).
    pub connect_timeout: Duration,
    /// Longest wait for any one read or write, the TLS handshake's included.
    pub io_timeout: Duration,
    /// The whole request: connecting, the TLS handshake, sending, and reading the full response.
    pub request_timeout: Duration,
    /// Largest response body accepted, in bytes, after chunked decoding. Size it from the largest response the
    /// server's API can send.
    pub max_body: usize,
}

impl Limits {
    fn check(&self) -> Result<(), HttpError> {
        for (name, d) in
            [("connect_timeout", self.connect_timeout), ("io_timeout", self.io_timeout), ("request_timeout", self.request_timeout)]
        {
            if d.is_zero() {
                return Err(HttpError::Request { msg: format!("{name} must be greater than zero") });
            }
        }
        if self.max_body == 0 {
            return Err(HttpError::Request { msg: "max_body must be greater than zero".into() });
        }
        Ok(())
    }
}

/// Headers the client writes itself (compared case-insensitively).
const OWN_HEADERS: [&str; 7] =
    ["host", "user-agent", "accept", "content-type", "content-length", "connection", "transfer-encoding"];

/// RFC 9110 `tchar`.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Visible ASCII, space and tab; no CR, LF, NUL or other control character.
fn is_field_value(v: &str) -> bool {
    v.bytes().all(|b| b == b'\t' || (0x20..0x7f).contains(&b))
}

fn check_header(name: &str, value: &str) -> Result<(), HttpError> {
    if name.is_empty() || !name.bytes().all(is_tchar) {
        return Err(HttpError::Request { msg: format!("header name {name:?} is not an HTTP token") });
    }
    if OWN_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name)) {
        return Err(HttpError::Request { msg: format!("header {name} is written by the client itself") });
    }
    if !is_field_value(value) {
        return Err(HttpError::Request {
            msg: format!("the value of header {name} contains a control or non-ASCII character"),
        });
    }
    Ok(())
}

/// A route is `/` followed by visible ASCII other than `#`.
fn check_route(route: &str) -> Result<(), HttpError> {
    if !route.starts_with('/') || !route.bytes().all(|b| (0x21..0x7f).contains(&b) && b != b'#') {
        return Err(HttpError::Request {
            msg: format!("route {route:?} must start with '/' and hold only visible ASCII other than '#'"),
        });
    }
    Ok(())
}

pub struct HttpsClient {
    connector: SslConnector,
    base: BaseUrl,
    limits: Limits,
    user_agent: String,
}

impl HttpsClient {
    /// A client for `base` within `limits`. `user_agent` (e.g. `"my_mod/1.2.0"`) is sent as `User-Agent` on
    /// every request; it must be a valid header value. `base` must pass [`BaseUrl::validate`].
    pub fn new(connector: SslConnector, base: BaseUrl, limits: Limits, user_agent: &str) -> Result<Self, HttpError> {
        if user_agent.is_empty() || !is_field_value(user_agent) {
            return Err(HttpError::Request { msg: format!("User-Agent {user_agent:?} is not a valid header value") });
        }
        base.validate().map_err(|msg| HttpError::Request { msg: format!("base URL: {msg}") })?;
        limits.check()?;
        Ok(HttpsClient { connector, base, limits, user_agent: user_agent.to_owned() })
    }

    pub fn base(&self) -> &BaseUrl {
        &self.base
    }

    /// `<method> <base prefix><route>` with the caller's `headers` (e.g. `("Authorization", "Bearer …")`)
    /// and, when `json` is given, that JSON body. Returns the status and the decoded body whatever the
    /// status is; deciding which statuses are success is the caller's.
    pub fn request(
        &self,
        method: Method,
        route: &str,
        headers: &[(&str, &str)],
        json: Option<&[u8]>,
    ) -> Result<Response, HttpError> {
        check_route(route)?;
        for (name, value) in headers {
            check_header(name, value)?;
        }
        let host = &self.base.host;
        let host_header =
            if self.base.port == 443 { host.clone() } else { format!("{host}:{}", self.base.port) };
        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {}\r\nAccept: application/json\r\n",
            method.as_str(),
            self.base.path(route),
            self.user_agent,
        );
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if let Some(body) = json {
            head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
        }
        head.push_str("Connection: close\r\n\r\n");

        let deadline = Instant::now() + self.limits.request_timeout;
        let expired = Arc::new(AtomicBool::new(false));
        match self.exchange(&head, json, deadline, &expired) {
            Err(_) if expired.load(Ordering::Relaxed) => {
                Err(HttpError::Deadline { host: host.clone(), after: self.limits.request_timeout })
            }
            other => other,
        }
    }

    fn exchange(
        &self,
        head: &str,
        json: Option<&[u8]>,
        deadline: Instant,
        expired: &Arc<AtomicBool>,
    ) -> Result<Response, HttpError> {
        let host = &self.base.host;
        let tcp = connect_until(&self.base, self.limits.connect_timeout, self.limits.io_timeout, Some((deadline, expired)))?;
        let stream = DeadlineStream::new(tcp, self.limits.io_timeout, deadline, expired.clone());
        let mut tls = crate::tls::connect(&self.connector, host, stream)
            .map_err(|e| HttpError::Tls { host: host.clone(), msg: e.to_string() })?;
        let io = |e: std::io::Error| HttpError::Io { host: host.clone(), msg: e.to_string() };
        tls.write_all(head.as_bytes()).map_err(io)?;
        if let Some(body) = json {
            tls.write_all(body).map_err(io)?;
        }
        tls.flush().map_err(io)?;
        read_response(&mut tls, host, self.limits.max_body)
    }

    /// `POST <base prefix><route>` with a JSON body and no extra headers.
    pub fn post_json(&self, route: &str, json: &[u8]) -> Result<Response, HttpError> {
        self.request(Method::Post, route, &[], Some(json))
    }
}

/// Resolve `base` and open a TCP connection to the first address that accepts, with blocking read/write
/// timeouts of `io_timeout` and Nagle off. Shared by the REST client and the lobby WebSocket. `base` must pass
/// [`BaseUrl::validate`].
pub fn connect_tcp(base: &BaseUrl, connect_timeout: Duration, io_timeout: Duration) -> Result<TcpStream, HttpError> {
    connect_until(base, connect_timeout, io_timeout, None)
}

/// [`connect_tcp`], with every connect attempt also bounded by `deadline` (which sets `expired` once it
/// has passed).
fn connect_until(
    base: &BaseUrl,
    connect_timeout: Duration,
    io_timeout: Duration,
    deadline: Option<(Instant, &AtomicBool)>,
) -> Result<TcpStream, HttpError> {
    base.validate().map_err(|msg| HttpError::Request { msg: format!("base URL: {msg}") })?;
    let (host, port) = (&base.host, base.port);
    let addrs: Vec<SocketAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| HttpError::Resolve { host: host.clone(), port, msg: e.to_string() })?
        .collect();
    if addrs.is_empty() {
        return Err(HttpError::Resolve { host: host.clone(), port, msg: "no addresses".into() });
    }
    let mut errors = Vec::new();
    for a in &addrs {
        let timeout = match deadline {
            None => connect_timeout,
            Some((at, expired)) => {
                let left = at.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    expired.store(true, Ordering::Relaxed);
                    errors.push(format!("{a}: request deadline passed"));
                    break;
                }
                connect_timeout.min(left)
            }
        };
        match TcpStream::connect_timeout(a, timeout) {
            Ok(s) => {
                let io = |e: std::io::Error| HttpError::Io { host: host.clone(), msg: e.to_string() };
                s.set_read_timeout(Some(io_timeout)).map_err(io)?;
                s.set_write_timeout(Some(io_timeout)).map_err(io)?;
                s.set_nodelay(true).map_err(io)?;
                return Ok(s);
            }
            Err(e) => errors.push(format!("{a}: {e}")),
        }
    }
    if let Some((at, expired)) = deadline
        && Instant::now() >= at
    {
        expired.store(true, Ordering::Relaxed);
    }
    Err(HttpError::Connect { host: host.clone(), port, msg: errors.join("; ") })
}

/// A TCP stream whose every read and write waits at most `io_timeout` and never past `deadline`. Each call
/// waits at most `min(io_timeout, time left)`, and the socket timeout is changed whenever that differs from
/// the one set, so slow reads (a server dribbling a byte at a time, the TLS handshake's included) cannot add up
/// past the deadline. Once the deadline has passed every call fails and `expired` is set.
#[derive(Debug)]
struct DeadlineStream {
    tcp: TcpStream,
    io_timeout: Duration,
    deadline: Instant,
    expired: Arc<AtomicBool>,
    /// The socket's read and write timeouts as last set.
    read_armed: Duration,
    write_armed: Duration,
}

impl DeadlineStream {
    /// `tcp` has both timeouts set to `io_timeout` ([`connect_until`]).
    fn new(tcp: TcpStream, io_timeout: Duration, deadline: Instant, expired: Arc<AtomicBool>) -> Self {
        DeadlineStream { tcp, io_timeout, deadline, expired, read_armed: io_timeout, write_armed: io_timeout }
    }

    fn passed(&self) -> io::Error {
        self.expired.store(true, Ordering::Relaxed);
        io::Error::new(io::ErrorKind::TimedOut, "request deadline passed")
    }

    /// How long the next call may wait.
    fn wait(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(self.passed());
        }
        Ok(left.min(self.io_timeout))
    }

    /// A blocking socket reports its timeout as `WouldBlock` (Unix) or `TimedOut` (Windows).
    fn timed_out(&self, e: io::Error, waited: Duration) -> io::Error {
        if !matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) {
            return e;
        }
        if Instant::now() >= self.deadline {
            return self.passed();
        }
        io::Error::new(io::ErrorKind::TimedOut, format!("nothing sent or received for {} ms", waited.as_millis()))
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let wait = self.wait()?;
        if wait != self.read_armed && rearm(self.tcp.set_read_timeout(Some(wait)))? {
            self.read_armed = wait;
        }
        self.tcp.read(buf).map_err(|e| self.timed_out(e, wait))
    }
}

/// Whether a changed socket timeout took effect. macOS refuses `setsockopt` with `EINVAL` once the connection is
/// shut down in both directions (shown by the test
/// `a_read_after_the_peer_closed_needs_its_timeout_changed_and_still_completes`): a read then returns at once
/// (data still buffered, or end of stream) and a write fails at once, so the call goes ahead with the old
/// timeout. Should `EINVAL` mean anything else, that one call still waits at most the old timeout, which is
/// never more than `io_timeout`. Every other error, std's own `InvalidInput` for a zero timeout included, is
/// returned.
fn rearm(set: io::Result<()>) -> io::Result<bool> {
    match set {
        Ok(()) => Ok(true),
        #[cfg(target_vendor = "apple")]
        Err(e) if e.raw_os_error() == Some(22) => Ok(false),
        Err(e) => Err(e),
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let wait = self.wait()?;
        if wait != self.write_armed && rearm(self.tcp.set_write_timeout(Some(wait)))? {
            self.write_armed = wait;
        }
        self.tcp.write(buf).map_err(|e| self.timed_out(e, wait))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

/// Read and frame one HTTP/1.1 response from `r`, accepting a body of at most `max_body` bytes.
pub fn read_response(r: &mut impl Read, host: &str, max_body: usize) -> Result<Response, HttpError> {
    let malformed = |msg: String| HttpError::Malformed { host: host.to_owned(), msg };
    let mut head: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    // Bytes of `head` already searched for the empty line that ends the headers.
    let mut searched = 0;
    // Headers. They are parsed only once the empty line has arrived, so each received byte is searched once.
    let (status, body_start, framing) = loop {
        if let Some(end) = end_of_head(&head, searched) {
            if end > MAX_HEAD {
                return Err(malformed(format!("response headers exceed {MAX_HEAD} bytes")));
            }
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(&head) {
                Ok(httparse::Status::Complete(n)) => {
                    let status = resp.code.ok_or_else(|| malformed("no status code".into()))?;
                    break (status, n, framing_of(resp.headers, max_body).map_err(malformed)?);
                }
                Ok(httparse::Status::Partial) => {}
                Err(e) => return Err(malformed(format!("bad header block: {e}"))),
            }
        }
        if head.len() > MAX_HEAD {
            return Err(malformed(format!("response headers exceed {MAX_HEAD} bytes")));
        }
        searched = head.len();
        let n = read_some(r, &mut chunk, host)?;
        if n == 0 {
            return Err(malformed("connection closed before the end of the headers".into()));
        }
        head.extend_from_slice(&chunk[..n]);
    };
    let rest = &head[body_start..];
    match framing {
        Framing::Length(n) => {
            let mut body = rest.to_vec();
            while body.len() < n {
                let k = read_some(r, &mut chunk, host)?;
                if k == 0 {
                    return Err(malformed(format!("body ended at {} of {n} bytes", body.len())));
                }
                body.extend_from_slice(&chunk[..k]);
            }
            if body.len() > n {
                return Err(malformed(format!("{} bytes after a {n}-byte body", body.len() - n)));
            }
            Ok(Response { status, body })
        }
        Framing::Chunked => {
            let mut decoder = Chunked::new(max_body);
            decoder.feed(rest).map_err(malformed)?;
            while !decoder.done() {
                let k = read_some(r, &mut chunk, host)?;
                if k == 0 {
                    return Err(malformed("connection closed inside a chunked body".into()));
                }
                decoder.feed(&chunk[..k]).map_err(malformed)?;
            }
            Ok(Response { status, body: decoder.out })
        }
        Framing::UntilClose => {
            let mut body = rest.to_vec();
            loop {
                if body.len() > max_body {
                    return Err(malformed(format!("body exceeds the {max_body}-byte cap")));
                }
                let k = read_some(r, &mut chunk, host)?;
                if k == 0 {
                    return Ok(Response { status, body });
                }
                body.extend_from_slice(&chunk[..k]);
            }
        }
    }
}

/// The length of the header block in `head` (through the empty line that ends it), searching only from
/// `searched` on (less the two bytes an `\r\n` or `\n` split across reads can need). HTTP/1.1 lines end in
/// CRLF; httparse also accepts a bare LF, and so does this.
fn end_of_head(head: &[u8], searched: usize) -> Option<usize> {
    let from = searched.saturating_sub(2);
    head[from..].iter().enumerate().find_map(|(k, &b)| {
        let i = from + k;
        if b != b'\n' {
            return None;
        }
        match head.get(i + 1..) {
            Some([b'\n', ..]) => Some(i + 2),
            Some([b'\r', b'\n', ..]) => Some(i + 3),
            _ => None,
        }
    })
}

#[derive(Debug, PartialEq, Eq)]
enum Framing {
    Length(usize),
    Chunked,
    UntilClose,
}

fn framing_of(headers: &[httparse::Header], max_body: usize) -> Result<Framing, String> {
    let mut length = None;
    let mut chunked = false;
    for h in headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            let v = std::str::from_utf8(h.value).map_err(|_| "non-ASCII Content-Length".to_string())?;
            let n: usize = v.trim().parse().map_err(|_| format!("Content-Length {v:?} is not a number"))?;
            if length.replace(n).is_some_and(|prev| prev != n) {
                return Err("conflicting Content-Length headers".into());
            }
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            let v = std::str::from_utf8(h.value).map_err(|_| "non-ASCII Transfer-Encoding".to_string())?;
            if v.trim().eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else {
                return Err(format!("unsupported Transfer-Encoding {v:?}"));
            }
        }
    }
    match (length, chunked) {
        (Some(_), true) => Err("both Content-Length and chunked".into()),
        (Some(n), false) if n > max_body => Err(format!("Content-Length {n} exceeds the {max_body}-byte body cap")),
        (Some(n), false) => Ok(Framing::Length(n)),
        (None, true) => Ok(Framing::Chunked),
        (None, false) => Ok(Framing::UntilClose),
    }
}

/// Read once into `chunk`; 0 is a clean end of stream.
fn read_some(r: &mut impl Read, chunk: &mut [u8], host: &str) -> Result<usize, HttpError> {
    r.read(chunk).map_err(|e| HttpError::Io { host: host.to_owned(), msg: e.to_string() })
}

/// A `Transfer-Encoding: chunked` body, decoded as it arrives: [`Chunked::feed`] is given only new bytes, looks
/// at each once, and copies chunk data once, so decoding is linear in the bytes received. Trailers are not
/// accepted.
struct Chunked {
    state: ChunkState,
    /// The chunk-size line being collected (with its CR, once that has arrived).
    line: Vec<u8>,
    out: Vec<u8>,
    max_body: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChunkState {
    /// Collecting a chunk-size line.
    Size,
    /// This many bytes of the current chunk's data are still to come.
    Data(usize),
    /// The CR, then the LF, after a chunk's data.
    DataCr,
    DataLf,
    /// After the zero-size last chunk: the CR, then the LF, of the empty line that ends the body.
    EndCr,
    EndLf,
    Done,
}

impl Chunked {
    fn new(max_body: usize) -> Self {
        Chunked { state: ChunkState::Size, line: Vec::new(), out: Vec::new(), max_body }
    }

    fn done(&self) -> bool {
        self.state == ChunkState::Done
    }

    fn feed(&mut self, mut b: &[u8]) -> Result<(), String> {
        while let Some(&c) = b.first() {
            match self.state {
                ChunkState::Size => {
                    b = &b[1..];
                    if c != b'\n' {
                        // The line plus its CR.
                        if self.line.len() > MAX_CHUNK_LINE {
                            return Err(format!("chunk-size line longer than {MAX_CHUNK_LINE} bytes"));
                        }
                        self.line.push(c);
                        continue;
                    }
                    let Some(line) = self.line.strip_suffix(b"\r") else {
                        return Err("chunk-size line not ended by CRLF".into());
                    };
                    let size = chunk_size(line)?;
                    let room = self.max_body - self.out.len();
                    if size > room as u64 {
                        return Err(format!(
                            "a {size}-byte chunk after {} body bytes exceeds the {}-byte body cap",
                            self.out.len(),
                            self.max_body
                        ));
                    }
                    self.line.clear();
                    // `size` <= `room`, a usize.
                    self.state = if size == 0 { ChunkState::EndCr } else { ChunkState::Data(size as usize) };
                }
                ChunkState::Data(left) => {
                    let n = left.min(b.len());
                    self.out.extend_from_slice(&b[..n]);
                    b = &b[n..];
                    self.state = if n == left { ChunkState::DataCr } else { ChunkState::Data(left - n) };
                }
                ChunkState::DataCr | ChunkState::DataLf => {
                    let (want, next) =
                        if self.state == ChunkState::DataCr { (b'\r', ChunkState::DataLf) } else { (b'\n', ChunkState::Size) };
                    if c != want {
                        return Err("chunk not followed by CRLF".into());
                    }
                    b = &b[1..];
                    self.state = next;
                }
                ChunkState::EndCr | ChunkState::EndLf => {
                    let (want, next) =
                        if self.state == ChunkState::EndCr { (b'\r', ChunkState::EndLf) } else { (b'\n', ChunkState::Done) };
                    if c != want {
                        return Err("chunk trailers are not supported".into());
                    }
                    b = &b[1..];
                    self.state = next;
                }
                ChunkState::Done => return Err("bytes after the final chunk".into()),
            }
        }
        Ok(())
    }
}

/// The size on a chunk-size line (`<hex>[;extensions]`, whitespace around the hex allowed): hex digits only,
/// at most 16 of them after leading zeros, so it always fits a `u64`.
fn chunk_size(line: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(line).map_err(|_| "non-ASCII chunk size".to_string())?;
    let digits = text.split(';').next().unwrap_or("").trim();
    let significant = digits.trim_start_matches('0');
    if digits.is_empty() || significant.len() > MAX_CHUNK_SIZE_DIGITS || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("bad chunk size {text:?}"));
    }
    if significant.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(significant, 16).map_err(|_| format!("bad chunk size {text:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        client_for, client_with, serve_once, serve_once_tuned, serve_with, test_limits, test_pki, test_pki_cn_only,
    };
    use openssl::ssl::SslVersion;
    use std::net::TcpListener;

    const CAP: usize = 1 << 20;

    fn read(raw: &[u8]) -> Result<Response, HttpError> {
        read_response(&mut &raw[..], "h", CAP)
    }

    /// A reader that returns one byte per call, as a server writing one byte per TLS record does.
    struct Dribble<'a>(&'a [u8]);

    impl Read for Dribble<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let Some((&first, rest)) = self.0.split_first() else { return Ok(0) };
            if buf.is_empty() {
                return Ok(0);
            }
            buf[0] = first;
            self.0 = rest;
            Ok(1)
        }
    }

    fn malformed_msg(r: Result<Response, HttpError>) -> String {
        match r {
            Err(HttpError::Malformed { msg, .. }) => msg,
            other => panic!("expected a Malformed error, got {other:?}"),
        }
    }

    #[test]
    fn content_length_response() {
        let raw = b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\nhello";
        let r = read(raw).unwrap();
        assert_eq!(r, Response { status: 201, body: b"hello".to_vec() });
    }

    #[test]
    fn chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n";
        assert_eq!(read(raw).unwrap().body, b"abcde");
    }

    #[test]
    fn until_close_response() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\n{}";
        assert_eq!(read(raw).unwrap().body, b"{}");
    }

    #[test]
    fn truncated_bodies_and_bad_framing_are_errors() {
        for raw in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nab",
            b"HTTP/1.1 200",
            b"garbage\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: 1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nextra",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\nabc\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+3\r\nabc\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\nabc\r\n0\r\n\r\n",
        ] {
            assert!(matches!(read(raw), Err(HttpError::Malformed { .. })), "{:?}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn chunk_sizes_that_overflow_or_exceed_the_body_cap_are_errors() {
        // Sizes that overflowed `i + size + 2` (usize::MAX on 64-bit hosts, u32::MAX on i686) or exceed the cap;
        // each must fail on its size line, before any data or more input is awaited.
        for size in ["ffffffffffffffff", "fffffffffffffffe", "ffffffff", "fffffffe", "100001", "10000000000000000"] {
            let raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size}\r\nXYZ");
            let msg = malformed_msg(read(raw.as_bytes()));
            assert!(msg.contains("body cap") || msg.contains("bad chunk size"), "{size}: {msg}");
        }
        // Exactly the cap fits; one byte over across two chunks does not.
        let mut ok = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100000\r\n".to_vec();
        ok.extend(vec![b'a'; CAP]);
        ok.extend(b"\r\n0\r\n\r\n");
        assert_eq!(read(&ok).unwrap().body.len(), CAP);
        let mut over = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nfffff\r\n".to_vec();
        over.extend(vec![b'a'; CAP - 1]);
        over.extend(b"\r\n2\r\nbb\r\n0\r\n\r\n");
        assert!(malformed_msg(read(&over)).contains("exceeds the 1048576-byte body cap"));
        // Leading zeros do not count against the digit limit.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n00000000000000000003\r\nabc\r\n0\r\n\r\n";
        assert_eq!(read(raw).unwrap().body, b"abc");
    }

    #[test]
    fn an_overlong_chunk_size_line_is_an_error() {
        let raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;{}\r\nq\r\n0\r\n\r\n", "x".repeat(300));
        assert!(malformed_msg(read(raw.as_bytes())).contains("chunk-size line longer than 256 bytes"));
        let raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;{}\r\nq\r\n0\r\n\r\n", "x".repeat(250));
        assert_eq!(read(raw.as_bytes()).unwrap().body, b"q");
    }

    #[test]
    fn decoding_byte_by_byte_gives_the_same_result() {
        for raw in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n"[..],
            b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\nhello",
            b"HTTP/1.1 200 OK\nContent-Length: 2\n\n{}",
            b"HTTP/1.1 200 OK\r\n\r\n{}",
        ] {
            assert_eq!(read_response(&mut Dribble(raw), "h", CAP), read(raw), "{:?}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn chunked_decoding_is_linear() {
        // 200000 one-byte chunks, one byte per read: the quadratic decoder took minutes on this.
        let n = 200_000;
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..n {
            raw.extend_from_slice(b"1\r\nq\r\n");
        }
        raw.extend_from_slice(b"0\r\n\r\n");
        let start = Instant::now();
        let r = read_response(&mut Dribble(&raw), "h", CAP).unwrap();
        let took = start.elapsed();
        assert_eq!(r.body.len(), n);
        assert!(took < Duration::from_secs(5), "{n} one-byte chunks took {took:?}");
    }

    #[test]
    fn bodies_and_headers_over_their_caps_are_errors() {
        let small = |raw: &[u8]| malformed_msg(read_response(&mut &raw[..], "h", 4));
        assert!(small(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").contains("Content-Length 5 exceeds the 4-byte body cap"));
        assert!(small(b"HTTP/1.1 200 OK\r\n\r\nhello").contains("body exceeds the 4-byte cap"));
        assert!(small(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").contains("body cap"));
        assert_eq!(read_response(&mut &b"HTTP/1.1 200 OK\r\n\r\nhell"[..], "h", 4).unwrap().body, b"hell");

        let big = format!("HTTP/1.1 200 OK\r\nX-Big: {}\r\nContent-Length: 0\r\n\r\n", "b".repeat(MAX_HEAD));
        assert!(malformed_msg(read(big.as_bytes())).contains("response headers exceed 16384 bytes"));
        let endless = format!("HTTP/1.1 200 OK\r\nX-Big: {}", "b".repeat(4 * MAX_HEAD));
        assert!(malformed_msg(read(endless.as_bytes())).contains("response headers exceed 16384 bytes"));
    }

    // ---- live TLS tests against a local OpenSSL server with a throwaway CA ----

    #[test]
    fn get_with_authorization_sends_no_body_headers() {
        let pki = test_pki();
        let body = br#"{"rows":[]}"#;
        let resp = [format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(), body].concat();
        let (port, server) = serve_once(&pki, resp);
        let c = client_for(&pki.ca_pem, "localhost", port);
        let r = c.request(Method::Get, "/v1/board?x=1", &[("Authorization", "Bearer t0k")], None).unwrap();
        assert_eq!(r, Response { status: 200, body: body.to_vec() });
        let (req, _) = server.join().unwrap().unwrap();
        let req = String::from_utf8(req).unwrap();
        assert_eq!(
            req,
            format!(
                "GET /api/v1/board?x=1 HTTP/1.1\r\nHost: localhost:{port}\r\nUser-Agent: mercs2_https-test/0\r\n\
                 Accept: application/json\r\nAuthorization: Bearer t0k\r\nConnection: close\r\n\r\n"
            )
        );
    }

    #[test]
    fn put_with_headers_and_json_body() {
        let pki = test_pki();
        let (port, server) = serve_once(&pki, b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec());
        let c = client_for(&pki.ca_pem, "localhost", port);
        let r = c
            .request(Method::Put, "/v1/x", &[("Authorization", "Bearer a"), ("X-Run", "7")], Some(b"{\"s\":1}"))
            .unwrap();
        assert_eq!(r, Response { status: 204, body: Vec::new() });
        let req = String::from_utf8(server.join().unwrap().unwrap().0).unwrap();
        assert!(req.starts_with("PUT /api/v1/x HTTP/1.1\r\n"), "{req}");
        assert!(
            req.ends_with(
                "Authorization: Bearer a\r\nX-Run: 7\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\
                 Connection: close\r\n\r\n{\"s\":1}"
            ),
            "{req}"
        );
    }

    #[test]
    fn bad_requests_are_refused_before_connecting_and_never_echo_values() {
        // Nothing listens on this port: a refusal that tried to connect would be a Connect error instead.
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let c = client_for(&test_pki().ca_pem, "127.0.0.1", port);
        let secret = "Bearer s3cret";
        for (route, headers) in [
            ("/x", vec![("Authorization", "Bearer a\r\nX-Evil: 1")]),
            ("/x", vec![("Authorization", "Bearer s3cret\0")]),
            ("/x", vec![("Bad Name", secret)]),
            ("/x", vec![("", secret)]),
            ("/x", vec![("Host", secret)]),
            ("/x", vec![("content-length", secret)]),
            ("/x", vec![("Transfer-Encoding", secret)]),
            ("/x", vec![("Connection", secret)]),
            ("/x", vec![("User-Agent", secret)]),
            ("/x", vec![("Content-Type", secret)]),
            ("/x", vec![("Accept", secret)]),
            ("x", vec![]),
            ("/a b", vec![]),
            ("/a\r\nb", vec![]),
            ("/a#f", vec![]),
        ] {
            let e = c.request(Method::Post, route, &headers, Some(b"{}")).unwrap_err();
            assert!(matches!(e, HttpError::Request { .. }), "{route:?} {headers:?}: {e}");
            assert!(!e.to_string().contains("s3cret"), "{e}");
        }
    }

    #[test]
    fn user_agent_must_be_a_header_value() {
        let connector = || crate::tls::connector(&test_pki().ca_pem).unwrap();
        let base = BaseUrl { host: "localhost".into(), port: 443, prefix: String::new() };
        for bad in ["", "a\r\nb", "x\0"] {
            assert!(matches!(
                HttpsClient::new(connector(), base.clone(), test_limits(), bad),
                Err(HttpError::Request { .. })
            ));
        }
    }

    #[test]
    fn an_invalid_base_url_or_zero_limit_is_refused() {
        let connector = || crate::tls::connector(&test_pki().ca_pem).unwrap();
        let injected = BaseUrl { host: "localhost".into(), port: 443, prefix: "/api\r\nX-Injected: 1\r\nX-Tail:".into() };
        let e = HttpsClient::new(connector(), injected.clone(), test_limits(), "t/0").err().unwrap();
        assert!(matches!(&e, HttpError::Request { msg } if msg.starts_with("base URL: path prefix")), "{e}");
        let e = connect_tcp(&injected, Duration::from_secs(1), Duration::from_secs(1)).unwrap_err();
        assert!(matches!(&e, HttpError::Request { msg } if msg.starts_with("base URL: path prefix")), "{e}");

        let base = BaseUrl { host: "localhost".into(), port: 443, prefix: String::new() };
        let l = test_limits();
        for (limits, name) in [
            (Limits { connect_timeout: Duration::ZERO, ..l }, "connect_timeout"),
            (Limits { io_timeout: Duration::ZERO, ..l }, "io_timeout"),
            (Limits { request_timeout: Duration::ZERO, ..l }, "request_timeout"),
            (Limits { max_body: 0, ..l }, "max_body"),
        ] {
            let e = HttpsClient::new(connector(), base.clone(), limits, "t/0").err().unwrap();
            assert!(matches!(&e, HttpError::Request { msg } if msg.starts_with(name)), "{e}");
        }
    }

    #[test]
    fn https_post_round_trip_with_tls13_and_verified_hostname() {
        let pki = test_pki();
        let (port, server) = serve_once(&pki, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec());
        let c = client_for(&pki.ca_pem, "localhost", port);
        let r = c.post_json("/v1/sessions", br#"{"a":1}"#).unwrap();
        assert_eq!(r, Response { status: 200, body: b"{}".to_vec() });
        let (req, version) = server.join().unwrap().unwrap();
        let req = String::from_utf8(req).unwrap();
        assert!(req.starts_with("POST /api/v1/sessions HTTP/1.1\r\n"), "{req}");
        assert!(req.contains(&format!("\r\nHost: localhost:{port}\r\n")), "{req}");
        assert!(req.ends_with("\r\n\r\n{\"a\":1}"), "{req}");
        assert_eq!(version, "TLSv1.3");
    }

    #[test]
    fn hostname_mismatch_is_refused() {
        let pki = test_pki();
        let (port, server) = serve_once(&pki, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
        // Connect by IP: the certificate names only `localhost`.
        let c = client_for(&pki.ca_pem, "127.0.0.1", port);
        let e = c.post_json("/v1/sessions", b"{}").unwrap_err();
        assert!(matches!(&e, HttpError::Tls { msg, .. } if msg.contains("certificate verify failed")), "{e}");
        assert!(server.join().unwrap().is_err());
    }

    #[test]
    fn a_name_only_in_the_subject_cn_is_refused() {
        // RFC 6125 §6.4.4: with no subjectAltName the certificate names no host, whatever its CN says.
        let pki = test_pki_cn_only();
        let (port, server) = serve_once(&pki, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
        let c = client_for(&pki.ca_pem, "localhost", port);
        let e = c.post_json("/v1/sessions", b"{}").unwrap_err();
        assert!(matches!(&e, HttpError::Tls { msg, .. } if msg.contains("certificate verify failed")), "{e}");
        assert!(server.join().unwrap().is_err());
    }

    #[test]
    fn tls12_cbc_suites_are_refused_and_aead_suites_accepted() {
        let tls12_only = |ciphers: &'static str| {
            move |acc: &mut openssl::ssl::SslAcceptorBuilder| {
                acc.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
                acc.set_cipher_list(ciphers).unwrap();
            }
        };
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec();
        for cbc in ["ECDHE-RSA-AES128-SHA", "AES128-SHA", "ECDHE-RSA-AES256-SHA384"] {
            let pki = test_pki();
            let (port, server) = serve_once_tuned(&pki, ok.clone(), tls12_only(cbc));
            let e = client_for(&pki.ca_pem, "localhost", port).post_json("/x", b"{}").unwrap_err();
            assert!(matches!(&e, HttpError::Tls { .. }), "{cbc}: {e}");
            assert!(server.join().unwrap().is_err(), "{cbc}");
        }
        for aead in ["ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-CHACHA20-POLY1305"] {
            let pki = test_pki();
            let (port, server) = serve_once_tuned(&pki, ok.clone(), tls12_only(aead));
            let r = client_for(&pki.ca_pem, "localhost", port).post_json("/x", b"{}");
            assert_eq!(r, Ok(Response { status: 200, body: b"{}".to_vec() }), "{aead}");
            assert_eq!(server.join().unwrap().unwrap().1, "TLSv1.2", "{aead}");
        }
    }

    #[test]
    fn unknown_ca_is_refused_by_the_mozilla_bundle() {
        let pki = test_pki();
        let (port, server) = serve_once(&pki, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
        let c = HttpsClient::new(
            crate::tls::mozilla_connector().unwrap(),
            BaseUrl { host: "localhost".into(), port, prefix: String::new() },
            test_limits(),
            "mercs2_https-test/0",
        )
        .unwrap();
        let e = c.post_json("/v1/sessions", b"{}").unwrap_err();
        assert!(matches!(&e, HttpError::Tls { msg, .. } if msg.contains("certificate verify failed")), "{e}");
        assert!(server.join().unwrap().is_err());
    }

    #[test]
    fn connection_refused_is_reported() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let c = client_for(&test_pki().ca_pem, "127.0.0.1", port);
        assert!(matches!(c.post_json("/x", b"{}"), Err(HttpError::Connect { .. })));
    }

    fn short_deadline() -> Limits {
        Limits { io_timeout: Duration::from_secs(2), request_timeout: Duration::from_millis(1500), ..test_limits() }
    }

    #[test]
    fn a_server_dribbling_its_headers_hits_the_request_deadline() {
        // One byte every 300 ms never trips the 2 s I/O timeout; the 1.5 s request deadline ends it.
        let pki = test_pki();
        let (port, server) = serve_with(&pki, |s| {
            for b in b"HTTP/1.1 200 OK\r\nX-Pad: pppppppppppppppppppppppppppp\r\nContent-Length: 0\r\n\r\n" {
                if s.write_all(&[*b]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        });
        let c = client_with(&pki.ca_pem, "localhost", port, short_deadline());
        let start = Instant::now();
        let e = c.request(Method::Get, "/x", &[], None).unwrap_err();
        let took = start.elapsed();
        assert_eq!(e, HttpError::Deadline { host: "localhost".into(), after: Duration::from_millis(1500) });
        assert!(took >= Duration::from_millis(1500) && took < Duration::from_millis(2500), "{took:?}");
        server.join().unwrap().unwrap();
    }

    #[test]
    fn a_server_dribbling_its_chunks_hits_the_request_deadline() {
        let pki = test_pki();
        let (port, server) = serve_with(&pki, |s| {
            if s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").is_err() {
                return;
            }
            for _ in 0..40 {
                if s.write_all(b"1\r\nq\r\n").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let c = client_with(&pki.ca_pem, "localhost", port, short_deadline());
        let start = Instant::now();
        let e = c.request(Method::Get, "/x", &[], None).unwrap_err();
        assert!(matches!(e, HttpError::Deadline { .. }), "{e}");
        assert!(start.elapsed() < Duration::from_millis(2500), "{:?}", start.elapsed());
        server.join().unwrap().unwrap();
    }

    #[test]
    fn a_silent_tls_handshake_hits_the_request_deadline() {
        // TCP accepts, TLS never answers: the handshake's reads are bounded by the deadline, not the 2 s I/O timeout.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            std::thread::sleep(Duration::from_millis(2000));
            drop(s);
        });
        let limits = Limits { request_timeout: Duration::from_millis(500), ..short_deadline() };
        let c = client_with(&test_pki().ca_pem, "localhost", port, limits);
        let start = Instant::now();
        let e = c.post_json("/x", b"{}").unwrap_err();
        let took = start.elapsed();
        assert_eq!(e, HttpError::Deadline { host: "localhost".into(), after: Duration::from_millis(500) });
        assert!(took < Duration::from_millis(1500), "{took:?}");
        server.join().unwrap();
    }

    #[test]
    fn a_read_after_the_peer_closed_needs_its_timeout_changed_and_still_completes() {
        // The deadline is nearer than the I/O timeout, so the read must change the socket timeout after the
        // connection is already shut down in both directions.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.write_all(b"x").unwrap();
        });
        let io_timeout = Duration::from_secs(5);
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(io_timeout)).unwrap();
        server.join().unwrap();
        tcp.shutdown(std::net::Shutdown::Write).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let expired = Arc::new(AtomicBool::new(false));
        let mut s = DeadlineStream::new(tcp, io_timeout, Instant::now() + Duration::from_secs(2), expired.clone());
        let mut buf = [0u8; 8];
        let start = Instant::now();
        assert_eq!(s.read(&mut buf).unwrap(), 1);
        assert_eq!(s.read(&mut buf).unwrap(), 0);
        // A write on the shut connection fails at once, and not with the refused timeout change.
        let e = s.write(b"y").unwrap_err();
        assert_ne!(e.raw_os_error(), Some(22), "{e}");
        assert!(start.elapsed() < Duration::from_millis(500), "{:?}", start.elapsed());
        assert!(!expired.load(Ordering::Relaxed));
    }

    #[test]
    fn a_silent_server_hits_the_io_timeout_with_a_clear_message() {
        let pki = test_pki();
        let (port, server) = serve_with(&pki, |s| {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n{");
            std::thread::sleep(Duration::from_millis(1500));
        });
        let limits = Limits { io_timeout: Duration::from_millis(500), ..test_limits() };
        let c = client_with(&pki.ca_pem, "localhost", port, limits);
        let e = c.request(Method::Get, "/x", &[], None).unwrap_err();
        assert!(matches!(&e, HttpError::Io { msg, .. } if msg.contains("nothing sent or received for 500 ms")), "{e}");
        server.join().unwrap().unwrap();
    }
}
