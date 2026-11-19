//! Blocking HTTPS/1.1 JSON client for a server's REST endpoints. It blocks for up to the connect timeout plus
//! the I/O timeout per read or write, so run it on a worker thread, never on the game thread.
//!
//! One request per connection (`Connection: close`). Response framing: `Content-Length`, or
//! `Transfer-Encoding: chunked`, or (neither) read to a clean TLS close. Anything else is an error.
//!
//! The client writes `Host`, `User-Agent`, `Accept: application/json`, `Connection: close` and, with a
//! body, `Content-Type: application/json` and `Content-Length` itself. A caller header with one of those
//! names, a header name that is not an RFC 9110 token, or a value with a control character is refused
//! before anything is sent. Error messages name a refused header but never print its value, so an
//! `Authorization` token never reaches a log.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use openssl::ssl::SslConnector;
use thiserror::Error;

use crate::url::BaseUrl;

/// Upper bound on a response (headers + body). The API's bodies are a few hundred bytes.
const MAX_RESPONSE: usize = 1 << 20;
const MAX_HEADERS: usize = 64;

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
    connect_timeout: Duration,
    io_timeout: Duration,
    user_agent: String,
}

impl HttpsClient {
    /// A client for `base`. `user_agent` (e.g. `"my_mod/1.2.0"`) is sent as `User-Agent` on every request;
    /// it must be a valid header value.
    pub fn new(
        connector: SslConnector,
        base: BaseUrl,
        connect_timeout: Duration,
        io_timeout: Duration,
        user_agent: &str,
    ) -> Result<Self, HttpError> {
        if user_agent.is_empty() || !is_field_value(user_agent) {
            return Err(HttpError::Request { msg: format!("User-Agent {user_agent:?} is not a valid header value") });
        }
        Ok(HttpsClient { connector, base, connect_timeout, io_timeout, user_agent: user_agent.to_owned() })
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

        let tcp = connect_tcp(&self.base, self.connect_timeout, self.io_timeout)?;
        let mut tls = self
            .connector
            .connect(host, tcp)
            .map_err(|e| HttpError::Tls { host: host.clone(), msg: e.to_string() })?;
        let io = |e: std::io::Error| HttpError::Io { host: host.clone(), msg: e.to_string() };
        tls.write_all(head.as_bytes()).map_err(io)?;
        if let Some(body) = json {
            tls.write_all(body).map_err(io)?;
        }
        tls.flush().map_err(io)?;
        read_response(&mut tls, host)
    }

    /// `POST <base prefix><route>` with a JSON body and no extra headers.
    pub fn post_json(&self, route: &str, json: &[u8]) -> Result<Response, HttpError> {
        self.request(Method::Post, route, &[], Some(json))
    }
}

/// Resolve `base` and open a TCP connection to the first address that accepts, with blocking read/write
/// timeouts of `io_timeout` and Nagle off. Shared by the REST client and the lobby WebSocket.
pub fn connect_tcp(base: &BaseUrl, connect_timeout: Duration, io_timeout: Duration) -> Result<TcpStream, HttpError> {
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
        match TcpStream::connect_timeout(a, connect_timeout) {
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
    Err(HttpError::Connect { host: host.clone(), port, msg: errors.join("; ") })
}

/// Read and frame one HTTP/1.1 response from `r`.
pub fn read_response(r: &mut impl Read, host: &str) -> Result<Response, HttpError> {
    let malformed = |msg: String| HttpError::Malformed { host: host.to_owned(), msg };
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut eof = false;
    // Headers.
    let (status, body_start, framing) = loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&buf) {
            Ok(httparse::Status::Complete(n)) => {
                let status = resp.code.ok_or_else(|| malformed("no status code".into()))?;
                break (status, n, framing_of(resp.headers).map_err(malformed)?);
            }
            Ok(httparse::Status::Partial) => {}
            Err(e) => return Err(malformed(format!("bad header block: {e}"))),
        }
        if eof {
            return Err(malformed("connection closed before the end of the headers".into()));
        }
        eof = fill(r, &mut buf, &mut chunk, host)?;
    };
    let mut body = buf.split_off(body_start);
    match framing {
        Framing::Length(n) => {
            while body.len() < n {
                if fill(r, &mut body, &mut chunk, host)? {
                    return Err(malformed(format!("body ended at {} of {n} bytes", body.len())));
                }
            }
            if body.len() > n {
                return Err(malformed(format!("{} bytes after a {n}-byte body", body.len() - n)));
            }
            Ok(Response { status, body })
        }
        Framing::Chunked => loop {
            if let Some(decoded) = decode_chunked(&body).map_err(malformed)? {
                return Ok(Response { status, body: decoded });
            }
            if fill(r, &mut body, &mut chunk, host)? {
                return Err(malformed("connection closed inside a chunked body".into()));
            }
        },
        Framing::UntilClose => {
            while !fill(r, &mut body, &mut chunk, host)? {}
            Ok(Response { status, body })
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Framing {
    Length(usize),
    Chunked,
    UntilClose,
}

fn framing_of(headers: &[httparse::Header]) -> Result<Framing, String> {
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
        (Some(n), false) if n > MAX_RESPONSE => Err(format!("Content-Length {n} exceeds {MAX_RESPONSE}")),
        (Some(n), false) => Ok(Framing::Length(n)),
        (None, true) => Ok(Framing::Chunked),
        (None, false) => Ok(Framing::UntilClose),
    }
}

/// Read once into `buf`. Returns true on a clean end of stream.
fn fill(r: &mut impl Read, buf: &mut Vec<u8>, chunk: &mut [u8], host: &str) -> Result<bool, HttpError> {
    let n = r.read(chunk).map_err(|e| HttpError::Io { host: host.to_owned(), msg: e.to_string() })?;
    buf.extend_from_slice(&chunk[..n]);
    if buf.len() > MAX_RESPONSE {
        return Err(HttpError::Malformed { host: host.to_owned(), msg: format!("response exceeds {MAX_RESPONSE} bytes") });
    }
    Ok(n == 0)
}

/// Decode a complete chunked body, `Ok(None)` if more bytes are needed. Trailers are not accepted.
fn decode_chunked(b: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let Some(eol) = b[i..].windows(2).position(|w| w == b"\r\n") else { return Ok(None) };
        let line = std::str::from_utf8(&b[i..i + eol]).map_err(|_| "non-ASCII chunk size".to_string())?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| format!("bad chunk size {line:?}"))?;
        i += eol + 2;
        if size == 0 {
            return match b.get(i..i + 2) {
                None => Ok(None),
                Some(b"\r\n") if b.len() == i + 2 => Ok(Some(out)),
                Some(b"\r\n") => Err("bytes after the final chunk".into()),
                Some(_) => Err("chunk trailers are not supported".into()),
            };
        }
        if b.len() < i + size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&b[i..i + size]);
        if &b[i + size..i + size + 2] != b"\r\n" {
            return Err("chunk not followed by CRLF".into());
        }
        i += size + 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{client_for, serve_once, test_pki};
    use std::net::TcpListener;

    #[test]
    fn content_length_response() {
        let raw = b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\nhello";
        let r = read_response(&mut &raw[..], "h").unwrap();
        assert_eq!(r, Response { status: 201, body: b"hello".to_vec() });
    }

    #[test]
    fn chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n";
        assert_eq!(read_response(&mut &raw[..], "h").unwrap().body, b"abcde");
    }

    #[test]
    fn until_close_response() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\n{}";
        assert_eq!(read_response(&mut &raw[..], "h").unwrap().body, b"{}");
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
        ] {
            assert!(
                matches!(read_response(&mut &raw[..], "h"), Err(HttpError::Malformed { .. })),
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
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
        let t = Duration::from_secs(1);
        for bad in ["", "a\r\nb", "x\0"] {
            assert!(matches!(
                HttpsClient::new(connector(), base.clone(), t, t, bad),
                Err(HttpError::Request { .. })
            ));
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
    fn unknown_ca_is_refused_by_the_mozilla_bundle() {
        let pki = test_pki();
        let (port, server) = serve_once(&pki, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
        let c = HttpsClient::new(
            crate::tls::mozilla_connector().unwrap(),
            BaseUrl { host: "localhost".into(), port, prefix: String::new() },
            Duration::from_secs(5),
            Duration::from_secs(5),
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
}
