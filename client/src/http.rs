//! Blocking HTTPS/1.1 JSON client for the server's REST endpoints. Runs only on the worker thread.
//!
//! One request per connection (`Connection: close`). Response framing: `Content-Length`, or
//! `Transfer-Encoding: chunked`, or (neither) read to a clean TLS close. Anything else is an error.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use openssl::ssl::SslConnector;
use thiserror::Error;

use crate::config::BaseUrl;

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub struct HttpsClient {
    connector: SslConnector,
    base: BaseUrl,
    connect_timeout: Duration,
    io_timeout: Duration,
    user_agent: String,
}

impl HttpsClient {
    pub fn new(connector: SslConnector, base: BaseUrl, connect_timeout: Duration, io_timeout: Duration) -> Self {
        HttpsClient {
            connector,
            base,
            connect_timeout,
            io_timeout,
            user_agent: format!("multiplayer_restored/{}", crate::ASI_VERSION),
        }
    }

    pub fn base(&self) -> &BaseUrl {
        &self.base
    }

    /// `POST <base prefix><route>` with a JSON body.
    pub fn post_json(&self, route: &str, json: &[u8]) -> Result<Response, HttpError> {
        let host = &self.base.host;
        let tcp = connect_tcp(&self.base, self.connect_timeout, self.io_timeout)?;
        let mut tls = self
            .connector
            .connect(host, tcp)
            .map_err(|e| HttpError::Tls { host: host.clone(), msg: e.to_string() })?;
        let host_header =
            if self.base.port == 443 { host.clone() } else { format!("{host}:{}", self.base.port) };
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {}\r\nAccept: application/json\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.base.path(route),
            self.user_agent,
            json.len()
        );
        let io = |e: std::io::Error| HttpError::Io { host: host.clone(), msg: e.to_string() };
        tls.write_all(head.as_bytes()).map_err(io)?;
        tls.write_all(json).map_err(io)?;
        tls.flush().map_err(io)?;
        read_response(&mut tls, host)
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
pub(crate) mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::ssl::{SslAcceptor, SslMethod};
    use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
    use openssl::x509::{X509, X509NameBuilder};
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

    pub struct TestPki {
        pub ca_pem: Vec<u8>,
        pub leaf_cert: X509,
        pub leaf_key: PKey<Private>,
    }

    fn name(cn: &str) -> openssl::x509::X509Name {
        let mut n = X509NameBuilder::new().unwrap();
        n.append_entry_by_text("CN", cn).unwrap();
        n.build()
    }

    /// A CA and a leaf for `localhost` (DNS SAN), signed by that CA.
    pub fn test_pki() -> TestPki {
        let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut ca = X509::builder().unwrap();
        ca.set_version(2).unwrap();
        ca.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap()).unwrap();
        ca.set_subject_name(&name("mr-test-ca")).unwrap();
        ca.set_issuer_name(&name("mr-test-ca")).unwrap();
        ca.set_pubkey(&ca_key).unwrap();
        ca.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        ca.set_not_after(&Asn1Time::days_from_now(2).unwrap()).unwrap();
        ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
        ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let ca = ca.build();

        let leaf_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut leaf = X509::builder().unwrap();
        leaf.set_version(2).unwrap();
        leaf.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap()).unwrap();
        leaf.set_subject_name(&name("localhost")).unwrap();
        leaf.set_issuer_name(ca.subject_name()).unwrap();
        leaf.set_pubkey(&leaf_key).unwrap();
        leaf.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        leaf.set_not_after(&Asn1Time::days_from_now(2).unwrap()).unwrap();
        let san = SubjectAlternativeName::new().dns("localhost").build(&leaf.x509v3_context(Some(&ca), None)).unwrap();
        leaf.append_extension(san).unwrap();
        leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
        TestPki { ca_pem: ca.to_pem().unwrap(), leaf_cert: leaf.build(), leaf_key }
    }

    /// What the test server saw: the raw request and the negotiated TLS version.
    pub type Served = std::thread::JoinHandle<Result<(Vec<u8>, String), String>>;

    /// Serve one connection: read the request head + body, check it, answer with `response`.
    /// Returns the port and a handle yielding (request bytes, negotiated TLS version).
    pub fn serve_once(
        pki: &TestPki,
        response: Vec<u8>,
    ) -> (u16, Served) {
        let mut acc = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
        acc.set_certificate(&pki.leaf_cert).unwrap();
        acc.set_private_key(&pki.leaf_key).unwrap();
        let acc = acc.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().map_err(|e| e.to_string())?;
            let mut s = acc.accept(tcp).map_err(|e| e.to_string())?;
            let version = s.ssl().version_str().to_owned();
            let mut req = Vec::new();
            let mut b = [0u8; 4096];
            loop {
                let n = s.read(&mut b).map_err(|e| e.to_string())?;
                req.extend_from_slice(&b[..n]);
                if let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&req[..end]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map(|v| v.trim().parse().unwrap())
                        .unwrap_or(0);
                    if req.len() >= end + 4 + len {
                        break;
                    }
                }
                if n == 0 {
                    return Err("client closed early".into());
                }
            }
            s.write_all(&response).map_err(|e| e.to_string())?;
            s.shutdown().map_err(|e| e.to_string())?;
            Ok((req, version))
        });
        (port, h)
    }

    pub fn client_for(pki_pem: &[u8], host: &str, port: u16) -> HttpsClient {
        let base = BaseUrl { host: host.into(), port, prefix: "/api".into() };
        HttpsClient::new(
            crate::tls::connector(pki_pem).unwrap(),
            base,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
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
        );
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
