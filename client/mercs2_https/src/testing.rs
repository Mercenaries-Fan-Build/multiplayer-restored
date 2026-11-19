//! Test fixtures for this crate's tests and its consumers' tests: a throwaway CA with a `localhost` leaf, a
//! one-shot local TLS server, and a client that trusts only that CA. Nothing here is used at run time; a
//! release build that does not call it links none of it.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use std::net::TcpStream;

use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslStream};
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509, X509NameBuilder};

use crate::http::{HttpsClient, Limits};
use crate::url::BaseUrl;

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
    pki(true)
}

/// Like [`test_pki`], but the leaf names `localhost` only in its subject CN and has no subjectAltName.
pub fn test_pki_cn_only() -> TestPki {
    pki(false)
}

fn pki(san: bool) -> TestPki {
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
    if san {
        let san = SubjectAlternativeName::new().dns("localhost").build(&leaf.x509v3_context(Some(&ca), None)).unwrap();
        leaf.append_extension(san).unwrap();
    }
    leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
    TestPki { ca_pem: ca.to_pem().unwrap(), leaf_cert: leaf.build(), leaf_key }
}

/// What the test server saw: the raw request and the negotiated TLS version.
pub type Served = std::thread::JoinHandle<Result<(Vec<u8>, String), String>>;

/// Serve one connection: read the request head + body, check it, answer with `response`.
/// Returns the port and a handle yielding (request bytes, negotiated TLS version).
pub fn serve_once(pki: &TestPki, response: Vec<u8>) -> (u16, Served) {
    serve_once_tuned(pki, response, |_| {})
}

/// [`serve_once`] with the server's acceptor adjusted by `tune` first (e.g. its protocol versions or ciphers).
pub fn serve_once_tuned(pki: &TestPki, response: Vec<u8>, tune: impl FnOnce(&mut SslAcceptorBuilder)) -> (u16, Served) {
    let acc = acceptor(pki, tune);
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

/// Serve one connection: read the request head, then hand the stream to `behave` (which may answer slowly,
/// partially, or not at all). The handle ends when `behave` returns.
pub fn serve_with(
    pki: &TestPki,
    behave: impl FnOnce(&mut SslStream<TcpStream>) + Send + 'static,
) -> (u16, std::thread::JoinHandle<Result<(), String>>) {
    let acc = acceptor(pki, |_| {});
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().map_err(|e| e.to_string())?;
        let mut s = acc.accept(tcp).map_err(|e| e.to_string())?;
        let mut req = Vec::new();
        let mut b = [0u8; 4096];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut b).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("client closed early".into());
            }
            req.extend_from_slice(&b[..n]);
        }
        behave(&mut s);
        Ok(())
    });
    (port, h)
}

fn acceptor(pki: &TestPki, tune: impl FnOnce(&mut SslAcceptorBuilder)) -> SslAcceptor {
    let mut acc = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    acc.set_certificate(&pki.leaf_cert).unwrap();
    acc.set_private_key(&pki.leaf_key).unwrap();
    tune(&mut acc);
    acc.build()
}

/// 5-second connect and I/O timeouts, a 10-second request deadline, a 1 MiB body cap.
pub fn test_limits() -> Limits {
    Limits {
        connect_timeout: Duration::from_secs(5),
        io_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
        max_body: 1 << 20,
    }
}

/// A client for `https://<host>:<port>/api` that trusts only `pki_pem`, with [`test_limits`].
pub fn client_for(pki_pem: &[u8], host: &str, port: u16) -> HttpsClient {
    client_with(pki_pem, host, port, test_limits())
}

/// [`client_for`] with the caller's limits.
pub fn client_with(pki_pem: &[u8], host: &str, port: u16, limits: Limits) -> HttpsClient {
    let base = BaseUrl { host: host.into(), port, prefix: "/api".into() };
    HttpsClient::new(crate::tls::connector(pki_pem).unwrap(), base, limits, "mercs2_https-test/0").unwrap()
}
