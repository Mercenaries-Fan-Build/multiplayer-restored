//! TLS client configuration (OpenSSL 3, statically linked via the `openssl` crate's `vendored` feature).
//!
//! Policy: TLS 1.2 minimum (OpenSSL negotiates 1.3 when the server offers it), SNI, certificate chain
//! verification against **only** the embedded Mozilla CA bundle, and hostname verification (both done by
//! `SslConnector::connect`). The connector's default verify paths are replaced, not extended, so no
//! system or build-machine trust store is consulted.
//!
//! **CA bundle:** `ca/cacert.pem` is curl's extract of the Mozilla NSS root store
//! (<https://curl.se/docs/caextract.html>), "Certificate data from Mozilla as of
//! [`CA_BUNDLE_MOZILLA_DATE`]", SHA-256 [`CA_BUNDLE_SHA256`] (matches curl.se's published
//! `cacert.pem.sha256`, kept beside it). Refresh with `ca/refresh_cacert.sh`, then update both constants;
//! a test pins the embedded bytes to the recorded hash.

use openssl::error::ErrorStack;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;

pub const CA_BUNDLE: &[u8] = include_bytes!("../ca/cacert.pem");
pub const CA_BUNDLE_SHA256: &str = "a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505";
pub const CA_BUNDLE_MOZILLA_DATE: &str = "Fri Sep 25 03:12:01 2026 GMT";

/// Build a connector that trusts exactly the certificates in `roots_pem`.
pub fn connector(roots_pem: &[u8]) -> Result<SslConnector, ErrorStack> {
    let mut b = SslConnector::builder(SslMethod::tls_client())?;
    b.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    let mut store = X509StoreBuilder::new()?;
    for cert in X509::stack_from_pem(roots_pem)? {
        store.add_cert(cert)?;
    }
    b.set_cert_store(store.build());
    b.set_verify(SslVerifyMode::PEER);
    Ok(b.build())
}

/// The production connector: the embedded Mozilla bundle.
pub fn mozilla_connector() -> Result<SslConnector, ErrorStack> {
    connector(CA_BUNDLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_bundle_is_the_recorded_one() {
        assert_eq!(crate::build_id::sha256_hex(CA_BUNDLE), CA_BUNDLE_SHA256);
        let published = include_str!("../ca/cacert.pem.sha256");
        assert!(published.starts_with(CA_BUNDLE_SHA256), "{published}");
        let text = std::str::from_utf8(CA_BUNDLE).unwrap();
        assert!(text.contains(&format!("Certificate data from Mozilla as of: {CA_BUNDLE_MOZILLA_DATE}")));
    }

    #[test]
    fn bundle_loads_every_root() {
        let certs = X509::stack_from_pem(CA_BUNDLE).unwrap();
        let blocks = std::str::from_utf8(CA_BUNDLE).unwrap().matches("-----BEGIN CERTIFICATE-----").count();
        assert_eq!(certs.len(), blocks);
        assert!(certs.len() > 100);
        mozilla_connector().unwrap();
    }

    #[test]
    fn openssl_is_3x() {
        let v = openssl::version::number();
        assert_eq!(v >> 28, 3, "OpenSSL version number {v:#x} ({})", openssl::version::version());
    }
}
