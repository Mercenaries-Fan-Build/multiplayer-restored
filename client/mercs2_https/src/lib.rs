//! `mercs2_https` — the HTTPS client the Mercenaries 2 ASIs share, so every one of them talks to a server
//! under the same trust policy.
//!
//! * [`tls`]: the policy (OpenSSL 3, statically linked; TLS ≥ 1.2 with AEAD suites only; chain verification
//!   against only the embedded Mozilla CA bundle; hostname verification against the subjectAltName only).
//! * [`url`]: [`BaseUrl`], the `https://host[:port][/prefix]` a server is reached at.
//! * [`http`]: [`HttpsClient`], one blocking request per connection within the caller's [`Limits`] (connect,
//!   I/O and whole-request timeouts, response body cap), meant to run on a worker thread, never on the game
//!   thread.
//! * `testing` (feature `testing`): a throwaway CA and a one-shot local TLS server for consumers' tests.
//!
//! ```no_run
//! use std::time::Duration;
//! use mercs2_https::{BaseUrl, HttpsClient, Limits, Method, tls};
//!
//! let base = BaseUrl::parse("https://mp.example.org/api").unwrap();
//! let limits = Limits {
//!     connect_timeout: Duration::from_secs(10),
//!     io_timeout: Duration::from_secs(15),
//!     request_timeout: Duration::from_secs(30),
//!     max_body: 64 * 1024,
//! };
//! let client = HttpsClient::new(tls::mozilla_connector().unwrap(), base, limits, "my_mod/1.0.0").unwrap();
//! let token = "…";
//! let auth = format!("Bearer {token}");
//! let resp = client
//!     .request(Method::Post, "/v1/scores", &[("Authorization", auth.as_str())], Some(br#"{"score":1}"#))
//!     .unwrap();
//! println!("HTTP {}: {} bytes", resp.status, resp.body.len());
//! ```

pub mod http;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod tls;
pub mod url;

pub use http::{HttpError, HttpsClient, Limits, Method, Response};
pub use url::BaseUrl;
