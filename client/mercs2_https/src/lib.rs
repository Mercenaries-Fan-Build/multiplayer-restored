//! `mercs2_https` — the HTTPS client the Mercenaries 2 ASIs share, so every one of them talks to a server
//! under the same trust policy.
//!
//! * [`tls`]: the policy (OpenSSL 3, statically linked; TLS ≥ 1.2; chain verification against only the
//!   embedded Mozilla CA bundle; hostname verification).
//! * [`url`]: [`BaseUrl`], the `https://host[:port][/prefix]` a server is reached at.
//! * [`http`]: [`HttpsClient`], one blocking request per connection with connect and I/O timeouts, meant to
//!   run on a worker thread, never on the game thread.
//! * [`testing`]: a throwaway CA and a one-shot local TLS server for consumers' tests.
//!
//! ```no_run
//! use std::time::Duration;
//! use mercs2_https::{BaseUrl, HttpsClient, Method, tls};
//!
//! let base = BaseUrl::parse("https://mp.example.org/api").unwrap();
//! let client = HttpsClient::new(
//!     tls::mozilla_connector().unwrap(),
//!     base,
//!     Duration::from_secs(10),
//!     Duration::from_secs(15),
//!     "my_mod/1.0.0",
//! )
//! .unwrap();
//! let token = "…";
//! let auth = format!("Bearer {token}");
//! let resp = client
//!     .request(Method::Post, "/v1/scores", &[("Authorization", auth.as_str())], Some(br#"{"score":1}"#))
//!     .unwrap();
//! println!("HTTP {}: {} bytes", resp.status, resp.body.len());
//! ```

pub mod http;
pub mod testing;
pub mod tls;
pub mod url;

pub use http::{HttpError, HttpsClient, Method, Response};
pub use url::BaseUrl;
