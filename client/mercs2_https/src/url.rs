//! The address a server is reached at.

use std::fmt;

/// `https://host[:port][/prefix]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseUrl {
    pub host: String,
    pub port: u16,
    /// Path prefix without a trailing slash; empty for none.
    pub prefix: String,
}

impl BaseUrl {
    pub fn parse(s: &str) -> Result<Self, String> {
        let rest = s.strip_prefix("https://").ok_or("must start with https://")?;
        if rest.contains(['?', '#']) {
            return Err("must not contain a query or fragment".into());
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err("must not contain user info".into());
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| format!("port {p:?} is not a number 1-65535"))?),
            None => (authority, 443),
        };
        if port == 0 {
            return Err("port 0 is invalid".into());
        }
        if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
            return Err(format!("host {host:?} must be a DNS name or IPv4 address"));
        }
        let prefix = path.trim_end_matches('/').to_owned();
        Ok(BaseUrl { host: host.to_ascii_lowercase(), port, prefix })
    }

    /// The request target for an API route such as `/v1/sessions`.
    pub fn path(&self, route: &str) -> String {
        format!("{}{route}", self.prefix)
    }
}

/// The canonical spelling: `https://host[:port]prefix`, the port only when it is not 443, no trailing
/// slash. [`BaseUrl::parse`] of it gives back the same value.
impl fmt::Display for BaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == 443 {
            write!(f, "https://{}{}", self.host, self.prefix)
        } else {
            write!(f, "https://{}:{}{}", self.host, self.port, self.prefix)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_joins_routes() {
        let b = BaseUrl::parse("https://MP.example.org/api/").unwrap();
        assert_eq!(b, BaseUrl { host: "mp.example.org".into(), port: 443, prefix: "/api".into() });
        assert_eq!(b.path("/v1/sessions"), "/api/v1/sessions");
    }

    #[test]
    fn rejects_what_is_not_an_https_base() {
        for bad in [
            "http://mp.example.org",
            "https://mp.example.org:0",
            "https://mp.example.org:70000",
            "https://mp.example.org/?q=1",
            "https://mp.example.org/#f",
            "https://user@mp.example.org",
            "https://",
            "https://mp_example.org",
        ] {
            assert!(BaseUrl::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn display_is_canonical_and_round_trips() {
        for (text, shown) in [
            ("https://mp.example.org", "https://mp.example.org"),
            ("https://mp.example.org:443/", "https://mp.example.org"),
            ("https://MP.example.org:8443/api/", "https://mp.example.org:8443/api"),
            ("https://127.0.0.1:9/a/b", "https://127.0.0.1:9/a/b"),
        ] {
            let b = BaseUrl::parse(text).unwrap();
            assert_eq!(b.to_string(), shown);
            assert_eq!(BaseUrl::parse(&b.to_string()).unwrap(), b);
        }
    }
}
