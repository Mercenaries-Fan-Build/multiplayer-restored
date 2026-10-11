//! `multiplayer_restored.ini` — strict parser. Every key is required, unknown sections/keys, duplicates and
//! malformed lines are errors. There are no defaults: the file shipped next to the ASI is the only source.
//!
//! ```ini
//! [server]
//! base_url = https://mp.example.org        ; https only; optional path prefix, no query/fragment
//!
//! [fesl]
//! intercept_names = fesl.ea.com           ; ProtoSSLConnect names that become the virtual FESL link
//! activity_timeout_secs = 240             ; sent in the Hello reply (activityTimeoutSecs)
//! keepalive_interval_secs = 60            ; fsys MemCheck push interval; must be < activity timeout
//!
//! [theater]
//! advertise_ip = 127.0.0.1                ; Hello theaterIp; the game connects back to this ip:port
//! advertise_port = 14300
//! activity_timeout_secs = 240             ; CONN reply activityTimeoutSecs
//! keepalive_interval_secs = 60            ; Theater PING push interval; must be < activity timeout
//! lobby_name = Online                     ; LDAT NAME of the one lobby the ASI presents
//!
//! [messenger]
//! advertise_ip = 127.0.0.1                ; Hello messengerIp; connects are refused by design
//! advertise_port = 13505
//!
//! [privacy]
//! room_key = none                         ; Dark Souls-style room key, or `none` for public games only
//!
//! [account]
//! terms_of_service = Play nice.           ; acct GetTos reply text
//! countries = US:United States|GB:United Kingdom  ; acct GetCountryList (ISO:description, '|'-separated)
//!
//! [http]
//! connect_timeout_ms = 10000              ; also used for the lobby WebSocket's TCP connect
//! io_timeout_ms = 15000                   ; also bounds the WebSocket's TLS + upgrade handshake
//!
//! [websocket]
//! poll_interval_ms = 10                   ; lobby WebSocket thread: how often it services its socket
//! idle_timeout_secs = 75                  ; no frame from the server for this long ends the online session
//!
//! [relay]
//! alias_base = 127.0.0.2                  ; peer in relay slot s appears to the game as alias_base + s
//! alias_tunnel_port = 10010               ; UDP port each alias serves ProtoTunnel on (not the game's own)
//! dtls_mtu = 1200                         ; DTLS path MTU towards the relay
//! handshake_timeout_ms = 10000            ; DTLS handshake with the relay must finish within this
//! poll_interval_ms = 50                   ; socket read timeout of the shim's threads (stop/keepalive tick)
//! close_grace_ms = 5000                   ; relay closed the association: wait this long for the lobby's reason
//!
//! [startup]
//! signature_wait_ms = 120000              ; bounded wait for the unpacked image's signatures
//!
//! [log]
//! file = multiplayer_restored.log         ; relative paths are relative to the ASI's directory
//! ```

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("line {line}: {msg}")]
    Syntax { line: usize, msg: String },
    #[error("line {line}: unknown section [{section}]")]
    UnknownSection { line: usize, section: String },
    #[error("line {line}: unknown key {key:?} in [{section}]")]
    UnknownKey { line: usize, section: String, key: String },
    #[error("line {line}: duplicate key {key:?} in [{section}]")]
    DuplicateKey { line: usize, section: String, key: String },
    #[error("line {line}: duplicate section [{section}]")]
    DuplicateSection { line: usize, section: String },
    #[error("missing required key {key:?} in [{section}]")]
    Missing { section: &'static str, key: &'static str },
    #[error("[{section}] {key}: {msg}")]
    Invalid { section: &'static str, key: &'static str, msg: String },
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: Ipv4Addr,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Country {
    pub iso_code: String,
    pub description: String,
}

/// `[relay]`: the local side of the relay shim (`crate::relay`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayConfig {
    pub alias_base: Ipv4Addr,
    pub alias_tunnel_port: u16,
    pub dtls_mtu: u32,
    pub handshake_timeout_ms: u32,
    pub poll_interval_ms: u32,
    pub close_grace_ms: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub server: BaseUrl,
    pub fesl_names: Vec<String>,
    pub activity_timeout_secs: u32,
    pub keepalive_interval_secs: u32,
    pub theater: Endpoint,
    pub theater_activity_timeout_secs: u32,
    pub theater_keepalive_interval_secs: u32,
    pub lobby_name: String,
    pub messenger: Endpoint,
    /// `None` = public games only; `Some(key)` = only games hosted with exactly this key.
    pub room_key: Option<String>,
    pub terms_of_service: String,
    pub countries: Vec<Country>,
    pub connect_timeout_ms: u32,
    pub io_timeout_ms: u32,
    pub ws_poll_interval_ms: u32,
    pub ws_idle_timeout_secs: u32,
    pub relay: RelayConfig,
    pub signature_wait_ms: u32,
    pub log_file: String,
}

const SCHEMA: &[(&str, &[&str])] = &[
    ("server", &["base_url"]),
    ("fesl", &["intercept_names", "activity_timeout_secs", "keepalive_interval_secs"]),
    ("theater", &["advertise_ip", "advertise_port", "activity_timeout_secs", "keepalive_interval_secs", "lobby_name"]),
    ("messenger", &["advertise_ip", "advertise_port"]),
    ("privacy", &["room_key"]),
    ("account", &["terms_of_service", "countries"]),
    ("http", &["connect_timeout_ms", "io_timeout_ms"]),
    ("websocket", &["poll_interval_ms", "idle_timeout_secs"]),
    ("relay", &["alias_base", "alias_tunnel_port", "dtls_mtu", "handshake_timeout_ms", "poll_interval_ms", "close_grace_ms"]),
    ("startup", &["signature_wait_ms"]),
    ("log", &["file"]),
];

type Raw = BTreeMap<(&'static str, &'static str), String>;

fn parse_raw(text: &str) -> Result<Raw, ConfigError> {
    let mut raw = Raw::new();
    let mut seen_sections: Vec<&str> = Vec::new();
    let mut current: Option<(&'static str, &'static [&'static str])> = None;
    for (i, line) in text.lines().enumerate() {
        let line_no = i + 1;
        let t = line.trim();
        if t.is_empty() || t.starts_with(';') || t.starts_with('#') {
            continue;
        }
        if let Some(inner) = t.strip_prefix('[') {
            let name = inner
                .strip_suffix(']')
                .ok_or_else(|| ConfigError::Syntax { line: line_no, msg: "section header without ']'".into() })?
                .trim();
            let (sec, keys) = SCHEMA
                .iter()
                .find(|(s, _)| *s == name)
                .ok_or_else(|| ConfigError::UnknownSection { line: line_no, section: name.to_owned() })?;
            if seen_sections.contains(sec) {
                return Err(ConfigError::DuplicateSection { line: line_no, section: name.to_owned() });
            }
            seen_sections.push(sec);
            current = Some((sec, keys));
            continue;
        }
        let (k, v) = t
            .split_once('=')
            .ok_or_else(|| ConfigError::Syntax { line: line_no, msg: format!("expected key = value, got {t:?}") })?;
        let (k, v) = (k.trim(), v.trim());
        let (sec, keys) =
            current.ok_or_else(|| ConfigError::Syntax { line: line_no, msg: format!("key {k:?} before any [section]") })?;
        let key = keys.iter().find(|x| **x == k).ok_or_else(|| ConfigError::UnknownKey {
            line: line_no,
            section: sec.to_owned(),
            key: k.to_owned(),
        })?;
        if raw.insert((sec, key), v.to_owned()).is_some() {
            return Err(ConfigError::DuplicateKey { line: line_no, section: sec.to_owned(), key: k.to_owned() });
        }
    }
    Ok(raw)
}

fn get<'a>(raw: &'a Raw, section: &'static str, key: &'static str) -> Result<&'a str, ConfigError> {
    match raw.get(&(section, key)) {
        Some(v) if !v.is_empty() => Ok(v),
        Some(_) => Err(ConfigError::Invalid { section, key, msg: "must not be empty".into() }),
        None => Err(ConfigError::Missing { section, key }),
    }
}

fn get_u32(raw: &Raw, section: &'static str, key: &'static str) -> Result<u32, ConfigError> {
    let v = get(raw, section, key)?;
    let n: u32 = v
        .parse()
        .map_err(|_| ConfigError::Invalid { section, key, msg: format!("{v:?} is not a non-negative integer") })?;
    if n == 0 {
        return Err(ConfigError::Invalid { section, key, msg: "must be greater than 0".into() });
    }
    Ok(n)
}

fn get_endpoint(raw: &Raw, section: &'static str) -> Result<Endpoint, ConfigError> {
    let ip_text = get(raw, section, "advertise_ip")?;
    let ip: Ipv4Addr = ip_text.parse().map_err(|_| ConfigError::Invalid {
        section,
        key: "advertise_ip",
        msg: format!("{ip_text:?} is not a dotted IPv4 address (the game parses %d.%d.%d.%d)"),
    })?;
    if !ip.is_loopback() {
        return Err(ConfigError::Invalid {
            section,
            key: "advertise_ip",
            msg: format!("{ip} is not a loopback address; the ASI serves this endpoint in-process"),
        });
    }
    let port = get_port(raw, section, "advertise_port")?;
    Ok(Endpoint { ip, port })
}

fn get_port(raw: &Raw, section: &'static str, key: &'static str) -> Result<u16, ConfigError> {
    let port = get_u32(raw, section, key)?;
    u16::try_from(port).map_err(|_| ConfigError::Invalid { section, key, msg: format!("{port} exceeds 65535") })
}

/// Keepalive below timeout, as both FESL and Theater require.
fn keepalive_pair(raw: &Raw, section: &'static str) -> Result<(u32, u32), ConfigError> {
    let timeout = get_u32(raw, section, "activity_timeout_secs")?;
    let keepalive = get_u32(raw, section, "keepalive_interval_secs")?;
    if keepalive >= timeout {
        return Err(ConfigError::Invalid {
            section,
            key: "keepalive_interval_secs",
            msg: format!("{keepalive} must be less than activity_timeout_secs ({timeout})"),
        });
    }
    Ok((timeout, keepalive))
}

fn get_relay(raw: &Raw) -> Result<RelayConfig, ConfigError> {
    let text = get(raw, "relay", "alias_base")?;
    let alias_base: Ipv4Addr = text.parse().map_err(|_| ConfigError::Invalid {
        section: "relay",
        key: "alias_base",
        msg: format!("{text:?} is not a dotted IPv4 address"),
    })?;
    if !alias_base.is_loopback() || alias_base == Ipv4Addr::LOCALHOST {
        return Err(ConfigError::Invalid {
            section: "relay",
            key: "alias_base",
            msg: format!("{alias_base} must be a loopback address other than 127.0.0.1 (the game's own address)"),
        });
    }
    Ok(RelayConfig {
        alias_base,
        alias_tunnel_port: get_port(raw, "relay", "alias_tunnel_port")?,
        dtls_mtu: get_u32(raw, "relay", "dtls_mtu")?,
        handshake_timeout_ms: get_u32(raw, "relay", "handshake_timeout_ms")?,
        poll_interval_ms: get_u32(raw, "relay", "poll_interval_ms")?,
        close_grace_ms: get_u32(raw, "relay", "close_grace_ms")?,
    })
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let raw = parse_raw(text)?;
        // Report every missing key up front in schema order (first one wins as the error).
        for (sec, keys) in SCHEMA {
            for key in *keys {
                get(&raw, sec, key)?;
            }
        }
        let server = BaseUrl::parse(get(&raw, "server", "base_url")?)
            .map_err(|msg| ConfigError::Invalid { section: "server", key: "base_url", msg })?;
        let fesl_names: Vec<String> =
            get(&raw, "fesl", "intercept_names")?.split(',').map(|s| s.trim().to_owned()).collect();
        if fesl_names.iter().any(|n| n.is_empty() || n.len() > 255 || n.contains(':')) {
            return Err(ConfigError::Invalid {
                section: "fesl",
                key: "intercept_names",
                msg: "comma-separated host names, each 1-255 characters, no ':port'".into(),
            });
        }
        let (activity_timeout_secs, keepalive_interval_secs) = keepalive_pair(&raw, "fesl")?;
        let theater = get_endpoint(&raw, "theater")?;
        let (theater_activity_timeout_secs, theater_keepalive_interval_secs) = keepalive_pair(&raw, "theater")?;
        let messenger = get_endpoint(&raw, "messenger")?;
        if theater == messenger {
            return Err(ConfigError::Invalid {
                section: "messenger",
                key: "advertise_port",
                msg: "theater and messenger must advertise different ip:port pairs".into(),
            });
        }
        let room_key = match get(&raw, "privacy", "room_key")? {
            "none" => None,
            key => {
                mp_api::rules::check_room_key(key)
                    .map_err(|e| ConfigError::Invalid { section: "privacy", key: "room_key", msg: e.message })?;
                Some(key.to_owned())
            }
        };
        let terms_of_service = get(&raw, "account", "terms_of_service")?.to_owned();
        let mut countries = Vec::new();
        for item in get(&raw, "account", "countries")?.split('|') {
            let (iso, desc) = item.split_once(':').ok_or_else(|| ConfigError::Invalid {
                section: "account",
                key: "countries",
                msg: format!("entry {item:?} is not ISO:description"),
            })?;
            let (iso, desc) = (iso.trim(), desc.trim());
            if iso.len() != 2 || !iso.bytes().all(|b| b.is_ascii_uppercase()) || desc.is_empty() {
                return Err(ConfigError::Invalid {
                    section: "account",
                    key: "countries",
                    msg: format!("entry {item:?}: ISO code must be two uppercase letters and the description non-empty"),
                });
            }
            countries.push(Country { iso_code: iso.to_owned(), description: desc.to_owned() });
        }
        Ok(Config {
            server,
            fesl_names,
            activity_timeout_secs,
            keepalive_interval_secs,
            theater,
            theater_activity_timeout_secs,
            theater_keepalive_interval_secs,
            lobby_name: get(&raw, "theater", "lobby_name")?.to_owned(),
            messenger,
            room_key,
            terms_of_service,
            countries,
            connect_timeout_ms: get_u32(&raw, "http", "connect_timeout_ms")?,
            io_timeout_ms: get_u32(&raw, "http", "io_timeout_ms")?,
            ws_poll_interval_ms: get_u32(&raw, "websocket", "poll_interval_ms")?,
            ws_idle_timeout_secs: get_u32(&raw, "websocket", "idle_timeout_secs")?,
            relay: get_relay(&raw)?,
            signature_wait_ms: get_u32(&raw, "startup", "signature_wait_ms")?,
            log_file: get(&raw, "log", "file")?.to_owned(),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const SAMPLE: &str = "\
; comment
[server]
base_url = https://mp.example.org/api/

[fesl]
intercept_names = fesl.ea.com, mercs2-pc.fesl.ea.com
activity_timeout_secs = 240
keepalive_interval_secs = 60

[theater]
advertise_ip = 127.0.0.1
advertise_port = 14300
activity_timeout_secs = 240
keepalive_interval_secs = 60
lobby_name = Online games

[messenger]
advertise_ip = 127.0.0.1
advertise_port = 13505

[privacy]
room_key = none

[account]
terms_of_service = Be excellent to each other.
countries = US:United States|GB:United Kingdom

[http]
connect_timeout_ms = 10000
io_timeout_ms = 15000

[websocket]
poll_interval_ms = 10
idle_timeout_secs = 75

[relay]
alias_base = 127.0.0.2
alias_tunnel_port = 10010
dtls_mtu = 1200
handshake_timeout_ms = 10000
poll_interval_ms = 50
close_grace_ms = 5000

[startup]
signature_wait_ms = 120000

[log]
file = multiplayer_restored.log
";

    pub fn sample() -> Config {
        Config::parse(SAMPLE).unwrap()
    }

    #[test]
    fn parses_sample() {
        let c = sample();
        assert_eq!(c.server, BaseUrl { host: "mp.example.org".into(), port: 443, prefix: "/api".into() });
        assert_eq!(c.server.path("/v1/sessions"), "/api/v1/sessions");
        assert_eq!(c.fesl_names, vec!["fesl.ea.com", "mercs2-pc.fesl.ea.com"]);
        assert_eq!(c.theater, Endpoint { ip: Ipv4Addr::LOCALHOST, port: 14300 });
        assert_eq!(c.countries.len(), 2);
        assert_eq!(c.countries[1], Country { iso_code: "GB".into(), description: "United Kingdom".into() });
        assert_eq!(c.terms_of_service, "Be excellent to each other.");
        assert_eq!(c.room_key, None);
        assert_eq!(c.lobby_name, "Online games");
        assert_eq!((c.theater_activity_timeout_secs, c.theater_keepalive_interval_secs), (240, 60));
        assert_eq!((c.ws_poll_interval_ms, c.ws_idle_timeout_secs), (10, 75));
        assert_eq!(
            c.relay,
            RelayConfig {
                alias_base: Ipv4Addr::new(127, 0, 0, 2),
                alias_tunnel_port: 10010,
                dtls_mtu: 1200,
                handshake_timeout_ms: 10000,
                poll_interval_ms: 50,
                close_grace_ms: 5000
            }
        );
    }

    #[test]
    fn room_key_values() {
        let t = SAMPLE.replace("room_key = none", "room_key = Venezuela-42");
        assert_eq!(Config::parse(&t).unwrap().room_key.as_deref(), Some("Venezuela-42"));
        for bad in ["room_key = abc", "room_key = has space", "room_key ="] {
            let t = SAMPLE.replace("room_key = none", bad);
            assert!(Config::parse(&t).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn shipped_ini_parses() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../src/multiplayer_restored.ini");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        Config::parse(&text).unwrap();
    }

    #[test]
    fn unknown_key_is_an_error() {
        let t = SAMPLE.replace("[log]\n", "[log]\nlevel = debug\n");
        assert!(matches!(Config::parse(&t), Err(ConfigError::UnknownKey { key, .. }) if key == "level"));
    }

    #[test]
    fn unknown_section_is_an_error() {
        let t = format!("{SAMPLE}[extra]\n");
        assert!(matches!(Config::parse(&t), Err(ConfigError::UnknownSection { .. })));
    }

    #[test]
    fn missing_key_is_an_error() {
        let t = SAMPLE.replace("io_timeout_ms = 15000\n", "");
        assert_eq!(Config::parse(&t), Err(ConfigError::Missing { section: "http", key: "io_timeout_ms" }));
    }

    #[test]
    fn duplicates_are_errors() {
        let t = SAMPLE.replace("[log]\n", "[log]\nfile = a.log\n");
        assert!(matches!(Config::parse(&t), Err(ConfigError::DuplicateKey { .. })));
        let t = format!("{SAMPLE}[log]\n");
        assert!(matches!(Config::parse(&t), Err(ConfigError::DuplicateSection { .. })));
    }

    #[test]
    fn value_rules() {
        for (from, to) in [
            ("https://mp.example.org/api/", "http://mp.example.org"),
            ("https://mp.example.org/api/", "https://mp.example.org:0"),
            ("advertise_ip = 127.0.0.1\nadvertise_port = 14300", "advertise_ip = 10.0.0.1\nadvertise_port = 14300"),
            ("advertise_port = 13505", "advertise_port = 14300"),
            ("alias_base = 127.0.0.2", "alias_base = 127.0.0.1"),
            ("alias_base = 127.0.0.2", "alias_base = 10.0.0.2"),
            ("alias_tunnel_port = 10010", "alias_tunnel_port = 70000"),
            ("keepalive_interval_secs = 60\nlobby_name", "keepalive_interval_secs = 300\nlobby_name"),
            ("keepalive_interval_secs = 60", "keepalive_interval_secs = 240"),
            ("countries = US:United States|GB:United Kingdom", "countries = USA:United States"),
            ("intercept_names = fesl.ea.com, mercs2-pc.fesl.ea.com", "intercept_names = fesl.ea.com:18710"),
            ("io_timeout_ms = 15000", "io_timeout_ms = 0"),
            ("io_timeout_ms = 15000", "io_timeout_ms ="),
        ] {
            let t = SAMPLE.replace(from, to);
            assert_ne!(t, SAMPLE, "replacement {from:?} did not apply");
            assert!(Config::parse(&t).is_err(), "{to:?} should be rejected");
        }
    }

    #[test]
    fn syntax_errors() {
        assert!(matches!(Config::parse("[server\n"), Err(ConfigError::Syntax { line: 1, .. })));
        assert!(matches!(Config::parse("base_url = x\n"), Err(ConfigError::Syntax { line: 1, .. })));
        assert!(matches!(Config::parse("[server]\nbase_url\n"), Err(ConfigError::Syntax { line: 2, .. })));
    }
}
