//! The FESL service, answered in-process.
//!
//! Bytes the game Sends on the virtual FESL connection are framed with `plasma_proto` and dispatched by
//! service 4CC + `TXN`; replies are queued for the game's Recv. Request fields and the reply fields the
//! game reads are from `docs/reverse_engineer/multiplayer_txn_catalogue.md` §1 (graded there).
//!
//! Answered locally: fsys Hello / MemCheck / Ping / Goodbye / GetPingSites; acct GetCountryList / GetTos /
//! SuggestScreenNames / GetTelemetryToken / GameSpyPreAuth; subs GetEntitlementByBundle.
//! Answered via the server: acct AddAccount (`POST /v1/accounts`, username + password only) and acct Login
//! (`POST /v1/sessions`). A successful Login opens the lobby WebSocket ([`crate::lobby`]) with the new
//! session; from then on this connection also fails (game-visible FESL disconnect) if the lobby ends.
//!
//! **Browsing (pnow).** The game's matchmaking module sends `pnow Start` and waits for a `pnow Status` push;
//! with `sessionState=COMPLETE` it reads `props.{resultType}` and, for `LIST`/`JOIN`, `props.{games}.[]`
//! and per game `props.{games}.<i>.lid` / `.gid` (format `%s.%i.%s`, keys `lid`/`gid` at `0xb64318`/
//! `0xb64314`), then fetches each game with Theater GDAT `LID+GID` (`FUN_009b82c0`, `FUN_009b5690`, status
//! dispatch `0x9bb8e3`; state names compared in `0x97fb10`: NEW ACTIVE COMPLETE ERROR CANCELLED DELETED;
//! `ERROR` reads `props.{reasonString}`). Start is answered at once (`id.id`, `id.partition`); the Status
//! push follows the server's `games.list` (joinable games, current room key). Custom-search filters arrive
//! as `players.0.props.{filter-<n>}=<value>` with `players.0.props.{filterToGame-<n>}=<field>`; each is
//! matched fuzzily against the listed games' properties ([`normalise_key`], [`values_match`],
//! [`filter_outcome`]). A filter naming no property of a game is logged and treated as matching (user
//! decision: fuzzy, neither strict nor ignored).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use mp_api::rest::{ClientInfo, CreateAccount, CreateSession};
use plasma_proto::fesl::{FeslId, MultipartAssembler, MultipartError, encode_reply};
use plasma_proto::frame::{self, FrameDecoder, FrameError, Kind};
use plasma_proto::tagfield::{TagFieldError, TagFieldReader, TagFields};
use thiserror::Error;

use mp_api::ws::{GameSummary, Joinability, Request, Response};

use crate::config::{Config, Country, Endpoint};
use crate::errors::{FeslError, GENERIC_ERROR_CODE, map_api_error};
use crate::lobby::{Lobby, LobbyEvent, LobbyProvider};
use crate::log::Logger;
use crate::room_key::RoomKeyStore;
use crate::session::{LoggedIn, SessionSlot};
use crate::worker::{Backend, BackendFailure, BackendReply, BackendRequest, JobId, Outcome};

/// Largest client → ASI frame accepted. The client splits anything above its own `fragmentSize` into
/// multipart frames (`FUN_0097ccb0`), so real frames stay far below this; ASI policy bound.
pub const MAX_INBOUND_FRAME: usize = 0x10000;

/// The client builds pieces of `fragmentSize - 0x20` (`FUN_0097ccb0`); the multipart encoder needs room
/// for at least one 4-character quad beyond that.
const MIN_FRAGMENT_SIZE: i64 = 0x24;

/// Entitlement answered for every account (user decision, design draft); the parser `FUN_009739a0` reads
/// these keys (catalogue §1 subs).
const ENTITLEMENT_PRICING_OPTION: &str = "REG-PC-MERCENARIES2-UNLOCK-1";
const ENTITLEMENT_NAME: &str = "Mercenaries 2 UNLOCK 1 PC";

const FSYS: Kind = Kind::new(b"fsys");
const PNOW: Kind = Kind::new(b"pnow");
const FILTER_PREFIX: &str = "players.0.props.{filter-";

#[derive(Debug, Error)]
pub enum FeslFailure {
    #[error("FESL framing: {0}")]
    Frame(#[from] FrameError),
    #[error("FESL multipart: {0}")]
    Multipart(#[from] MultipartError),
    #[error("FESL TagField: {0}")]
    TagField(#[from] TagFieldError),
    #[error("FESL protocol: {0}")]
    Protocol(String),
    #[error("server unreachable for {what}: {msg}")]
    Transport { what: String, msg: String },
    #[error("lobby: {0}")]
    Lobby(String),
}

/// Settings the adapter needs, taken from the ini and the build identity.
#[derive(Clone, Debug)]
pub struct FeslSettings {
    pub theater: Endpoint,
    pub messenger: Endpoint,
    pub activity_timeout_secs: u32,
    pub keepalive: Duration,
    pub terms_of_service: String,
    pub countries: Vec<Country>,
    pub client: ClientInfo,
}

impl FeslSettings {
    pub fn from_config(cfg: &Config, build_sha256: &str) -> Self {
        FeslSettings {
            theater: cfg.theater.clone(),
            messenger: cfg.messenger.clone(),
            activity_timeout_secs: cfg.activity_timeout_secs,
            keepalive: Duration::from_secs(cfg.keepalive_interval_secs.into()),
            terms_of_service: cfg.terms_of_service.clone(),
            countries: cfg.countries.clone(),
            client: ClientInfo { build_sha256: build_sha256.to_owned(), asi_version: crate::ASI_VERSION.to_owned() },
        }
    }
}

enum PendingKind {
    Login { username: String },
    AddAccount,
}

struct Pending {
    kind: Kind,
    tid: u32,
    txn: String,
    what: PendingKind,
}

/// One custom-search filter from pnow Start.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Filter {
    /// `<n>` of `{filter-<n>}`.
    name: String,
    /// What the filter is compared with: the `{filterToGame-<n>}` value, or `<n>` itself when the game sent
    /// no `filterToGame` for it.
    target: String,
    /// The `{filter-<n>}` value.
    wanted: String,
}

/// A pnow session waiting for its games.list answer.
struct Pnow {
    id: i64,
    partition: String,
    filters: Vec<Filter>,
}

pub struct FeslAdapter<B: Backend> {
    settings: Arc<FeslSettings>,
    backend: B,
    session: SessionSlot,
    log: Logger,
    decoder: FrameDecoder,
    multipart: HashMap<u32, (Kind, MultipartAssembler)>,
    out: VecDeque<u8>,
    fragment_size: Option<usize>,
    pending: HashMap<JobId, Pending>,
    next_job: JobId,
    next_keepalive: Option<Instant>,
    wall_clock: fn() -> SystemTime,
    random: fn(&mut [u8]) -> Result<(), String>,
    lobby_provider: Arc<dyn LobbyProvider>,
    lobby: Option<Box<dyn Lobby>>,
    room_keys: RoomKeyStore,
    pnow: HashMap<u64, Pnow>,
    next_pnow_id: i64,
}

fn openssl_random(buf: &mut [u8]) -> Result<(), String> {
    openssl::rand::rand_bytes(buf).map_err(|e| e.to_string())
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl<B: Backend> FeslAdapter<B> {
    pub fn new(
        settings: Arc<FeslSettings>,
        backend: B,
        session: SessionSlot,
        lobby_provider: Arc<dyn LobbyProvider>,
        room_keys: RoomKeyStore,
        log: Logger,
    ) -> Self {
        FeslAdapter {
            settings,
            backend,
            session,
            log,
            decoder: FrameDecoder::new(MAX_INBOUND_FRAME),
            multipart: HashMap::new(),
            out: VecDeque::new(),
            fragment_size: None,
            pending: HashMap::new(),
            next_job: 1,
            next_keepalive: None,
            wall_clock: SystemTime::now,
            random: openssl_random,
            lobby_provider,
            lobby: None,
            room_keys,
            pnow: HashMap::new(),
            next_pnow_id: 1,
        }
    }

    #[cfg(test)]
    fn with_clocks(mut self, wall: fn() -> SystemTime, random: fn(&mut [u8]) -> Result<(), String>) -> Self {
        self.wall_clock = wall;
        self.random = random;
        self
    }

    /// Bytes queued for the game's Recv.
    pub fn outbound(&mut self) -> &mut VecDeque<u8> {
        &mut self.out
    }

    /// Bytes from the game's Send.
    pub fn on_game_bytes(&mut self, bytes: &[u8], now: Instant) -> Result<(), FeslFailure> {
        self.decoder.feed(bytes);
        while let Some(f) = self.decoder.next_frame()? {
            let id = FeslId::decode(f.id);
            if id.multipart {
                let entry = self.multipart.entry(id.tid).or_insert_with(|| (f.kind, MultipartAssembler::new()));
                if entry.0 != f.kind {
                    return Err(FeslFailure::Protocol(format!(
                        "multipart tid {} switched service from {:?} to {:?}",
                        id.tid, entry.0, f.kind
                    )));
                }
                if let Some(text) = entry.1.push(&f)? {
                    self.multipart.remove(&id.tid);
                    self.dispatch(f.kind, id.tid, &text, now)?;
                }
            } else {
                self.dispatch(f.kind, id.tid, &f.payload, now)?;
            }
        }
        Ok(())
    }

    /// Deliver finished backend calls and keepalive pushes. Call from Update/Recv.
    pub fn pump(&mut self, now: Instant) -> Result<(), FeslFailure> {
        for (job, outcome) in self.backend.poll() {
            let p = self
                .pending
                .remove(&job)
                .ok_or_else(|| FeslFailure::Protocol(format!("backend returned unknown job {job}")))?;
            self.complete(p, outcome)?;
        }
        let events = match self.lobby.as_mut() {
            Some(l) => l.poll().map_err(FeslFailure::Lobby)?,
            None => Vec::new(),
        };
        for ev in events {
            match ev {
                LobbyEvent::Reply { id, result } => {
                    let p = self
                        .pnow
                        .remove(&id)
                        .ok_or_else(|| FeslFailure::Protocol(format!("lobby reply #{id} matches no pnow session")))?;
                    self.pnow_status(p, result)?;
                }
                LobbyEvent::Push(p) => {
                    return Err(FeslFailure::Protocol(format!("lobby push on the FESL handle, which never subscribes: {p:?}")));
                }
            }
        }
        if let Some(due) = self.next_keepalive
            && now >= due
        {
            self.push_memcheck()?;
            self.next_keepalive = Some(now + self.settings.keepalive);
        }
        Ok(())
    }

    fn fragment_size(&self, txn: &str) -> Result<usize, FeslFailure> {
        self.fragment_size
            .ok_or_else(|| FeslFailure::Protocol(format!("{txn} arrived before fsys Hello (no fragmentSize to reply with)")))
    }

    fn reply(&mut self, kind: Kind, tid: u32, fields: &TagFields, txn: &str) -> Result<(), FeslFailure> {
        let frag = self.fragment_size(txn)?;
        for f in encode_reply(kind, tid, fields, frag)? {
            self.out.extend(f);
        }
        Ok(())
    }

    fn push(&mut self, kind: Kind, fields: &TagFields) -> Result<(), FeslFailure> {
        self.out.extend(frame::encode(kind, FeslId::push(), &fields.to_payload())?);
        Ok(())
    }

    fn reply_error(&mut self, kind: Kind, tid: u32, txn: &str, e: &FeslError) -> Result<(), FeslFailure> {
        let mut t = TagFields::new();
        t.set_str("TXN", txn)?;
        t.set_int("errorCode", e.code)?;
        t.set_str("localizedMessage", &e.message)?;
        self.reply(kind, tid, &t, txn)
    }

    fn push_memcheck(&mut self) -> Result<(), FeslFailure> {
        let mut salt = [0u8; 4];
        (self.random)(&mut salt).map_err(|e| FeslFailure::Protocol(format!("random salt: {e}")))?;
        let mut t = TagFields::new();
        t.set_str("TXN", "MemCheck")?;
        t.set_int("salt", u32::from_le_bytes(salt).into())?;
        t.set_int("type", 0)?;
        t.set_int("memcheck.[]", 0)?;
        self.push(FSYS, &t)
    }

    fn dispatch(&mut self, kind: Kind, tid: u32, payload: &[u8], now: Instant) -> Result<(), FeslFailure> {
        let r = TagFieldReader::new(payload);
        let txn = r
            .get_str("TXN")?
            .ok_or_else(|| FeslFailure::Protocol(format!("{kind:?} frame tid {tid} without TXN")))?;
        let mut t = TagFields::new();
        t.set_str("TXN", &txn)?;
        match (&kind.0, txn.as_str()) {
            (b"fsys", "Hello") => {
                let frag = r
                    .get_int("fragmentSize")?
                    .ok_or_else(|| FeslFailure::Protocol("fsys Hello without fragmentSize".into()))?;
                if frag < MIN_FRAGMENT_SIZE {
                    return Err(FeslFailure::Protocol(format!("fsys Hello fragmentSize {frag} is below {MIN_FRAGMENT_SIZE}")));
                }
                self.fragment_size = Some(frag as usize);
                self.log.info(format!(
                    "FESL Hello: clientString={:?} sku={:?} clientVersion={:?} fragmentSize={frag}",
                    r.get_str("clientString")?.unwrap_or_default(),
                    r.get_str("sku")?.unwrap_or_default(),
                    r.get_str("clientVersion")?.unwrap_or_default()
                ));
                let s = self.settings.clone();
                let cur = crate::curtime::format((self.wall_clock)()).map_err(FeslFailure::Protocol)?;
                t.set_str("theaterIp", s.theater.ip.to_string())?;
                t.set_int("theaterPort", s.theater.port.into())?;
                t.set_str("messengerIp", s.messenger.ip.to_string())?;
                t.set_int("messengerPort", s.messenger.port.into())?;
                t.set_int("activityTimeoutSecs", s.activity_timeout_secs.into())?;
                t.set_str("curTime", cur)?;
                self.reply(kind, tid, &t, &txn)?;
                self.push_memcheck()?;
                self.next_keepalive = Some(now + s.keepalive);
            }
            // The client's answer to our MemCheck push, its own keepalive, and its sign-off: no reply.
            (b"fsys", "MemCheck") | (b"fsys", "Ping") => {}
            (b"fsys", "Goodbye") => {
                self.log.info(format!(
                    "FESL Goodbye: reason={:?} message={:?}",
                    r.get_str("reason")?.unwrap_or_default(),
                    r.get_str("message")?.unwrap_or_default()
                ));
            }
            (b"fsys", "GetPingSites") => {
                t.set_int("minPingSitesToPing", 0)?;
                t.set_int("pingSite.[]", 0)?;
                self.reply(kind, tid, &t, &txn)?;
            }
            (b"acct", "GetCountryList") => {
                let countries = self.settings.countries.clone();
                t.set_list("countryList", &countries, |t, p, c| {
                    t.set_str(&format!("{p}.description"), &c.description)?;
                    t.set_str(&format!("{p}.ISOCode"), &c.iso_code)?;
                    t.set_int(&format!("{p}.parentalControlAgeLimit"), 0)?;
                    t.set_int(&format!("{p}.registrationAgeLimit"), 0)?;
                    t.set_int(&format!("{p}.allowEmailsDefaultValue"), 0)?;
                    Ok(())
                })?;
                self.reply(kind, tid, &t, &txn)?;
            }
            (b"acct", "GetTos") => {
                t.set_str("tos", self.settings.terms_of_service.clone())?;
                self.reply(kind, tid, &t, &txn)?;
            }
            (b"acct", "SuggestScreenNames") => {
                t.set_int("names.[]", 0)?;
                self.reply(kind, tid, &t, &txn)?;
            }
            // No reply key of either TXN exists in the exe (catalogue §1 acct): a bare acknowledgement.
            (b"acct", "GetTelemetryToken") | (b"acct", "GameSpyPreAuth") => self.reply(kind, tid, &t, &txn)?,
            (b"subs", "GetEntitlementByBundle") => {
                self.log.info(format!("entitlement query bundleId={:?}: ACTIVE", r.get_str("bundleId")?.unwrap_or_default()));
                t.set_int("type", 1)?;
                t.set_str("name", ENTITLEMENT_NAME)?;
                t.set_str("description", ENTITLEMENT_NAME)?;
                t.set_int("entitlementStatus", 0)?;
                t.set_str("entitlementStatusDesc", "ACTIVE")?;
                t.set_str("entitlementSuspendDate", "")?;
                t.set_str("pricingOptionId", ENTITLEMENT_PRICING_OPTION)?;
                self.reply(kind, tid, &t, &txn)?;
            }
            (b"acct", "Login") => self.login(kind, tid, &txn, &r)?,
            (b"pnow", "Start") => self.pnow_start(kind, tid, &txn, &r)?,
            (b"acct", "AddAccount") => self.add_account(kind, tid, &txn, &r)?,
            _ => {
                let msg = format!("{} {txn} is not implemented by multiplayer_restored {}", kind_name(kind), crate::ASI_VERSION);
                self.log.error(&msg);
                self.reply_error(kind, tid, &txn, &FeslError { code: GENERIC_ERROR_CODE, message: msg.clone() })?;
            }
        }
        Ok(())
    }

    fn credentials(&mut self, kind: Kind, tid: u32, txn: &str, r: &TagFieldReader) -> Result<Option<(String, String)>, FeslFailure> {
        let name = r.get_str("name")?;
        let password = r.get_str("password")?;
        let (Some(name), Some(password)) = (name, password) else {
            let msg = if r.get_str("encryptedInfo")?.is_some_and(|s| !s.is_empty()) {
                format!("{txn} with encryptedInfo (saved EA login) cannot be used; log in with name and password")
            } else {
                format!("{txn} without name and password")
            };
            self.log.error(&msg);
            self.reply_error(kind, tid, txn, &FeslError { code: GENERIC_ERROR_CODE, message: msg })?;
            return Ok(None);
        };
        if let Err(e) = mp_api::rules::check_username(&name).and_then(|_| mp_api::rules::check_password(&password)) {
            self.log.warn(format!("{txn} for {name:?} rejected locally: {e}"));
            self.reply_error(kind, tid, txn, &map_api_error(&e))?;
            return Ok(None);
        }
        Ok(Some((name, password)))
    }

    fn submit(&mut self, p: Pending, req: BackendRequest) {
        let job = self.next_job;
        self.next_job += 1;
        self.log.info(format!("{} {} tid {} → {}", kind_name(p.kind), p.txn, p.tid, req.describe()));
        self.pending.insert(job, p);
        self.backend.submit(job, req);
    }

    fn login(&mut self, kind: Kind, tid: u32, txn: &str, r: &TagFieldReader) -> Result<(), FeslFailure> {
        if r.get_int("returnEncryptedInfo")? == Some(1) {
            self.log.info("Login asked for encryptedLoginInfo; none is issued (the game clears it when absent)");
        }
        let Some((username, password)) = self.credentials(kind, tid, txn, r)? else { return Ok(()) };
        let req = CreateSession { username: username.clone(), password, client: self.settings.client.clone() };
        self.submit(
            Pending { kind, tid, txn: txn.to_owned(), what: PendingKind::Login { username } },
            BackendRequest::CreateSession(req),
        );
        Ok(())
    }

    fn add_account(&mut self, kind: Kind, tid: u32, txn: &str, r: &TagFieldReader) -> Result<(), FeslFailure> {
        // Everything except name/password stays on this machine (user decision): log which were present,
        // never their values.
        let dropped: Vec<&str> = [
            "email",
            "DOBDay",
            "DOBMonth",
            "DOBYear",
            "zipCode",
            "countryCode",
            "parentalEmail",
            "eaMailFlag",
            "thirdPartyMailFlag",
        ]
        .into_iter()
        .filter(|k| r.contains(k))
        .collect();
        self.log.info(format!("AddAccount: not forwarded: {}", dropped.join(", ")));
        let Some((username, password)) = self.credentials(kind, tid, txn, r)? else { return Ok(()) };
        self.submit(
            Pending { kind, tid, txn: txn.to_owned(), what: PendingKind::AddAccount },
            BackendRequest::CreateAccount(CreateAccount { username, password }),
        );
        Ok(())
    }

    fn complete(&mut self, p: Pending, outcome: Outcome) -> Result<(), FeslFailure> {
        let what = format!("{} {} tid {}", kind_name(p.kind), p.txn, p.tid);
        match (p.what, outcome) {
            (PendingKind::Login { username }, Ok(BackendReply::SessionCreated(s))) => {
                if s.display_name.len() > mp_api::rules::USERNAME_MAX || s.display_name.is_empty() {
                    return Err(FeslFailure::Protocol(format!(
                        "server display_name {:?} does not fit the game's 31-character buffer",
                        s.display_name
                    )));
                }
                let mut raw = [0u8; 16];
                (self.random)(&mut raw).map_err(|e| FeslFailure::Protocol(format!("random lkey: {e}")))?;
                let lkey = hex(&raw);
                let mut t = TagFields::new();
                t.set_str("TXN", &p.txn)?;
                t.set_str("lkey", &lkey)?;
                t.set_str("displayName", &s.display_name)?;
                t.set_int("userId", s.user_id.0)?;
                self.reply(p.kind, p.tid, &t, &p.txn)?;
                self.log.info(format!("{what}: {username:?} logged in as {:?} (user {})", s.display_name, s.user_id.0));
                let logged = LoggedIn {
                    token: s.token,
                    user_id: s.user_id,
                    display_name: s.display_name,
                    expires_at: s.expires_at,
                    lkey,
                };
                *self.session.lock().map_err(|_| FeslFailure::Protocol("session lock poisoned".into()))? = Some(logged.clone());
                self.lobby_provider.start(&logged).map_err(FeslFailure::Lobby)?;
                self.lobby = Some(self.lobby_provider.handle(false).map_err(FeslFailure::Lobby)?);
            }
            (PendingKind::AddAccount, Ok(BackendReply::AccountCreated(a))) => {
                let mut t = TagFields::new();
                t.set_str("TXN", &p.txn)?;
                self.reply(p.kind, p.tid, &t, &p.txn)?;
                self.log.info(format!("{what}: account {:?} created (user {})", a.username, a.user_id.0));
            }
            (_, Ok(other)) => {
                return Err(FeslFailure::Protocol(format!("{what}: backend answered with the wrong reply type {other:?}")));
            }
            (_, Err(BackendFailure::Api(e))) => {
                self.log.warn(format!("{what}: server refused: {e}"));
                self.reply_error(p.kind, p.tid, &p.txn, &map_api_error(&e))?;
            }
            (_, Err(BackendFailure::Transport(msg))) => return Err(FeslFailure::Transport { what, msg }),
        }
        Ok(())
    }
}

impl<B: Backend> FeslAdapter<B> {
    fn pnow_start(&mut self, kind: Kind, tid: u32, txn: &str, r: &TagFieldReader) -> Result<(), FeslFailure> {
        if self.lobby.is_none() {
            let msg = format!("pnow {txn} before acct Login");
            self.log.error(&msg);
            return self.reply_error(kind, tid, txn, &FeslError { code: GENERIC_ERROR_CODE, message: msg });
        }
        let partition = r
            .get_str("partition.partition")?
            .ok_or_else(|| FeslFailure::Protocol("pnow Start without partition.partition".into()))?;
        let mut filters = Vec::new();
        for key in r.keys()? {
            let Some(name) = key.strip_prefix(FILTER_PREFIX).and_then(|k| k.strip_suffix('}')) else { continue };
            let wanted = r
                .get_str(&key)?
                .ok_or_else(|| FeslFailure::Protocol(format!("pnow Start lists {key} but its value cannot be read")))?;
            let target = r.get_str(&format!("players.0.props.{{filterToGame-{name}}}"))?.unwrap_or_else(|| name.to_owned());
            filters.push(Filter { name: name.to_owned(), target, wanted });
        }
        if !filters.is_empty() {
            let shown: Vec<String> =
                filters.iter().map(|f| format!("{}={:?} (→ {:?}, key {:?})", f.name, f.wanted, f.target, normalise_key(&f.target))).collect();
            self.log.info(format!("pnow Start: fuzzy filters {}", shown.join(", ")));
        }
        let id = self.next_pnow_id;
        self.next_pnow_id += 1;
        let mut t = TagFields::new();
        t.set_str("TXN", txn)?;
        t.set_int("id.id", id)?;
        t.set_str("id.partition", &partition)?;
        self.reply(kind, tid, &t, txn)?;
        let room_key = self.room_keys.get().map_err(FeslFailure::Lobby)?;
        let lobby = self.lobby.as_mut().expect("checked above");
        let job = lobby.request(Request::GamesList { joinable_only: true, room_key }).map_err(FeslFailure::Lobby)?;
        self.log.info(format!("pnow Start {id} ({} filter(s)) → lobby #{job}: games.list", filters.len()));
        self.pnow.insert(job, Pnow { id, partition, filters });
        Ok(())
    }

    fn pnow_status(&mut self, p: Pnow, result: Result<Response, mp_api::ApiError>) -> Result<(), FeslFailure> {
        let mut t = TagFields::new();
        t.set_str("TXN", "Status")?;
        t.set_int("id.id", p.id)?;
        t.set_str("id.partition", &p.partition)?;
        match result {
            Ok(Response::Games(games)) => {
                let mut kept = Vec::new();
                let mut unmatched: Vec<(&str, Vec<i64>)> = p.filters.iter().map(|f| (f.name.as_str(), Vec::new())).collect();
                for g in games {
                    let props = game_properties(&g);
                    let mut all = true;
                    for (f, (_, no_counterpart)) in p.filters.iter().zip(unmatched.iter_mut()) {
                        match filter_outcome(f, &props) {
                            FilterOutcome::Match => {}
                            FilterOutcome::Mismatch => all = false,
                            FilterOutcome::NoCounterpart => no_counterpart.push(g.game_id.0),
                        }
                    }
                    if all {
                        kept.push(g);
                    }
                }
                for (name, gids) in unmatched.iter().filter(|(_, gids)| !gids.is_empty()) {
                    self.log.info(format!(
                        "pnow Status {}: filter {name:?} has no counterpart in game(s) {gids:?}; treated as matching",
                        p.id
                    ));
                }
                let games = kept;
                t.set_str("sessionState", "COMPLETE")?;
                t.set_str("props.{resultType}", "LIST")?;
                t.set_int("props.{availableServerCount}", games.len() as i64)?;
                t.set_list("props.{games}", &games, |t, prefix, g| {
                    t.set_int(&format!("{prefix}.lid"), crate::theater::LOBBY_ID)?;
                    t.set_int(&format!("{prefix}.gid"), g.game_id.0)?;
                    Ok(())
                })?;
                self.log.info(format!("pnow Status {}: {} game(s)", p.id, games.len()));
            }
            Err(e) => {
                self.log.error(format!("pnow {}: games.list failed: {e}", p.id));
                t.set_str("sessionState", "ERROR")?;
                t.set_str("props.{reasonString}", e.to_string())?;
            }
            Ok(other) => return Err(FeslFailure::Protocol(format!("games.list answered with {other:?}"))),
        }
        self.reply(PNOW, 0, &t, "Status")
    }
}

/// A game's properties a filter may name, as `(key, value)`: every `B-U-*` attribute, `B-version`, and the
/// summary fields `name`, `max_players`, `players` and `joinable` (the GDAT `J` letter `O`/`W`/`C`).
fn game_properties(g: &GameSummary) -> Vec<(String, String)> {
    let joinable = match g.joinable {
        Joinability::Open => "O",
        Joinability::Wait => "W",
        Joinability::Closed => "C",
    };
    let mut p: Vec<(String, String)> = g.attrs.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    p.push(("B-version".into(), g.version.clone()));
    p.push(("name".into(), g.name.clone()));
    p.push(("max_players".into(), g.max_players.to_string()));
    p.push(("players".into(), g.players.to_string()));
    p.push(("joinable".into(), joinable.into()));
    p
}

/// The key normalisation filters and game properties are compared under, applied in this order:
/// 1. ASCII letters are lowercased;
/// 2. every `{` and `}` is removed;
/// 3. one leading `b-` or `b_` is removed, then one leading `u-` or `u_` (so `B-U-Mission`, `B-Mission`,
///    `U-Mission` and `Mission` all become `mission`);
/// 4. every remaining `-` and `_` is removed (so `max_players`, `max-players` and `MaxPlayers` all become
///    `maxplayers`).
fn normalise_key(key: &str) -> String {
    let k: String = key.to_ascii_lowercase().chars().filter(|c| !matches!(c, '{' | '}')).collect();
    let k = k.strip_prefix("b-").or_else(|| k.strip_prefix("b_")).unwrap_or(&k);
    let k = k.strip_prefix("u-").or_else(|| k.strip_prefix("u_")).unwrap_or(k);
    k.chars().filter(|c| !matches!(c, '-' | '_')).collect()
}

/// Values are equal as numbers when both parse as finite `f64` (`2` = `2.0`), otherwise when they are equal
/// ignoring case (Unicode lowercase). Nothing is trimmed.
fn values_match(a: &str, b: &str) -> bool {
    match (a.parse::<f64>(), b.parse::<f64>()) {
        (Ok(x), Ok(y)) if x.is_finite() && y.is_finite() => x == y,
        _ => a.to_lowercase() == b.to_lowercase(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FilterOutcome {
    Match,
    Mismatch,
    /// No property's normalised key equals the filter's: logged, and the filter counts as matching.
    NoCounterpart,
}

/// The properties whose [`normalise_key`] equals the filter target's are its counterparts; the filter matches
/// when any counterpart's value [`values_match`] the wanted value.
fn filter_outcome(f: &Filter, properties: &[(String, String)]) -> FilterOutcome {
    let key = normalise_key(&f.target);
    let mut counterparts = properties.iter().filter(|(k, _)| normalise_key(k) == key).peekable();
    if counterparts.peek().is_none() {
        return FilterOutcome::NoCounterpart;
    }
    if counterparts.any(|(_, v)| values_match(v, &f.wanted)) { FilterOutcome::Match } else { FilterOutcome::Mismatch }
}

fn kind_name(k: Kind) -> String {
    k.as_str().map(str::to_owned).unwrap_or_else(|| format!("{:#010x}", k.as_u32()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::sample;
    use crate::lobby::fake::FakeProvider;
    use crate::log::capture;
    use mp_api::rest::{AccountCreated, SessionCreated};
    use mp_api::{ApiError, ErrorCode, UserId};
    use plasma_proto::frame::Frame;
    use std::time::UNIX_EPOCH;

    #[derive(Default)]
    struct FakeBackend {
        submitted: Vec<(JobId, BackendRequest)>,
        ready: Vec<(JobId, Outcome)>,
    }

    impl Backend for FakeBackend {
        fn submit(&mut self, id: JobId, req: BackendRequest) {
            self.submitted.push((id, req));
        }
        fn poll(&mut self) -> Vec<(JobId, Outcome)> {
            std::mem::take(&mut self.ready)
        }
    }

    fn fixed_wall() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_791_654_343) // Oct-10-2026 17:45:43
    }

    fn fixed_random(b: &mut [u8]) -> Result<(), String> {
        b.iter_mut().enumerate().for_each(|(i, x)| *x = i as u8);
        Ok(())
    }

    struct Rig {
        a: FeslAdapter<FakeBackend>,
        dec: FrameDecoder,
        session: SessionSlot,
        provider: Arc<FakeProvider>,
        keys: RoomKeyStore,
        log: capture::Captured,
        now: Instant,
    }

    fn rig() -> Rig {
        let (log, cap) = capture::logger();
        let session = crate::session::new_slot();
        let settings = Arc::new(FeslSettings::from_config(&sample(), &"5a".repeat(32)));
        let provider = Arc::new(FakeProvider::default());
        let keys = RoomKeyStore::new(None);
        let a = FeslAdapter::new(settings, FakeBackend::default(), session.clone(), provider.clone(), keys.clone(), log)
            .with_clocks(fixed_wall, fixed_random);
        Rig { a, dec: FrameDecoder::new(1 << 20), session, provider, keys, log: cap, now: Instant::now() }
    }

    /// A client request exactly as the game frames it: id `0xC0000000 | tid`, TagField text + NUL.
    fn req(kind: &[u8; 4], tid: u32, text: &str) -> Vec<u8> {
        let mut payload = text.as_bytes().to_vec();
        payload.push(0);
        frame::encode(Kind::new(kind), FeslId::request(tid), &payload).unwrap()
    }

    impl Rig {
        fn send(&mut self, bytes: &[u8]) {
            self.a.on_game_bytes(bytes, self.now).unwrap();
        }
        fn frames(&mut self) -> Vec<Frame> {
            let bytes: Vec<u8> = self.a.outbound().drain(..).collect();
            self.dec.feed(&bytes);
            let mut out = Vec::new();
            while let Some(f) = self.dec.next_frame().unwrap() {
                out.push(f);
            }
            out
        }
        fn hello(&mut self) -> Vec<Frame> {
            // Field list of the client's Hello builder (catalogue §1 fsys).
            self.send(&req(
                b"fsys",
                1,
                "TXN=Hello\nclientString=mercs2-pc\nsku=MERCS2PC\nlocale=en_US\nclientPlatform=PC\n\
                 clientVersion=1.1\nSDKVersion=4.3.4.0.0\nprotocolVersion=2.0\nfragmentSize=8096\n",
            ));
            self.frames()
        }
    }

    fn text(f: &Frame) -> String {
        String::from_utf8(f.payload.clone()).unwrap()
    }

    #[test]
    fn hello_reply_golden_then_memcheck_push() {
        let mut r = rig();
        let f = r.hello();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].kind, FSYS);
        assert_eq!(f[0].id, 0x8000_0001);
        assert_eq!(
            text(&f[0]),
            "TXN=Hello\ntheaterIp=127.0.0.1\ntheaterPort=14300\nmessengerIp=127.0.0.1\nmessengerPort=13505\n\
             activityTimeoutSecs=240\ncurTime=\"Oct-10-2026 17:45:43\"\n\0"
        );
        assert_eq!(f[1].id, 0x8000_0000, "push uses tid 0");
        assert_eq!(text(&f[1]), "TXN=MemCheck\nsalt=50462976\ntype=0\nmemcheck.[]=0\n\0");
    }

    #[test]
    fn keepalive_memcheck_follows_the_interval() {
        let mut r = rig();
        r.hello();
        let t0 = r.now;
        r.a.pump(t0 + Duration::from_secs(59)).unwrap();
        assert!(r.frames().is_empty());
        r.a.pump(t0 + Duration::from_secs(60)).unwrap();
        let f = r.frames();
        assert_eq!(f.len(), 1);
        assert!(text(&f[0]).starts_with("TXN=MemCheck\n"));
        r.a.pump(t0 + Duration::from_secs(119)).unwrap();
        assert!(r.frames().is_empty());
    }

    #[test]
    fn client_memcheck_ping_goodbye_get_no_reply() {
        let mut r = rig();
        r.hello();
        r.send(&req(b"fsys", 0, "TXN=MemCheck\nresult=\n"));
        r.send(&req(b"fsys", 2, "TXN=Ping\n"));
        r.send(&req(b"fsys", 3, "TXN=Goodbye\nreason=GOODBYE_CLIENT_NORMAL\nmessage=\n"));
        assert!(r.frames().is_empty());
        assert!(r.log.text().contains("FESL Goodbye: reason=\"GOODBYE_CLIENT_NORMAL\""));
    }

    #[test]
    fn local_answers_golden() {
        let mut r = rig();
        r.hello();
        r.send(&req(b"fsys", 2, "TXN=GetPingSites\n"));
        r.send(&req(b"acct", 3, "TXN=GetCountryList\n"));
        r.send(&req(b"acct", 4, "TXN=GetTos\ncountryCode=US\n"));
        r.send(&req(b"acct", 5, "TXN=SuggestScreenNames\nname=mattias\nmaxSuggestions=5\nkeywords.[]=0\n"));
        r.send(&req(b"acct", 6, "TXN=GetTelemetryToken\n"));
        r.send(&req(b"acct", 7, "TXN=GameSpyPreAuth\n"));
        r.send(&req(b"subs", 8, "TXN=GetEntitlementByBundle\nbundleId=REG-PC-MERCENARIES2-UNLOCK-1\n"));
        let f = r.frames();
        let got: Vec<(u32, String)> = f.iter().map(|f| (f.id, text(f))).collect();
        assert_eq!(
            got,
            vec![
                (0x8000_0002, "TXN=GetPingSites\nminPingSitesToPing=0\npingSite.[]=0\n\0".into()),
                (
                    0x8000_0003,
                    "TXN=GetCountryList\ncountryList.[]=2\ncountryList.0.description=\"United States\"\n\
                     countryList.0.ISOCode=US\ncountryList.0.parentalControlAgeLimit=0\n\
                     countryList.0.registrationAgeLimit=0\ncountryList.0.allowEmailsDefaultValue=0\n\
                     countryList.1.description=\"United Kingdom\"\ncountryList.1.ISOCode=GB\n\
                     countryList.1.parentalControlAgeLimit=0\ncountryList.1.registrationAgeLimit=0\n\
                     countryList.1.allowEmailsDefaultValue=0\n\0"
                        .into()
                ),
                (0x8000_0004, "TXN=GetTos\ntos=\"Be excellent to each other.\"\n\0".into()),
                (0x8000_0005, "TXN=SuggestScreenNames\nnames.[]=0\n\0".into()),
                (0x8000_0006, "TXN=GetTelemetryToken\n\0".into()),
                (0x8000_0007, "TXN=GameSpyPreAuth\n\0".into()),
                (
                    0x8000_0008,
                    "TXN=GetEntitlementByBundle\ntype=1\nname=\"Mercenaries 2 UNLOCK 1 PC\"\n\
                     description=\"Mercenaries 2 UNLOCK 1 PC\"\nentitlementStatus=0\nentitlementStatusDesc=ACTIVE\n\
                     entitlementSuspendDate=\npricingOptionId=REG-PC-MERCENARIES2-UNLOCK-1\n\0"
                        .into()
                ),
            ]
        );
    }

    #[test]
    fn login_success_goes_through_the_server_and_sets_the_session() {
        let mut r = rig();
        r.hello();
        // Field list of the client's Login builder (0x97d5c0): returnEncryptedInfo, name, password, macAddr.
        r.send(&req(b"acct", 9, "TXN=Login\nreturnEncryptedInfo=0\nname=Mattias\npassword=\"p a s s w o r d\"\nmacAddr=$001122334455\n"));
        assert!(r.frames().is_empty(), "no reply until the server answers");
        let (job, sent) = r.a.backend.submitted[0].clone();
        assert_eq!(
            sent,
            BackendRequest::CreateSession(CreateSession {
                username: "Mattias".into(),
                password: "p a s s w o r d".into(),
                client: ClientInfo { build_sha256: "5a".repeat(32), asi_version: crate::ASI_VERSION.into() },
            })
        );
        r.a.backend.ready.push((
            job,
            Ok(BackendReply::SessionCreated(SessionCreated {
                token: "server-token".into(),
                user_id: UserId(1234567890123),
                display_name: "Mattias".into(),
                expires_at: 1_800_000_000,
            })),
        ));
        r.a.pump(r.now).unwrap();
        let f = r.frames();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, 0x8000_0009);
        assert_eq!(
            text(&f[0]),
            "TXN=Login\nlkey=000102030405060708090a0b0c0d0e0f\ndisplayName=Mattias\nuserId=1234567890123\n\0"
        );
        let s = r.session.lock().unwrap().clone().unwrap();
        assert_eq!(s.token, "server-token");
        assert_eq!(s.lkey, "000102030405060708090a0b0c0d0e0f");
        assert!(!r.log.text().contains("p a s s"), "password must never be logged");
    }

    /// Login through the fake backend; returns the adapter with the lobby started.
    fn logged_in(r: &mut Rig) {
        r.hello();
        r.send(&req(b"acct", 2, "TXN=Login\nreturnEncryptedInfo=0\nname=Mattias\npassword=longenough\n"));
        let job = r.a.backend.submitted[0].0;
        r.a.backend.ready.push((
            job,
            Ok(BackendReply::SessionCreated(SessionCreated {
                token: "server-token".into(),
                user_id: UserId(7),
                display_name: "Mattias".into(),
                expires_at: 1_800_000_000,
            })),
        ));
        r.a.pump(r.now).unwrap();
        r.frames();
    }

    #[test]
    fn login_starts_the_lobby_and_its_end_ends_fesl() {
        let mut r = rig();
        logged_in(&mut r);
        assert_eq!(*r.provider.started.lock().unwrap(), vec!["server-token".to_string()]);
        r.provider.lobby.kill("the lobby session ended: the server closed the session: 1008 session expired");
        let e = r.a.pump(r.now).unwrap_err();
        assert!(e.to_string().contains("lobby: the lobby session ended: the server closed the session"), "{e}");
    }

    fn game(id: i64, version: &str, mission: &str) -> mp_api::ws::GameSummary {
        mp_api::ws::GameSummary {
            game_id: mp_api::GameId(id),
            name: format!("game {id}"),
            host: mp_api::ws::UserRef { user_id: UserId(id), name: format!("host{id}") },
            max_players: 2,
            players: 1,
            joinable: mp_api::ws::Joinability::Open,
            version: version.into(),
            attrs: [("B-U-mission".to_string(), mission.to_string())].into(),
            private: false,
        }
    }

    #[test]
    fn pnow_start_and_status_golden() {
        let mut r = rig();
        logged_in(&mut r);
        r.keys.set(Some("venezuela-42".into())).unwrap();
        // Start builder 0x984bdc: partition, version, players.0.ownerId/ownerType, props.{...}, filter pairs.
        r.send(&req(
            b"pnow",
            3,
            "TXN=Start\npartition.partition=/eagames/MERCS2\nversion=1\nplayers.[]=1\nplayers.0.ownerId=7\n\
             players.0.ownerType=1\nplayers.0.props.{name}=Mattias\nplayers.0.props.{filter-version}=1.1\n\
             players.0.props.{filterToGame-version}=version\nplayers.0.props.{filter-Mission}=m01\n\
             players.0.props.{filterToGame-Mission}=U-Mission\nplayers.0.props.{filter-debug}=1\n",
        ));
        assert_eq!(
            r.frames().iter().map(|f| (f.id, text(f))).collect::<Vec<_>>(),
            vec![(0x8000_0003, "TXN=Start\nid.id=1\nid.partition=/eagames/MERCS2\n\0".to_string())]
        );
        let (id, sent) = r.provider.lobby.last();
        assert_eq!(sent, mp_api::ws::Request::GamesList { joinable_only: true, room_key: Some("venezuela-42".into()) });
        assert!(r.log.text().contains("pnow Start: fuzzy filters version=\"1.1\""), "{}", r.log.text());
        let mut matching = game(5, "1.1", "m01");
        matching.attrs.insert("B-U-Mission".into(), "m01".into());
        r.provider.lobby.reply(id, Ok(mp_api::ws::Response::Games(vec![matching, game(6, "1.0", "m01"), game(8, "1.1", "m02")])));
        r.a.pump(r.now).unwrap();
        let f = r.frames();
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].kind, f[0].id), (PNOW, 0x8000_0000));
        assert_eq!(
            text(&f[0]),
            "TXN=Status\nid.id=1\nid.partition=/eagames/MERCS2\nsessionState=COMPLETE\nprops.{resultType}=LIST\n\
             props.{availableServerCount}=1\nprops.{games}.[]=1\nprops.{games}.0.lid=1\nprops.{games}.0.gid=5\n\0"
        );
        assert!(
            r.log.text().contains("pnow Status 1: filter \"debug\" has no counterpart in game(s) [5, 6, 8]; treated as matching"),
            "{}",
            r.log.text()
        );
    }

    fn filter(target: &str, wanted: &str) -> Filter {
        Filter { name: "n".into(), target: target.into(), wanted: wanted.into() }
    }

    #[test]
    fn filter_keys_normalise() {
        for k in ["B-U-Mission", "B-Mission", "U-Mission", "Mission", "{mission}", "b_u_mission", "MIS-SION"] {
            assert_eq!(normalise_key(k), "mission", "{k}");
        }
        for k in ["max_players", "max-players", "MaxPlayers", "B-maxPlayers"] {
            assert_eq!(normalise_key(k), "maxplayers", "{k}");
        }
        assert_eq!(normalise_key("version"), normalise_key("B-version"));
        assert_eq!(normalise_key("build"), "build", "only a separated b- is a prefix");
    }

    #[test]
    fn filters_match_fuzzily() {
        let g = game(5, "1.1", "m01");
        let props = game_properties(&g);
        // Exact.
        assert_eq!(filter_outcome(&filter("B-U-mission", "m01"), &props), FilterOutcome::Match);
        assert_eq!(filter_outcome(&filter("B-U-mission", "m02"), &props), FilterOutcome::Mismatch);
        // Case-different key and value.
        assert_eq!(filter_outcome(&filter("U-MISSION", "M01"), &props), FilterOutcome::Match);
        // Prefix-different keys: the game's `B-version` and `B-U-mission` under `version` / `mission`.
        assert_eq!(filter_outcome(&filter("version", "1.1"), &props), FilterOutcome::Match);
        assert_eq!(filter_outcome(&filter("{mission}", "m01"), &props), FilterOutcome::Match);
        // Numeric: compared as numbers, so `2.0` matches `max_players` 2 and `1.10` matches version 1.1.
        assert_eq!(filter_outcome(&filter("maxPlayers", "2.0"), &props), FilterOutcome::Match);
        assert_eq!(filter_outcome(&filter("players", "2"), &props), FilterOutcome::Mismatch);
        assert_eq!(filter_outcome(&filter("version", "1.10"), &props), FilterOutcome::Match);
        // Summary fields: name (case-insensitive) and joinable (GDAT `J` letter).
        assert_eq!(filter_outcome(&filter("NAME", "GAME 5"), &props), FilterOutcome::Match);
        assert_eq!(filter_outcome(&filter("joinable", "o"), &props), FilterOutcome::Match);
        // Unmatched name: no counterpart, which the caller logs and treats as matching.
        assert_eq!(filter_outcome(&filter("difficulty", "hard"), &props), FilterOutcome::NoCounterpart);
    }

    #[test]
    fn pnow_error_and_before_login() {
        let mut r = rig();
        r.hello();
        r.send(&req(b"pnow", 2, "TXN=Start\npartition.partition=/eagames/MERCS2\n"));
        assert!(text(&r.frames()[0]).contains("localizedMessage=\"pnow Start before acct Login\""));
        logged_in(&mut r);
        r.send(&req(b"pnow", 4, "TXN=Start\npartition.partition=/eagames/MERCS2\n"));
        r.frames();
        let (id, _) = r.provider.lobby.last();
        r.provider.lobby.reply(id, Err(ApiError::new(ErrorCode::InvalidField, "room_key: must be 6-32 ASCII letters, digits or '-'")));
        r.a.pump(r.now).unwrap();
        assert_eq!(
            text(&r.frames()[0]),
            "TXN=Status\nid.id=1\nid.partition=/eagames/MERCS2\nsessionState=ERROR\n\
             props.{reasonString}=\"InvalidField: room_key: must be 6-32 ASCII letters, digits or '-'\"\n\0"
        );
    }

    #[test]
    fn login_bad_credentials_maps_to_101() {
        let mut r = rig();
        r.hello();
        r.send(&req(b"acct", 4, "TXN=Login\nreturnEncryptedInfo=0\nname=Mattias\npassword=wrongpassword\n"));
        let job = r.a.backend.submitted[0].0;
        r.a.backend.ready.push((job, Err(BackendFailure::Api(ApiError::new(ErrorCode::BadCredentials, "wrong username or password")))));
        r.a.pump(r.now).unwrap();
        let f = r.frames();
        assert_eq!(text(&f[0]), "TXN=Login\nerrorCode=101\nlocalizedMessage=\"wrong username or password\"\n\0");
        assert!(r.session.lock().unwrap().is_none());
    }

    #[test]
    fn login_with_saved_encrypted_info_or_bad_fields_is_refused_locally() {
        let mut r = rig();
        r.hello();
        r.send(&req(b"acct", 2, "TXN=Login\nreturnEncryptedInfo=1\nencryptedInfo=abcdef\nmacAddr=$00\n"));
        r.send(&req(b"acct", 3, "TXN=Login\nreturnEncryptedInfo=0\nname=ab\npassword=longenough\n"));
        assert!(r.a.backend.submitted.is_empty());
        let f = r.frames();
        assert_eq!(f.len(), 2);
        assert!(text(&f[0]).starts_with(&format!("TXN=Login\nerrorCode={GENERIC_ERROR_CODE}\nlocalizedMessage=")));
        assert!(text(&f[0]).contains("encryptedInfo"));
        assert!(text(&f[1]).contains("username: must be 3-31 characters"));
    }

    #[test]
    fn add_account_forwards_only_name_and_password() {
        let mut r = rig();
        r.hello();
        // Field list of the client's AddAccount builder (FUN_0097d660).
        r.send(&req(
            b"acct",
            5,
            "TXN=AddAccount\nname=newbie\npassword=longenough\nemail=a%40b.c\nDOBDay=1\nDOBMonth=2\nDOBYear=1990\n\
             zipCode=12345\ncountryCode=US\neaMailFlag=0\nthirdPartyMailFlag=0\n",
        ));
        let (job, sent) = r.a.backend.submitted[0].clone();
        assert_eq!(sent, BackendRequest::CreateAccount(CreateAccount { username: "newbie".into(), password: "longenough".into() }));
        assert!(r.log.text().contains("not forwarded: email, DOBDay, DOBMonth, DOBYear, zipCode, countryCode, eaMailFlag, thirdPartyMailFlag"));
        assert!(!r.log.text().contains("12345"));
        r.a.backend.ready.push((job, Ok(BackendReply::AccountCreated(AccountCreated { user_id: UserId(7), username: "newbie".into() }))));
        r.a.pump(r.now).unwrap();
        let f = r.frames();
        assert_eq!((f[0].id, text(&f[0])), (0x8000_0005, "TXN=AddAccount\n\0".into()));

        r.send(&req(b"acct", 6, "TXN=AddAccount\nname=newbie\npassword=longenough\n"));
        let job = r.a.backend.submitted[1].0;
        r.a.backend.ready.push((job, Err(BackendFailure::Api(ApiError::new(ErrorCode::NameTaken, "username taken")))));
        r.a.pump(r.now).unwrap();
        let f = r.frames();
        assert_eq!(text(&f[0]), format!("TXN=AddAccount\nerrorCode={GENERIC_ERROR_CODE}\nlocalizedMessage=\"username taken\"\n\0"));
    }

    #[test]
    fn transport_failure_is_fatal_for_the_connection() {
        let mut r = rig();
        r.hello();
        r.send(&req(b"acct", 2, "TXN=Login\nname=Mattias\npassword=longenough\n"));
        let job = r.a.backend.submitted[0].0;
        r.a.backend.ready.push((job, Err(BackendFailure::Transport("TLS handshake with x failed: certificate verify failed".into()))));
        let e = r.a.pump(r.now).unwrap_err();
        assert!(e.to_string().contains("certificate verify failed"), "{e}");
    }

    #[test]
    fn unimplemented_txn_gets_a_named_error() {
        let mut r = rig();
        r.hello();
        r.send(&req(b"rank", 3, "TXN=GetRankedStats\nowner=1\n"));
        let f = r.frames();
        assert_eq!(f[0].kind, Kind::new(b"rank"));
        assert!(text(&f[0]).contains("errorCode=99\nlocalizedMessage=\"rank GetRankedStats is not implemented"));
        assert!(r.log.text().contains("ERROR rank GetRankedStats is not implemented"));
    }

    #[test]
    fn request_before_hello_is_a_protocol_failure() {
        let mut r = rig();
        let e = r.a.on_game_bytes(&req(b"acct", 1, "TXN=GetTos\n"), r.now).unwrap_err();
        assert!(e.to_string().contains("before fsys Hello"));
    }

    #[test]
    fn multipart_client_request_is_reassembled() {
        use base64::Engine as _;
        let mut r = rig();
        r.hello();
        let text_req = "TXN=GetTos\ncountryCode=US\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(text_req);
        let pieces: Vec<&[u8]> = b64.as_bytes().chunks(8).collect();
        for (i, p) in pieces.iter().enumerate() {
            let mut t = TagFields::new();
            t.set_int("size", b64.len() as i64).unwrap();
            t.set_str("data", p).unwrap();
            r.send(&frame::encode(Kind::new(b"acct"), 0xF000_0000 | 11, &t.to_payload()).unwrap());
            if i + 1 < pieces.len() {
                assert!(r.frames().is_empty());
            }
        }
        let f = r.frames();
        assert_eq!((f[0].id, text(&f[0])), (0x8000_000b, "TXN=GetTos\ntos=\"Be excellent to each other.\"\n\0".into()));
    }

    #[test]
    fn large_reply_is_multipart_to_the_game() {
        let mut r = rig();
        // Small fragment size so the country list overflows it.
        r.send(&req(b"fsys", 1, "TXN=Hello\nfragmentSize=64\n"));
        r.frames();
        r.send(&req(b"acct", 2, "TXN=GetCountryList\n"));
        let f = r.frames();
        assert!(f.len() > 1);
        assert!(f.iter().all(|f| FeslId::decode(f.id) == FeslId { tid: 2, multipart: true }));
    }

    #[test]
    fn frame_split_across_sends_is_handled() {
        let mut r = rig();
        let bytes = req(b"fsys", 1, "TXN=Hello\nfragmentSize=8096\n");
        r.send(&bytes[..7]);
        assert!(r.frames().is_empty());
        r.send(&bytes[7..]);
        assert_eq!(r.frames().len(), 2);
    }
}
