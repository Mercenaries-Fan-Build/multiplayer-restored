//! The Theater service, answered in-process (the virtual connection at the advertised loopback endpoint).
//!
//! Frames are the 12-byte ProtoAries frame with TagField text; client requests carry `TID` and the reply
//! echoes it (appended last); a reply's id word is its error code, 0 = OK (`mercs2_plasma_proto::theater`). Field
//! lists are `docs/reverse_engineer/multiplayer_txn_catalogue.md` §2; reply shapes copy the exe's own LAN
//! Theater emulator where one exists (GDAT/GDET/PDAT `FUN_00996ee0`/`FUN_0099eca0`, LDAT `FUN_0099e240`,
//! GLST `FUN_009a8f00`, CGAM `FUN_009aa020`, EGAM `FUN_0099efe0`, EGEG `FUN_0099ca30`/`FUN_0099cae0`, EGRQ
//! `FUN_009aa140`, KICK `FUN_0099cca0`, GREM `FUN_0099ccf0`).
//!
//! | 4CC | handling |
//! |---|---|
//! | CONN | reply `activityTimeoutSecs` (the only key the client reads); starts the PING keepalive push |
//! | USER | `LKEY` must be the one the FESL Login reply issued; reply `NAME` |
//! | PING | reply `PING` |
//! | PING, id 0 | the game's answer to our keepalive push; dumped raw to the log, no reply; without a push outstanding the connection fails |
//! | LLST | reply `NUM-LOBBIES=1`, then one LDAT (`LID`, `NAME`) — the server has one game namespace |
//! | GLST | `games.list` (current room key) → reply `LID NUM-GAMES LOBBY-MAX-GAMES LOBBY-NUM-GAMES`, one GDAT per game |
//! | GDAT | `LID`+`GID` form: `games.get` → GDAT, GDET, one PDAT per player; not found → id `'ngam'` |
//! | CGAM | `games.create` (room key from the store, `friends_only` false) → relay session → reply `LID GID MAX-PLAYERS JOIN SECRET UGID EKEY` |
//! | UGAM / UGDE | `games.update`; no reply |
//! | UPLA | logged, not forwarded: the server API has no per-player attributes; no reply |
//! | UBRA | reply `TID` only |
//! | EGAM (host, own game) | answered here, not by the server: reply `LID GID`, then EGRQ for the host's own PID (no address) ([`SelfEntry`]) |
//! | EGRS (host, own PID) | reply `TID`, then EGEG `LID GID PID TICKET UGID EKEY` (no address), whatever `ALLOWED` says |
//! | PENT (host, own PID) | after its own entry: reply `PID`, not forwarded (LAN `FUN_0099cc60` only echoes `PID`) |
//! | EGAM | `games.join` → reply `LID GID` once the server queued the request; not found → `'ngam'`, full → `'jden'` `REASON=f`, closed → `'jden'` `REASON=c` |
//! | push join.request | (host) alias for the joiner's slot → EGRQ; while a joiner is already in or awaiting the host's answer: `join.respond` denied `mesh_unsupported`, logged, nothing to the game |
//! | EGRS | (host) `join.respond` (denial: `host_denied` with the game's integer `REASON`) → reply `TID` |
//! | push join.accepted / join.denied | (joiner) more than 2 players → connection fails; else relay session + alias for the host → EGEG / EGEG `'jden'`+`REASON` ([`game_reason`]) |
//! | PENT | (host) `players.enter` → reply `PID` |
//! | PLVT | (host) `players.leave` for that PID → reply `TID` (LAN `FUN_009a10a0`) |
//! | ECNL | (joiner) `players.leave` for itself → reply `LID GID` |
//! | RGAM | (host) `games.close` → reply `LID GID` |
//! | push game.kicked / game.removed | KICK `LID GID PID` / GREM `LID GID`; relay session ends |
//!
//! PIDs: the server assigns the joiner's PID with the join request, so EGRQ (host) and EGEG (joiner) carry
//! the same PID, as in the LAN emulator. `TICKET` is `0x<join id>` on both sides (the LAN emulator prints its
//! ticket with `0x%x`, `DAT_00ba8ad8`). Peer addresses are the relay shim's loopback aliases, given as both
//! the external and the internal pair; `PL=PC` (the client only compares `PL` with `xbox`/`xbox360`).
//!
//! Players: this ASI links only host↔joiner (no joiner↔joiner relay mesh), so it supports games of at most
//! [`MAX_PLAYERS`]: the host refuses a second joiner and the joiner refuses an acceptance reporting more players.
//!
//! Anything else — an unknown 4CC, a request without `TID`, a field the game always sends missing, a server
//! answer that does not fit, a lobby or relay that ended — fails the connection with a named reason, which
//! the game sees as a Theater disconnect.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mercs2_mp_api::ws::{
    CreateGame, GameDetail, GameSummary, JoinAccepted, JoinDenyReason, Joinability, Privacy, Push, Request, Response,
    UpdateGame, UserRef,
};
use mercs2_mp_api::{ApiError, ErrorCode, GameId, UserId, rules};
use mercs2_plasma_proto::frame::{FrameDecoder, Kind};
use mercs2_plasma_proto::tagfield::{TagFieldReader, TagFields};
use mercs2_plasma_proto::theater;

use crate::lobby::{Lobby, LobbyEvent, describe};
use crate::log::Logger;
use crate::relay::{PeerAddr, RelayFactory, RelayLink, RelayState};
use crate::room_key::RoomKeyStore;
use crate::session::LoggedIn;

/// The one lobby the ASI presents (LLST/LDAT/GLST `LID`, every game's `LID`). The LAN emulator uses −2
/// for its own lobby; any other value works for an online lobby.
pub const LOBBY_ID: i64 = 1;

/// `PL` sent in EGEG; the client only special-cases `xbox`/`xbox360` (`FUN_0097c420`).
const PLATFORM: &str = "PC";

const NO_SUCH_GAME: Kind = Kind::new(b"ngam");
const JOIN_DENIED: Kind = Kind::new(b"jden");
/// LAN emulator's CGAM answer to a non-zero `QLEN` (`FUN_009aa020`): queues are not supported.
const BAD_PARAMETER: Kind = Kind::new(b"bpar");

/// Players a game may hold with this ASI: the relay shim links the host with each joiner but joiners not with
/// each other, so a third player would reach the host and not the other joiner.
pub const MAX_PLAYERS: u8 = 2;

/// `REASON` letters the game's EGEG/QENT parsers map (`FUN_00981490`, `FUN_00974090`): `f` → 0 and `c` → 2.
/// The LAN emulator answers its own EGAM refusals with exactly these two (`FUN_0099efe0`); 2 is the code of the
/// host's "game is closed" gate (`FUN_0098fc80`). Reading `f` as "full" is inferred from the letter and that
/// pairing (`docs/reverse_engineer/multiplayer_rewrite_re.md`, join-deny reasons).
const REASON_FULL: &str = "f";
const REASON_CLOSED: &str = "c";

/// The `REASON` the joiner's game gets for a denial. A host's own denial is relayed as its integer, as the
/// LAN emulator does (`FUN_009a0e80` → `FUN_0099cae0`); the others use the letters above.
fn game_reason(r: JoinDenyReason, t: &mut TagFields) -> R {
    match r {
        JoinDenyReason::HostDenied { code } => t.set_int("REASON", code.into()),
        JoinDenyReason::MeshUnsupported => t.set_str("REASON", REASON_FULL),
        JoinDenyReason::GameRemoved => t.set_str("REASON", REASON_CLOSED),
    }
    .map_err(tf)?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct TheaterSettings {
    pub activity_timeout_secs: u32,
    pub keepalive: Duration,
    pub lobby_name: String,
    /// How long an orderly relay close may go unexplained by the lobby before the connection fails.
    pub relay_close_grace: Duration,
}

type R = Result<(), String>;

enum Pend {
    Glst { tid: i64, count: Option<usize> },
    Gdat { tid: i64, gid: i64 },
    Cgam { tid: i64, tunnel_port: u16, join: String, max_players: u8 },
    Egam { tid: i64, gid: i64, tunnel_port: u16 },
    Egrs { tid: i64, pid: u32, allowed: bool },
    /// The host's ASI denying a join the game was never shown (no relay mesh for a second joiner).
    MeshDeny { join_id: u64 },
    Pent { tid: i64, pid: u32 },
    Plvt { tid: i64, pid: u32 },
    Ecnl { tid: i64, gid: i64 },
    Rgam { tid: i64, gid: i64 },
    Update { what: &'static str },
}

#[derive(Clone, Debug)]
struct Member {
    join_id: u64,
    user: UserRef,
    slot: u8,
}

enum Role {
    /// `waiting`: join requests sent to the game as EGRQ, by PID; `players`: accepted joiners by PID.
    /// `self_entry`: the host's game entering its own game; `ugid`/`ekey`: the CGAM answer's, for that EGEG.
    Host { waiting: HashMap<u32, Member>, players: HashMap<u32, Member>, self_entry: SelfEntry, ugid: String, ekey: String },
    Joiner,
}

/// The host's own entry handshake. Right after its CGAM is answered the game sends EGAM for the game it
/// created, then expects EGRQ for itself, answers EGRS, and expects EGEG — the exe's LAN Theater emulator
/// answers that case locally (`FUN_009ab0e0` own-game branch → EGAM reply + EGRQ `FUN_009aa140`;
/// `FUN_009a0e80` requester-is-this-machine branch → EGEG `FUN_0099ca30`), and so does this ASI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelfEntry {
    NotRequested,
    /// EGRQ for the host's own PID sent; its EGRS not yet seen.
    Requested,
    Entered,
}

struct InGame {
    game_id: GameId,
    pid: u32,
    role: Role,
    relay: Box<dyn RelayLink>,
    /// When this adapter first saw the relay's orderly close.
    relay_closed_at: Option<Instant>,
}

struct Joining {
    game_id: GameId,
    join_id: Option<u64>,
    tunnel_port: u16,
}

pub struct TheaterAdapter {
    settings: Arc<TheaterSettings>,
    lobby: Box<dyn Lobby>,
    session: LoggedIn,
    room_keys: RoomKeyStore,
    relays: Arc<dyn RelayFactory>,
    log: Logger,
    decoder: FrameDecoder,
    out: VecDeque<u8>,
    pending: HashMap<u64, Pend>,
    keepalive_due: Option<Instant>,
    /// Keepalive PINGs pushed to the game and not yet answered (the game answers each with a PING of id 0).
    pings_unanswered: u32,
    joining: Option<Joining>,
    game: Option<InGame>,
}

fn kind_name(k: Kind) -> String {
    k.as_str().map(str::to_owned).unwrap_or_else(|| format!("{:#010x}", k.as_u32()))
}

fn ticket(join_id: u64) -> String {
    format!("0x{join_id:x}")
}

fn joinability(c: Joinability) -> &'static str {
    match c {
        Joinability::Open => "O",
        Joinability::Wait => "W",
        Joinability::Closed => "C",
    }
}

/// `JOIN` as the client's own CGAM-reply parser reads it (`FUN_0097b9b0`): `C` closed, `W` wait, anything
/// else open.
fn parse_join(v: &str) -> Joinability {
    match v.as_bytes().first() {
        Some(b'C') => Joinability::Closed,
        Some(b'W') => Joinability::Wait,
        _ => Joinability::Open,
    }
}

fn tf(e: mercs2_plasma_proto::TagFieldError) -> String {
    format!("Theater TagField: {e}")
}

struct Req<'a> {
    kind: Kind,
    r: TagFieldReader<'a>,
}

impl Req<'_> {
    fn name(&self) -> String {
        kind_name(self.kind)
    }
    fn int(&self, key: &str) -> Result<Option<i64>, String> {
        self.r.get_int(key).map_err(tf)
    }
    fn str(&self, key: &str) -> Result<Option<String>, String> {
        self.r.get_str(key).map_err(tf)
    }
    fn need_int(&self, key: &str) -> Result<i64, String> {
        self.int(key)?.ok_or_else(|| format!("{} without {key}", self.name()))
    }
    fn need_str(&self, key: &str) -> Result<String, String> {
        self.str(key)?.ok_or_else(|| format!("{} without {key}", self.name()))
    }
    fn port(&self, key: &str) -> Result<u16, String> {
        let v = self.need_int(key)?;
        u16::try_from(v).ok().filter(|p| *p != 0).ok_or_else(|| format!("{} {key}={v} is not a UDP port", self.name()))
    }
    fn pid(&self) -> Result<u32, String> {
        let v = self.need_int("PID")?;
        u32::try_from(v).map_err(|_| format!("{} PID={v} is out of range", self.name()))
    }
    /// Every field as `KEY=value`, in the request's order, for the log.
    fn text(&self) -> Result<String, String> {
        let mut parts = Vec::new();
        for k in self.r.keys().map_err(tf)? {
            parts.push(format!("{k}={}", self.str(&k)?.unwrap_or_default()));
        }
        Ok(parts.join(" "))
    }
    /// Every `<prefix>*` key with its value.
    fn prefixed(&self, prefix: &str) -> Result<BTreeMap<String, String>, String> {
        let mut m = BTreeMap::new();
        for k in self.r.keys().map_err(tf)? {
            if k.starts_with(prefix) && k.len() > prefix.len() {
                let v = self
                    .str(&k)?
                    .ok_or_else(|| format!("{} lists key {k} but its value cannot be read", self.name()))?;
                m.insert(k, v);
            }
        }
        Ok(m)
    }
}

impl TheaterAdapter {
    pub fn new(
        settings: Arc<TheaterSettings>,
        lobby: Box<dyn Lobby>,
        session: LoggedIn,
        room_keys: RoomKeyStore,
        relays: Arc<dyn RelayFactory>,
        log: Logger,
    ) -> Self {
        TheaterAdapter {
            settings,
            lobby,
            session,
            room_keys,
            relays,
            log,
            decoder: FrameDecoder::new(theater::MAX_FRAME),
            out: VecDeque::new(),
            pending: HashMap::new(),
            keepalive_due: None,
            pings_unanswered: 0,
            joining: None,
            game: None,
        }
    }

    pub fn outbound(&mut self) -> &mut VecDeque<u8> {
        &mut self.out
    }

    fn send(&mut self, kind: Kind, code: u32, t: &TagFields, tid: Option<i64>) -> R {
        let bytes = theater::encode(kind, code, t, tid).map_err(|e| format!("encoding {}: {e}", kind_name(kind)))?;
        self.out.extend(bytes);
        Ok(())
    }

    fn reply(&mut self, kind: Kind, tid: i64, t: &TagFields) -> R {
        self.send(kind, theater::OK, t, Some(tid))
    }

    fn error_reply(&mut self, kind: Kind, code: Kind, tid: i64, t: &TagFields) -> R {
        self.send(kind, code.as_u32(), t, Some(tid))
    }

    fn submit(&mut self, req: Request, pend: Pend) -> R {
        let what = describe(&req);
        let id = self.lobby.request(req).map_err(|e| format!("lobby request {what}: {e}"))?;
        self.log.info(format!("Theater → lobby #{id}: {what}"));
        self.pending.insert(id, pend);
        Ok(())
    }

    fn room_key(&self) -> Result<Option<String>, String> {
        self.room_keys.get()
    }

    /// Bytes from the game's Send.
    pub fn on_game_bytes(&mut self, bytes: &[u8], now: Instant) -> R {
        self.decoder.feed(bytes);
        while let Some(f) = self.decoder.next_frame().map_err(|e| format!("Theater framing: {e}"))? {
            // The client's Theater id encoder (`0x970600`) writes 0x40000000 or 0, by a flag each send passes in:
            // CONN, USER, GLST, CGAM, EGAM, PENT, ... arrive with 0x40000000; UGAM and the keepalive answer with 0.
            if f.id != theater::CLIENT_REQUEST_ID {
                if f.id != theater::OK {
                    return Err(format!(
                        "{} frame with id {:#x}; the client's Theater encoder (0x970600) writes only {:#x} or 0",
                        kind_name(f.kind),
                        f.id,
                        theater::CLIENT_REQUEST_ID
                    ));
                }
                // Raw dump of every id-0 frame, before it is handled.
                self.log.info(format!(
                    "Theater {} frame from the game with id 0x0: {} payload bytes, hex {}, text {:?}",
                    kind_name(f.kind),
                    f.payload.len(),
                    crate::fesl::hex(&f.payload),
                    String::from_utf8_lossy(&f.payload)
                ));
                // The game's answer to our keepalive push.
                if f.kind == Kind::new(b"PING") && self.pings_unanswered > 0 {
                    self.pings_unanswered -= 1;
                    continue;
                }
            }
            let req = Req { kind: f.kind, r: TagFieldReader::new(&f.payload) };
            let tid = req.int("TID")?.ok_or_else(|| format!("{} without TID", req.name()))?;
            self.dispatch(&req, tid, now)?;
        }
        Ok(())
    }

    /// Deliver lobby replies/pushes, check the relay, push keepalives. Call from Update/Recv.
    pub fn pump(&mut self, now: Instant) -> R {
        for ev in self.lobby.poll().map_err(|e| format!("lobby: {e}"))? {
            match ev {
                LobbyEvent::Reply { id, result } => {
                    let pend = self.pending.remove(&id).ok_or_else(|| format!("lobby reply #{id} matches no Theater request"))?;
                    self.complete(id, pend, result)?;
                }
                LobbyEvent::Push(p) => self.on_push(p)?,
            }
        }
        // After the lobby events: a game they ended no longer has a relay to check.
        if let Some(g) = self.game.as_mut() {
            match g.relay.state() {
                RelayState::Up => {}
                RelayState::Failed(why) => return Err(format!("relay: {why}")),
                RelayState::ClosedByRelay => {
                    let since = *g.relay_closed_at.get_or_insert(now);
                    if now.duration_since(since) > self.settings.relay_close_grace {
                        return Err(format!(
                            "relay: the relay closed the association for game {} and the lobby did not say why within {} ms",
                            g.game_id.0,
                            self.settings.relay_close_grace.as_millis()
                        ));
                    }
                }
            }
        }
        if let Some(due) = self.keepalive_due
            && now >= due
        {
            self.send(Kind::new(b"PING"), theater::OK, &TagFields::new(), None)?;
            self.pings_unanswered += 1;
            self.keepalive_due = Some(now + self.settings.keepalive);
        }
        Ok(())
    }

    fn hosted(&mut self, gid: i64, what: &str) -> Result<&mut InGame, String> {
        match self.game.as_mut() {
            Some(g) if g.game_id.0 == gid && matches!(g.role, Role::Host { .. }) => Ok(g),
            _ => Err(format!("{what} for game {gid}, which this client is not hosting")),
        }
    }

    fn dispatch(&mut self, q: &Req, tid: i64, now: Instant) -> R {
        let mut t = TagFields::new();
        match &q.kind.0 {
            b"CONN" => {
                self.log.info(format!(
                    "Theater CONN: PROT={:?} PROD={:?} VERS={:?} PLAT={:?} SDKVERSION={:?}",
                    q.str("PROT")?.unwrap_or_default(),
                    q.str("PROD")?.unwrap_or_default(),
                    q.str("VERS")?.unwrap_or_default(),
                    q.str("PLAT")?.unwrap_or_default(),
                    q.str("SDKVERSION")?.unwrap_or_default()
                ));
                t.set_int("activityTimeoutSecs", self.settings.activity_timeout_secs.into()).map_err(tf)?;
                self.reply(q.kind, tid, &t)?;
                self.keepalive_due = Some(now + self.settings.keepalive);
            }
            b"USER" => {
                let lkey = q.need_str("LKEY")?;
                if lkey != self.session.lkey {
                    return Err("Theater USER LKEY is not the lkey this session's FESL Login issued".into());
                }
                t.set_str("NAME", &self.session.display_name).map_err(tf)?;
                self.reply(q.kind, tid, &t)?;
            }
            b"PING" => self.reply(q.kind, tid, &t)?,
            b"LLST" => {
                t.set_int("NUM-LOBBIES", 1).map_err(tf)?;
                self.reply(q.kind, tid, &t)?;
                let mut l = TagFields::new();
                l.set_str("NAME", &self.settings.lobby_name).map_err(tf)?;
                l.set_int("LID", LOBBY_ID).map_err(tf)?;
                self.reply(Kind::new(b"LDAT"), tid, &l)?;
            }
            b"GLST" => {
                let lid = q.need_int("LID")?;
                if lid != LOBBY_ID {
                    return Err(format!("GLST for lobby {lid}; this client presents only lobby {LOBBY_ID}"));
                }
                let flag = |k: &str| -> Result<bool, String> { Ok(q.int(k)? == Some(1)) };
                let joinable_only = flag("FILTER-NOT-FULL")? || flag("FILTER-NOT-CLOSED")?;
                let count = q.int("COUNT")?.filter(|c| *c > 0).map(|c| c as usize);
                let ignored: Vec<String> = q
                    .r
                    .keys()
                    .map_err(tf)?
                    .into_iter()
                    .filter(|k| (k.starts_with("FILTER-") || k.starts_with("FAV-")) && k != "FILTER-NOT-FULL" && k != "FILTER-NOT-CLOSED")
                    .collect();
                if !ignored.is_empty() {
                    self.log.info(format!("GLST filters not applied by the server: {}", ignored.join(", ")));
                }
                let room_key = self.room_key()?;
                self.submit(Request::GamesList { joinable_only, room_key }, Pend::Glst { tid, count })?;
            }
            b"GDAT" => {
                let gid = match (q.int("LID")?, q.int("GID")?) {
                    (Some(_), Some(gid)) => gid,
                    _ => {
                        // USER+TYPE / UID+TYPE forms look a game up by player; the server API has none.
                        self.log.error(format!(
                            "GDAT by player (USER={:?} UID={:?}) is not supported: the server API looks games up by id only",
                            q.str("USER")?,
                            q.int("UID")?
                        ));
                        return self.error_reply(q.kind, NO_SUCH_GAME, tid, &t);
                    }
                };
                let room_key = self.room_key()?;
                self.submit(Request::GamesGet { game_id: GameId(gid), room_key }, Pend::Gdat { tid, gid })?;
            }
            b"CGAM" => self.cgam(q, tid)?,
            b"UGAM" => {
                let gid = q.need_int("GID")?;
                self.hosted(gid, "UGAM")?;
                let max_players = match q.int("MAX-PLAYERS")? {
                    Some(m) => Some(u8::try_from(m).map_err(|_| format!("UGAM MAX-PLAYERS={m} is out of range"))?),
                    None => None,
                };
                let attrs = q.prefixed("B-U-")?;
                let upd = UpdateGame {
                    game_id: GameId(gid),
                    name: q.str("NAME")?,
                    max_players,
                    joinable: q.str("JOIN")?.map(|j| parse_join(&j)),
                    attrs: (!attrs.is_empty()).then_some(attrs),
                    details: None,
                };
                self.submit(Request::GamesUpdate(upd), Pend::Update { what: "UGAM" })?;
            }
            b"UGDE" => {
                let gid = q.need_int("GID")?;
                self.hosted(gid, "UGDE")?;
                let upd = UpdateGame {
                    game_id: GameId(gid),
                    name: None,
                    max_players: None,
                    joinable: None,
                    attrs: None,
                    details: Some(q.prefixed("D-")?),
                };
                self.submit(Request::GamesUpdate(upd), Pend::Update { what: "UGDE" })?;
            }
            b"UPLA" => {
                let attrs = q.prefixed("P-")?;
                self.log.info(format!(
                    "UPLA PID={:?}: player attributes {:?} are not forwarded (the server API has no per-player attributes)",
                    q.int("PID")?,
                    attrs.keys().collect::<Vec<_>>()
                ));
            }
            b"UBRA" => self.reply(q.kind, tid, &t)?,
            b"EGAM" => {
                let gid = q.need_int("GID")?;
                if self.game.as_ref().is_some_and(|g| g.game_id.0 == gid && matches!(g.role, Role::Host { .. })) {
                    return self.self_enter(q, tid, gid);
                }
                if self.game.is_some() || self.joining.is_some() {
                    return Err(format!("EGAM for game {gid} while already in or joining a game"));
                }
                let tunnel_port = q.port("PORT")?;
                self.joining = Some(Joining { game_id: GameId(gid), join_id: None, tunnel_port });
                let room_key = self.room_key()?;
                self.submit(Request::GamesJoin { game_id: GameId(gid), room_key }, Pend::Egam { tid, gid, tunnel_port })?;
            }
            b"EGRS" => {
                let gid = q.need_int("GID")?;
                let pid = q.pid()?;
                let g = self.hosted(gid, "EGRS")?;
                if g.pid == pid && matches!(g.role, Role::Host { self_entry: SelfEntry::Requested, .. }) {
                    return self.self_entered(q, tid, gid);
                }
                let allowed = q.need_int("ALLOWED")? == 1;
                // The builder `FUN_0097b380` writes REASON with `%d`, only when denying.
                let reason = if allowed {
                    None
                } else {
                    let v = q.need_int("REASON")?;
                    let code = i32::try_from(v).map_err(|_| format!("EGRS REASON={v} is not a 32-bit integer"))?;
                    Some(JoinDenyReason::HostDenied { code })
                };
                let g = self.hosted(gid, "EGRS")?;
                let Role::Host { waiting, .. } = &g.role else { unreachable!("hosted() checked the role") };
                let m = waiting.get(&pid).ok_or_else(|| format!("EGRS for PID {pid}, which has no pending join request"))?;
                let join_id = m.join_id;
                self.submit(Request::JoinRespond { join_id, allowed, reason }, Pend::Egrs { tid, pid, allowed })?;
            }
            b"PENT" => {
                let gid = q.need_int("GID")?;
                let pid = q.pid()?;
                let g = self.hosted(gid, "PENT")?;
                let Role::Host { players, self_entry, .. } = &g.role else { unreachable!("hosted() checked the role") };
                if pid == g.pid {
                    // The host reporting itself entered, after its own EGEG. The LAN emulator's PENT handler
                    // (`FUN_0099cc60`) only echoes `PID`; the server's players.enter is for accepted joiners.
                    if *self_entry != SelfEntry::Entered {
                        return Err(format!("PENT for the host's own PID {pid} before its entry completed ({self_entry:?})"));
                    }
                    t.set_int("PID", pid.into()).map_err(tf)?;
                    self.reply(q.kind, tid, &t)?;
                    self.log.info(format!("game {gid}: the host reported itself entered (PENT PID {pid})"));
                    return Ok(());
                }
                let user = players.get(&pid).ok_or_else(|| format!("PENT for PID {pid}, which is not an accepted player"))?.user.user_id;
                self.submit(Request::PlayerEntered { game_id: GameId(gid), user_id: user }, Pend::Pent { tid, pid })?;
            }
            b"PLVT" => {
                let gid = q.need_int("GID")?;
                let pid = q.pid()?;
                let g = self.hosted(gid, "PLVT")?;
                let Role::Host { players, .. } = &g.role else { unreachable!("hosted() checked the role") };
                let user = players.get(&pid).ok_or_else(|| format!("PLVT for PID {pid}, which is not a player"))?.user.user_id;
                self.submit(Request::PlayerLeft { game_id: GameId(gid), user_id: user }, Pend::Plvt { tid, pid })?;
            }
            b"ECNL" => {
                let gid = q.need_int("GID")?;
                let in_it = self.game.as_ref().is_some_and(|g| g.game_id.0 == gid) || self.joining.as_ref().is_some_and(|j| j.game_id.0 == gid);
                if !in_it {
                    return Err(format!("ECNL for game {gid}, which this client is neither in nor joining"));
                }
                let me = self.session.user_id;
                self.submit(Request::PlayerLeft { game_id: GameId(gid), user_id: me }, Pend::Ecnl { tid, gid })?;
            }
            b"RGAM" => {
                let gid = q.need_int("GID")?;
                self.hosted(gid, "RGAM")?;
                self.submit(Request::GamesClose { game_id: GameId(gid) }, Pend::Rgam { tid, gid })?;
            }
            _ => return Err(format!("Theater {} is not implemented by multiplayer_restored {}", q.name(), crate::ASI_VERSION)),
        }
        Ok(())
    }

    fn cgam(&mut self, q: &Req, tid: i64) -> R {
        if self.game.is_some() || self.joining.is_some() {
            return Err("CGAM while already in or joining a game".into());
        }
        if q.r.contains("PASSWORD") {
            return Err("CGAM with PASSWORD: the shell UI has no password option, and games are private by room key".into());
        }
        let qlen = q.int("QLEN")?.unwrap_or(0);
        if qlen > 0 {
            self.log.error(format!("CGAM QLEN={qlen}: join queues are not supported; answered 'bpar' like the LAN emulator"));
            return self.error_reply(q.kind, BAD_PARAMETER, tid, &TagFields::new());
        }
        let max = q.need_int("MAX-PLAYERS")?;
        let max_players = u8::try_from(max).ok().filter(|m| *m > 0).ok_or_else(|| format!("CGAM MAX-PLAYERS={max} is out of range"))?;
        let join = q.str("JOIN")?.unwrap_or_else(|| "O".into());
        let create = CreateGame {
            name: q.need_str("NAME")?,
            max_players,
            version: q.need_str("B-version")?,
            joinable: parse_join(&join),
            attrs: q.prefixed("B-U-")?,
            privacy: Privacy { room_key: self.room_key()?, friends_only: false },
        };
        let tunnel_port = q.port("PORT")?;
        self.submit(Request::GamesCreate(create), Pend::Cgam { tid, tunnel_port, join, max_players })
    }

    /// The host's EGAM for the game it hosts. Answered here, not by the server (which already counts the host
    /// in its game): EGAM reply `LID GID`, then EGRQ for the host's own PID with the fields of the LAN
    /// emulator's EGRQ (`FUN_009aa140`: `LID GID NAME UID PID TICKET PTYPE`, no address in either of its paths).
    fn self_enter(&mut self, q: &Req, tid: i64, gid: i64) -> R {
        self.log.info(format!("Theater EGAM from the host for its own game {gid}: {}", q.text()?));
        let (name, uid) = (self.session.display_name.clone(), self.session.user_id.0);
        let g = self.hosted(gid, "EGAM")?;
        let Role::Host { self_entry, .. } = &mut g.role else { unreachable!("hosted() checked the role") };
        if *self_entry != SelfEntry::NotRequested {
            return Err(format!("EGAM from the host for its own game {gid} again (entry already {self_entry:?})"));
        }
        *self_entry = SelfEntry::Requested;
        let pid = g.pid;
        let t = Self::lid_gid(gid)?;
        self.reply(q.kind, tid, &t)?;
        // TICKET: the LAN emulator prints the host machine's id with `0x%x`; the user id is this design's.
        let ticket_id = u64::try_from(uid).map_err(|_| format!("user id {uid} cannot be a TICKET"))?;
        let mut t = Self::lid_gid(gid)?;
        t.set_str("NAME", &name).map_err(tf)?;
        t.set_int("UID", uid).map_err(tf)?;
        t.set_int("PID", pid.into()).map_err(tf)?;
        t.set_str("TICKET", ticket(ticket_id)).map_err(tf)?;
        t.set_str("PTYPE", "P").map_err(tf)?;
        self.send(Kind::new(b"EGRQ"), theater::OK, &t, None)?;
        self.log.info(format!("game {gid}: the host's own entry requested (EGRQ for PID {pid})"));
        Ok(())
    }

    /// The host's EGRS for its own entry: reply `TID`, then EGEG `LID GID PID TICKET UGID EKEY` with no address,
    /// as the LAN emulator's requester-is-this-machine branch (`FUN_009a0e80` → `FUN_0099ca30`), which sends it
    /// whatever `ALLOWED` says. UGID/EKEY: the LAN emulator has none and sends `NOGUID`/`NOENCYRPTIONKEY`; this
    /// game has the CGAM answer's, sent instead.
    fn self_entered(&mut self, q: &Req, tid: i64, gid: i64) -> R {
        let allowed = q.int("ALLOWED")?;
        let uid = self.session.user_id.0;
        let g = self.hosted(gid, "EGRS")?;
        let pid = g.pid;
        let Role::Host { self_entry, ugid, ekey, .. } = &mut g.role else { unreachable!("hosted() checked the role") };
        *self_entry = SelfEntry::Entered;
        let (ugid, ekey) = (ugid.clone(), ekey.clone());
        if allowed != Some(1) {
            self.log.warn(format!(
                "game {gid}: the host's game answered its own entry with ALLOWED={allowed:?}; entered regardless, as the LAN emulator does"
            ));
        }
        self.reply(q.kind, tid, &TagFields::new())?;
        let ticket_id = u64::try_from(uid).map_err(|_| format!("user id {uid} cannot be a TICKET"))?;
        let mut t = Self::lid_gid(gid)?;
        t.set_int("PID", pid.into()).map_err(tf)?;
        t.set_str("TICKET", ticket(ticket_id)).map_err(tf)?;
        t.set_str("UGID", &ugid).map_err(tf)?;
        t.set_str("EKEY", &ekey).map_err(tf)?;
        self.send(Kind::new(b"EGEG"), theater::OK, &t, None)?;
        self.log.info(format!("game {gid}: the host entered its own game as PID {pid}"));
        Ok(())
    }

    fn summary_fields(&self, s: &GameSummary) -> Result<TagFields, String> {
        let mut t = TagFields::new();
        for (k, v) in &s.attrs {
            t.set_str(k, v).map_err(tf)?;
        }
        t.set_int("LID", LOBBY_ID).map_err(tf)?;
        t.set_int("GID", s.game_id.0).map_err(tf)?;
        t.set_str("N", &s.name).map_err(tf)?;
        t.set_str("TYPE", "G").map_err(tf)?;
        t.set_int("MP", s.max_players.into()).map_err(tf)?;
        t.set_int("AP", s.players.into()).map_err(tf)?;
        t.set_int("JP", 0).map_err(tf)?;
        t.set_int("B-maxObservers", 0).map_err(tf)?;
        t.set_int("B-numObservers", 0).map_err(tf)?;
        t.set_str("HN", &s.host.name).map_err(tf)?;
        t.set_int("HU", s.host.user_id.0).map_err(tf)?;
        t.set_str("B-version", &s.version).map_err(tf)?;
        t.set_str("J", joinability(s.joinable)).map_err(tf)?;
        Ok(t)
    }

    fn send_detail(&mut self, tid: i64, d: &GameDetail) -> R {
        let gdat = self.summary_fields(&d.summary)?;
        self.reply(Kind::new(b"GDAT"), tid, &gdat)?;
        let mut gdet = TagFields::new();
        gdet.set_int("LID", LOBBY_ID).map_err(tf)?;
        gdet.set_int("GID", d.summary.game_id.0).map_err(tf)?;
        gdet.set_str("UGID", &d.ugid).map_err(tf)?;
        for (k, v) in &d.details {
            gdet.set_str(k, v).map_err(tf)?;
        }
        self.reply(Kind::new(b"GDET"), tid, &gdet)?;
        for p in &d.players {
            let mut pd = TagFields::new();
            pd.set_int("LID", LOBBY_ID).map_err(tf)?;
            pd.set_int("GID", d.summary.game_id.0).map_err(tf)?;
            pd.set_int("PID", p.pid.into()).map_err(tf)?;
            pd.set_str("NAME", &p.user.name).map_err(tf)?;
            pd.set_int("UID", p.user.user_id.0).map_err(tf)?;
            for (k, v) in &p.attrs {
                pd.set_str(k, v).map_err(tf)?;
            }
            self.reply(Kind::new(b"PDAT"), tid, &pd)?;
        }
        Ok(())
    }

    fn lid_gid(gid: i64) -> Result<TagFields, String> {
        let mut t = TagFields::new();
        t.set_int("LID", LOBBY_ID).map_err(tf)?;
        t.set_int("GID", gid).map_err(tf)?;
        Ok(t)
    }

    fn complete(&mut self, id: u64, pend: Pend, result: Result<Response, ApiError>) -> R {
        let unexpected = |what: &str, r: &Result<Response, ApiError>| format!("lobby #{id} ({what}): unexpected answer {r:?}");
        match pend {
            Pend::Glst { tid, count } => {
                let Ok(Response::Games(mut games)) = result else { return Err(unexpected("GLST", &result)) };
                if let Some(c) = count {
                    games.truncate(c);
                }
                let n = games.len() as i64;
                let mut t = TagFields::new();
                t.set_int("LID", LOBBY_ID).map_err(tf)?;
                t.set_int("NUM-GAMES", n).map_err(tf)?;
                t.set_int("LOBBY-MAX-GAMES", n).map_err(tf)?;
                t.set_int("LOBBY-NUM-GAMES", n).map_err(tf)?;
                self.reply(Kind::new(b"GLST"), tid, &t)?;
                for g in &games {
                    let f = self.summary_fields(g)?;
                    self.reply(Kind::new(b"GDAT"), tid, &f)?;
                }
            }
            Pend::Gdat { tid, gid } => match result {
                Ok(Response::Game(d)) => self.send_detail(tid, &d)?,
                Err(e) if e.code == ErrorCode::NotFound => {
                    self.log.info(format!("GDAT game {gid}: not found or not visible with the current room key"));
                    self.error_reply(Kind::new(b"GDAT"), NO_SUCH_GAME, tid, &TagFields::new())?;
                }
                other => return Err(unexpected("GDAT", &other)),
            },
            Pend::Cgam { tid, tunnel_port, join, max_players } => {
                let Ok(Response::GameCreated(c)) = result else { return Err(unexpected("CGAM", &result)) };
                if c.ekey.len() > rules::EKEY_LEN || c.secret.len() > rules::SECRET_MAX || c.ugid.len() > rules::UGID_MAX {
                    return Err(format!("games.create answer does not fit the game's CGAM buffers (EKEY ≤{}, SECRET ≤{}, UGID ≤{})", rules::EKEY_LEN, rules::SECRET_MAX, rules::UGID_MAX));
                }
                let relay = self.relays.start(c.game_id, &c.relay, tunnel_port)?;
                self.game = Some(InGame {
                    game_id: c.game_id,
                    pid: c.pid,
                    role: Role::Host {
                        waiting: HashMap::new(),
                        players: HashMap::new(),
                        self_entry: SelfEntry::NotRequested,
                        ugid: c.ugid.clone(),
                        ekey: c.ekey.clone(),
                    },
                    relay,
                    relay_closed_at: None,
                });
                let mut t = Self::lid_gid(c.game_id.0)?;
                t.set_int("MAX-PLAYERS", max_players.into()).map_err(tf)?;
                t.set_str("JOIN", &join).map_err(tf)?;
                t.set_str("SECRET", &c.secret).map_err(tf)?;
                t.set_str("UGID", &c.ugid).map_err(tf)?;
                t.set_str("EKEY", &c.ekey).map_err(tf)?;
                self.reply(Kind::new(b"CGAM"), tid, &t)?;
                self.log.info(format!("hosting game {} (relay slot {})", c.game_id.0, c.relay.local_slot));
            }
            Pend::Egam { tid, gid, tunnel_port } => match result {
                Ok(Response::JoinPending { join_id }) => {
                    match self.joining.as_mut() {
                        Some(j) if j.game_id.0 == gid && j.tunnel_port == tunnel_port => j.join_id = Some(join_id),
                        _ => return Err(format!("EGAM answer for game {gid} without a matching join in progress")),
                    }
                    let t = Self::lid_gid(gid)?;
                    self.reply(Kind::new(b"EGAM"), tid, &t)?;
                    self.log.info(format!("join request {join_id} for game {gid} queued with the host"));
                }
                Err(e) if matches!(e.code, ErrorCode::NotFound | ErrorCode::GameFull | ErrorCode::GameClosed) => {
                    self.joining = None;
                    self.log.info(format!("EGAM game {gid}: {e}"));
                    let mut t = TagFields::new();
                    let code = match e.code {
                        ErrorCode::GameFull => {
                            t.set_str("REASON", REASON_FULL).map_err(tf)?;
                            JOIN_DENIED
                        }
                        ErrorCode::GameClosed => {
                            t.set_str("REASON", REASON_CLOSED).map_err(tf)?;
                            JOIN_DENIED
                        }
                        _ => NO_SUCH_GAME,
                    };
                    self.error_reply(Kind::new(b"EGAM"), code, tid, &t)?;
                }
                other => return Err(unexpected("EGAM", &other)),
            },
            Pend::Egrs { tid, pid, allowed } => {
                let g = self.game.as_mut().ok_or("EGRS answer after the game ended")?;
                let Role::Host { waiting, players, .. } = &mut g.role else { return Err("EGRS answer while not hosting".into()) };
                let m = waiting.remove(&pid).ok_or_else(|| format!("EGRS answer for PID {pid} with no pending join"))?;
                match result {
                    Ok(Response::Ok) if allowed => {
                        players.insert(pid, m);
                    }
                    Ok(Response::Ok) => g.relay.remove_peer(m.slot),
                    Err(e) if e.code == ErrorCode::NotFound => {
                        self.log.warn(format!("EGRS PID {pid}: the join request is gone (the joiner left first): {e}"));
                        g.relay.remove_peer(m.slot);
                    }
                    other => return Err(unexpected("EGRS", &other)),
                }
                self.reply(Kind::new(b"EGRS"), tid, &TagFields::new())?;
            }
            Pend::MeshDeny { join_id } => match result {
                Ok(Response::Ok) => self.log.info(format!("join request {join_id}: denied (mesh_unsupported)")),
                Err(e) if e.code == ErrorCode::NotFound => {
                    self.log.warn(format!("join request {join_id}: gone before the denial reached the server: {e}"))
                }
                other => return Err(unexpected("join.respond (mesh_unsupported)", &other)),
            },
            Pend::Pent { tid, pid } => {
                let Ok(Response::Ok) = result else { return Err(unexpected("PENT", &result)) };
                let mut t = TagFields::new();
                t.set_int("PID", pid.into()).map_err(tf)?;
                self.reply(Kind::new(b"PENT"), tid, &t)?;
            }
            Pend::Plvt { tid, pid } => {
                match result {
                    Ok(Response::Ok) => {}
                    Err(e) if e.code == ErrorCode::NotFound => self.log.warn(format!("PLVT PID {pid}: already gone on the server: {e}")),
                    other => return Err(unexpected("PLVT", &other)),
                }
                if let Some(g) = self.game.as_mut()
                    && let Role::Host { players, .. } = &mut g.role
                    && let Some(m) = players.remove(&pid)
                {
                    g.relay.remove_peer(m.slot);
                }
                // The LAN emulator answers PLVT with `TID` (`FUN_009a10a0`).
                self.reply(Kind::new(b"PLVT"), tid, &TagFields::new())?;
            }
            Pend::Ecnl { tid, gid } => {
                let Ok(Response::Ok) = result else { return Err(unexpected("ECNL", &result)) };
                self.end_game("left (ECNL)");
                let t = Self::lid_gid(gid)?;
                self.reply(Kind::new(b"ECNL"), tid, &t)?;
            }
            Pend::Rgam { tid, gid } => {
                let Ok(Response::Ok) = result else { return Err(unexpected("RGAM", &result)) };
                self.end_game("closed by the host (RGAM)");
                let t = Self::lid_gid(gid)?;
                self.reply(Kind::new(b"RGAM"), tid, &t)?;
            }
            Pend::Update { what } => {
                let Ok(Response::Ok) = result else { return Err(unexpected(what, &result)) };
            }
        }
        Ok(())
    }

    fn end_game(&mut self, why: &str) {
        if let Some(g) = self.game.take() {
            self.log.info(format!("game {}: {why}; relay session ends", g.game_id.0));
        }
        self.joining = None;
    }

    fn on_push(&mut self, p: Push) -> R {
        match p {
            Push::JoinRequest { join_id, game_id, user, slot, pid } => {
                let g = self.hosted(game_id.0, "join request push")?;
                let Role::Host { waiting, players, .. } = &g.role else { unreachable!("hosted() checked the role") };
                if let Some(other) = players.values().chain(waiting.values()).next().map(|m| m.user.name.clone()) {
                    self.log.error(format!(
                        "join request {join_id}: {:?} (user {}) denied: game {} already has a joiner ({:?}); \
                         this ASI links only host and joiner, with no joiner-to-joiner relay mesh, so games of more \
                         than {MAX_PLAYERS} players are unsupported",
                        user.name,
                        user.user_id.0,
                        game_id.0,
                        other
                    ));
                    let deny = Request::JoinRespond { join_id, allowed: false, reason: Some(JoinDenyReason::MeshUnsupported) };
                    return self.submit(deny, Pend::MeshDeny { join_id });
                }
                let peer = g.relay.add_peer(slot)?;
                let Role::Host { waiting, .. } = &mut g.role else { unreachable!("hosted() checked the role") };
                waiting.insert(pid, Member { join_id, user: user.clone(), slot });
                let mut t = Self::lid_gid(game_id.0)?;
                t.set_str("NAME", &user.name).map_err(tf)?;
                t.set_int("UID", user.user_id.0).map_err(tf)?;
                t.set_int("PID", pid.into()).map_err(tf)?;
                t.set_str("TICKET", ticket(join_id)).map_err(tf)?;
                set_peer(&mut t, "IP", "PORT", peer)?;
                set_peer(&mut t, "R-INT-IP", "R-INT-PORT", peer)?;
                t.set_str("PTYPE", "P").map_err(tf)?;
                self.send(Kind::new(b"EGRQ"), theater::OK, &t, None)?;
                self.log.info(format!("join request {join_id}: {:?} (user {}) asks to join game {}", user.name, user.user_id.0, game_id.0));
            }
            Push::JoinAccepted(a) => self.join_accepted(a)?,
            Push::JoinDenied { join_id, game_id, reason } => {
                match self.joining.take() {
                    Some(j) if j.game_id == game_id && j.join_id == Some(join_id) => {}
                    _ => return Err(format!("join.denied for request {join_id} (game {}) that this client did not make", game_id.0)),
                }
                self.log.info(format!("join request {join_id} for game {} denied: {reason:?}", game_id.0));
                let mut t = Self::lid_gid(game_id.0)?;
                game_reason(reason, &mut t)?;
                self.send(Kind::new(b"EGEG"), JOIN_DENIED.as_u32(), &t, None)?;
            }
            Push::PlayerLeft { game_id, user_id } => self.player_left(game_id, user_id)?,
            Push::Kicked { game_id } => {
                let g = self.game.as_ref().filter(|g| g.game_id == game_id).ok_or_else(|| format!("kick from game {}, which this client is not in", game_id.0))?;
                let mut t = Self::lid_gid(game_id.0)?;
                t.set_int("PID", g.pid.into()).map_err(tf)?;
                self.end_game("removed by the host");
                self.send(Kind::new(b"KICK"), theater::OK, &t, None)?;
            }
            Push::GameRemoved { game_id } => {
                let ours = self.game.as_ref().is_some_and(|g| g.game_id == game_id) || self.joining.as_ref().is_some_and(|j| j.game_id == game_id);
                if !ours {
                    return Err(format!("game.removed for game {}, which this client is not in", game_id.0));
                }
                self.end_game("removed on the server");
                let t = Self::lid_gid(game_id.0)?;
                self.send(Kind::new(b"GREM"), theater::OK, &t, None)?;
            }
            Push::FriendsUpdated { op, friend } => self.log.warn(format!(
                "friends update ({op:?} {:?}) not shown in the game: asso NotifyAssociationUpdate is not implemented",
                friend.user.name
            )),
        }
        Ok(())
    }

    fn join_accepted(&mut self, a: JoinAccepted) -> R {
        let j = match self.joining.take() {
            Some(j) if j.game_id == a.game_id && j.join_id == Some(a.join_id) => j,
            _ => return Err(format!("join.accepted for request {} (game {}) that this client did not make", a.join_id, a.game_id.0)),
        };
        if a.players > MAX_PLAYERS {
            return Err(format!(
                "join.accepted for game {} reports {} players present; this ASI links only host and joiner, with no \
                 joiner-to-joiner relay mesh, so games of more than {MAX_PLAYERS} players are unsupported",
                a.game_id.0, a.players
            ));
        }
        if a.ekey.len() > rules::EKEY_LEN || a.ugid.len() > rules::UGID_MAX {
            return Err(format!("join.accepted EKEY/UGID do not fit the game's EGEG buffers (≤{} / ≤{})", rules::EKEY_LEN, rules::UGID_MAX));
        }
        let mut relay = self.relays.start(a.game_id, &a.relay, j.tunnel_port)?;
        let peer = relay.add_peer(a.host_slot)?;
        self.game = Some(InGame { game_id: a.game_id, pid: a.pid, role: Role::Joiner, relay, relay_closed_at: None });
        let mut t = Self::lid_gid(a.game_id.0)?;
        t.set_int("PID", a.pid.into()).map_err(tf)?;
        t.set_str("TICKET", ticket(a.join_id)).map_err(tf)?;
        t.set_str("UGID", &a.ugid).map_err(tf)?;
        t.set_str("EKEY", &a.ekey).map_err(tf)?;
        t.set_int("HUID", a.host.user_id.0).map_err(tf)?;
        t.set_str("PL", PLATFORM).map_err(tf)?;
        set_peer(&mut t, "I", "P", peer)?;
        set_peer(&mut t, "INT-IP", "INT-PORT", peer)?;
        self.send(Kind::new(b"EGEG"), theater::OK, &t, None)?;
        self.log.info(format!("joined game {} hosted by {:?} as PID {}", a.game_id.0, a.host.name, a.pid));
        Ok(())
    }

    fn player_left(&mut self, game_id: GameId, user_id: UserId) -> R {
        let g = self.game.as_mut().filter(|g| g.game_id == game_id).ok_or_else(|| format!("player.left for game {}, which this client is not in", game_id.0))?;
        if let Role::Host { waiting, players, .. } = &mut g.role {
            for map in [players, waiting] {
                if let Some(pid) = map.iter().find(|(_, m)| m.user.user_id == user_id).map(|(p, _)| *p) {
                    let m = map.remove(&pid).expect("found above");
                    g.relay.remove_peer(m.slot);
                    self.log.info(format!("game {}: {:?} (PID {pid}) left", game_id.0, m.user.name));
                    return Ok(());
                }
            }
        }
        self.log.info(format!("game {}: user {} left", game_id.0, user_id.0));
        Ok(())
    }
}

fn set_peer(t: &mut TagFields, ip_key: &str, port_key: &str, p: PeerAddr) -> R {
    t.set_str(ip_key, p.ip.to_string()).map_err(tf)?;
    t.set_int(port_key, p.tunnel_port.into()).map_err(tf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lobby::fake::FakeLobby;
    use crate::log::capture;
    use mercs2_mp_api::ws::{GameCreated, PlayerInfo, RelayAssignment};
    use mercs2_plasma_proto::frame::{self, Frame};
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    /// Relay stand-in: aliases are 127.0.0.(2+slot):10010, as the production plan with the shipped ini.
    #[derive(Default)]
    struct FakeRelays {
        events: Arc<Mutex<Vec<String>>>,
        state: Arc<Mutex<Option<RelayState>>>,
    }

    struct FakeLink {
        events: Arc<Mutex<Vec<String>>>,
        state: Arc<Mutex<Option<RelayState>>>,
    }

    impl RelayFactory for FakeRelays {
        fn start(&self, game: GameId, a: &RelayAssignment, port: u16) -> Result<Box<dyn RelayLink>, String> {
            self.events.lock().unwrap().push(format!("start game {} slot {} token {} game port {port}", game.0, a.local_slot, a.session_token));
            Ok(Box::new(FakeLink { events: self.events.clone(), state: self.state.clone() }))
        }
    }

    impl RelayLink for FakeLink {
        fn add_peer(&mut self, slot: u8) -> Result<PeerAddr, String> {
            self.events.lock().unwrap().push(format!("add {slot}"));
            Ok(PeerAddr { ip: Ipv4Addr::new(127, 0, 0, 2 + slot), tunnel_port: 10010 })
        }
        fn remove_peer(&mut self, slot: u8) {
            self.events.lock().unwrap().push(format!("remove {slot}"));
        }
        fn state(&self) -> RelayState {
            self.state.lock().unwrap().clone().unwrap_or(RelayState::Up)
        }
    }

    impl Drop for FakeLink {
        fn drop(&mut self) {
            self.events.lock().unwrap().push("end".into());
        }
    }

    struct Rig {
        a: TheaterAdapter,
        lobby: FakeLobby,
        relays: Arc<FakeRelays>,
        keys: RoomKeyStore,
        dec: FrameDecoder,
        now: Instant,
        log: capture::Captured,
    }

    fn session(id: i64, name: &str) -> LoggedIn {
        LoggedIn { token: format!("token-{name}"), user_id: UserId(id), display_name: name.into(), expires_at: 0, lkey: format!("lkey-{name}") }
    }

    fn rig_for(s: LoggedIn) -> Rig {
        let (log, cap) = capture::logger();
        let lobby = FakeLobby::default();
        let relays = Arc::new(FakeRelays::default());
        let keys = RoomKeyStore::new(Some("venezuela-42".into()));
        let settings = Arc::new(TheaterSettings {
            activity_timeout_secs: 240,
            keepalive: Duration::from_secs(60),
            lobby_name: "Online games".into(),
            relay_close_grace: Duration::from_secs(5),
        });
        let a = TheaterAdapter::new(settings, Box::new(lobby.clone()), s, keys.clone(), relays.clone(), log);
        Rig { a, lobby, relays, keys, dec: FrameDecoder::new(1 << 20), now: Instant::now(), log: cap }
    }

    fn rig() -> Rig {
        rig_for(session(7, "Mattias"))
    }

    /// A request exactly as the client frames it: id 0x40000000, TagField text + NUL, TID last.
    fn req(kind: &[u8; 4], text: &str) -> Vec<u8> {
        let mut p = text.as_bytes().to_vec();
        p.push(0);
        frame::encode(Kind::new(kind), theater::CLIENT_REQUEST_ID, &p).unwrap()
    }

    fn shown(f: &Frame) -> (String, String, String) {
        let id = match f.id {
            0 => "ok".to_string(),
            other => String::from_utf8(other.to_be_bytes().to_vec()).unwrap(),
        };
        (kind_name(f.kind), id, String::from_utf8(f.payload.clone()).unwrap())
    }

    fn g(kind: &str, id: &str, text: &str) -> (String, String, String) {
        (kind.into(), id.into(), format!("{text}\0"))
    }

    impl Rig {
        fn send(&mut self, kind: &[u8; 4], text: &str) {
            self.a.on_game_bytes(&req(kind, text), self.now).unwrap();
        }
        fn pump(&mut self) {
            self.a.pump(self.now).unwrap();
        }
        fn frames(&mut self) -> Vec<(String, String, String)> {
            let bytes: Vec<u8> = self.a.outbound().drain(..).collect();
            self.dec.feed(&bytes);
            let mut out = Vec::new();
            while let Some(f) = self.dec.next_frame().unwrap() {
                out.push(shown(&f));
            }
            out
        }
        fn answer(&mut self, result: Result<Response, ApiError>) -> Request {
            let (id, r) = self.lobby.last();
            self.lobby.reply(id, result);
            self.pump();
            r
        }
        fn relay_events(&self) -> Vec<String> {
            std::mem::take(&mut *self.relays.events.lock().unwrap())
        }
    }

    fn assignment(slot: u8, token: &str) -> RelayAssignment {
        RelayAssignment {
            host: "relay.example.org".into(),
            port: 3659,
            cert_sha256: "ab".repeat(32),
            session_token: token.into(),
            local_slot: slot,
            idle_timeout_secs: 60,
        }
    }

    fn summary() -> GameSummary {
        GameSummary {
            game_id: GameId(5),
            name: "Caracas run".into(),
            host: UserRef { user_id: UserId(7), name: "Mattias".into() },
            max_players: 2,
            players: 1,
            joinable: Joinability::Open,
            version: "1.1".into(),
            attrs: [("B-U-mission".to_string(), "m01".to_string())].into(),
            private: true,
        }
    }

    const CGAM: &str = "LID=1\nRESERVE-HOST=0\nNAME=\"Caracas run\"\nPORT=10000\nHTTYPE=A\nTYPE=G\nQLEN=0\n\
        DISABLE-AUTO-DEQUEUE=0\nHXFR=0\nINT-IP=192.168.1.5\nINT-PORT=10000\nMAX-PLAYERS=2\nB-maxObservers=0\n\
        B-numObservers=0\nUGID=\nSECRET=\nB-U-mission=m01\nB-version=1.1\nRESERVE-IDS=0\nRESERVE-TIMEOUT=0\nJOIN=O\nRT=0\nTID=7\n";

    fn hosting(r: &mut Rig) {
        r.send(b"CGAM", CGAM);
        let created = GameCreated {
            game_id: GameId(5),
            pid: 1,
            ekey: "abcdefghijklmnop".into(),
            secret: "s3cret".into(),
            ugid: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0".into(),
            relay: assignment(0, "host-token"),
        };
        r.answer(Ok(Response::GameCreated(created)));
    }

    #[test]
    fn conn_user_ping_llst_goldens_and_keepalive() {
        let mut r = rig();
        // CONN builder FUN_0097adb0; USER builder FUN_0097ae60.
        r.send(b"CONN", "PROT=2\nPROD=mercs2-pc\nVERS=1.1\nPLAT=PC\nLOCALE=en_US\nSDKVERSION=4.3.4.0.0\nTID=1\n");
        r.send(b"USER", "CID=\nMAC=$001122334455\nSKU=MERCS2PC\nLKEY=lkey-Mattias\nNAME=Mattias\nTID=2\n");
        r.send(b"PING", "TID=3\n");
        r.send(b"LLST", "FILTER-FAV-ONLY=0\nFILTER-NOT-FULL=0\nFILTER-NOT-PRIVATE=0\nFILTER-NOT-CLOSED=0\nFILTER-MIN-SIZE=0\nTID=4\n");
        assert_eq!(
            r.frames(),
            vec![
                g("CONN", "ok", "activityTimeoutSecs=240\nTID=1\n"),
                g("USER", "ok", "NAME=Mattias\nTID=2\n"),
                g("PING", "ok", "TID=3\n"),
                g("LLST", "ok", "NUM-LOBBIES=1\nTID=4\n"),
                g("LDAT", "ok", "NAME=\"Online games\"\nLID=1\nTID=4\n"),
            ]
        );
        assert!(r.lobby.take_sent().is_empty(), "none of these need the server");
        let t0 = r.now;
        r.a.pump(t0 + Duration::from_secs(59)).unwrap();
        assert!(r.frames().is_empty());
        r.a.pump(t0 + Duration::from_secs(60)).unwrap();
        assert_eq!(r.frames(), vec![g("PING", "ok", "")]);
    }

    /// The game's answer to a pushed PING, as the 2026-10-11 run logged it: a PING frame with id 0. Its payload
    /// was not captured, so this one is empty; the adapter does not read it.
    fn ping_answer() -> Vec<u8> {
        frame::encode(Kind::new(b"PING"), theater::OK, &[]).unwrap()
    }

    #[test]
    fn the_game_answering_a_pushed_ping_is_accepted_and_logged_raw() {
        let mut r = rig();
        r.send(b"CONN", "PROT=2\nPROD=mercs2-pc\nVERS=1.1\nPLAT=PC\nTID=1\n");
        r.frames();
        r.a.pump(r.now + Duration::from_secs(60)).unwrap();
        assert_eq!(r.frames(), vec![g("PING", "ok", "")]);
        r.a.on_game_bytes(&ping_answer(), r.now).unwrap();
        assert!(r.frames().is_empty(), "the answer gets no reply");
        assert!(r.log.text().contains("Theater PING frame from the game with id 0x0: 0 payload bytes"), "{}", r.log.text());
        // Still a working connection: the next request is served.
        r.send(b"PING", "TID=2\n");
        assert_eq!(r.frames(), vec![g("PING", "ok", "TID=2\n")]);
    }

    #[test]
    fn id_zero_frames_are_handled_and_other_ids_fail() {
        // UGAM exactly as the host's game sent it after its own entry (2026-10-11 log): id 0, with a TID.
        let mut r = rig();
        hosting(&mut r);
        r.send(b"EGAM", SELF_EGAM);
        r.send(b"EGRS", "LID=1\nGID=5\nALLOWED=1\nPID=1\nTID=9\n");
        r.send(b"PENT", "LID=1\nGID=5\nPID=1\nTID=10\n");
        r.frames();
        r.lobby.take_sent();
        let ugam = frame::encode(
            Kind::new(b"UGAM"),
            theater::OK,
            b"LID=1\nGID=5\nJOIN=O\nMAX-PLAYERS=2\nB-maxObservers=0\nB-numObservers=0\nTID=8\n\0",
        )
        .unwrap();
        r.a.on_game_bytes(&ugam, r.now).unwrap();
        assert!(r.frames().is_empty(), "UGAM gets no reply");
        let sent = r.lobby.take_sent();
        assert!(
            matches!(&sent[..], [(_, Request::GamesUpdate(u))] if u.game_id == GameId(5) && u.max_players == Some(2)),
            "{sent:?}"
        );
        assert!(r.log.text().contains("Theater UGAM frame from the game with id 0x0: 74 payload bytes"), "{}", r.log.text());

        // An id-0 PING with no keepalive outstanding is handled like any other frame: it needs a TID.
        let mut r = rig();
        r.send(b"CONN", "PROT=2\nPROD=mercs2-pc\nVERS=1.1\nPLAT=PC\nTID=1\n");
        let e = r.a.on_game_bytes(&ping_answer(), r.now).unwrap_err();
        assert_eq!(e, "PING without TID");

        // Any id the encoder (0x970600) cannot produce fails the connection.
        let mut r = rig();
        let odd = frame::encode(Kind::new(b"USER"), 0x8000_0001, b"TID=2\n\0").unwrap();
        let e = r.a.on_game_bytes(&odd, r.now).unwrap_err();
        assert!(e.contains("USER frame with id 0x80000001") && e.contains("0x970600"), "{e}");
    }

    #[test]
    fn user_with_another_lkey_fails_the_connection() {
        let mut r = rig();
        let e = r.a.on_game_bytes(&req(b"USER", "LKEY=stale\nTID=2\n"), r.now).unwrap_err();
        assert!(e.contains("LKEY is not the lkey"), "{e}");
    }

    #[test]
    fn glst_lists_with_the_current_room_key() {
        let mut r = rig();
        r.keys.set(Some("Changed-at-runtime".into())).unwrap();
        r.send(b"GLST", "LID=1\nTYPE=G\nFILTER-NOT-FULL=1\nFAV-PLAYER=\nCOUNT=10\nTID=4\n");
        let sent = r.answer(Ok(Response::Games(vec![summary()])));
        assert_eq!(sent, Request::GamesList { joinable_only: true, room_key: Some("Changed-at-runtime".into()) });
        assert_eq!(
            r.frames(),
            vec![
                g("GLST", "ok", "LID=1\nNUM-GAMES=1\nLOBBY-MAX-GAMES=1\nLOBBY-NUM-GAMES=1\nTID=4\n"),
                g(
                    "GDAT",
                    "ok",
                    "B-U-mission=m01\nLID=1\nGID=5\nN=\"Caracas run\"\nTYPE=G\nMP=2\nAP=1\nJP=0\nB-maxObservers=0\n\
                     B-numObservers=0\nHN=Mattias\nHU=7\nB-version=1.1\nJ=O\nTID=4\n"
                ),
            ]
        );
        assert!(r.log.text().contains("GLST filters not applied by the server: FAV-PLAYER"));
    }

    #[test]
    fn gdat_detail_and_not_found() {
        let mut r = rig();
        r.send(b"GDAT", "LID=1\nGID=5\nTID=5\n");
        let detail = GameDetail {
            summary: summary(),
            ugid: "u-g-i-d".into(),
            details: [("D-map".to_string(), "caracas".to_string())].into(),
            players: vec![
                PlayerInfo { user: UserRef { user_id: UserId(7), name: "Mattias".into() }, pid: 1, attrs: Default::default() },
                PlayerInfo {
                    user: UserRef { user_id: UserId(8), name: "Jen".into() },
                    pid: 2,
                    attrs: [("P-char".to_string(), "jen".to_string())].into(),
                },
            ],
        };
        assert_eq!(r.answer(Ok(Response::Game(detail))), Request::GamesGet { game_id: GameId(5), room_key: Some("venezuela-42".into()) });
        let f = r.frames();
        assert_eq!(f.len(), 4);
        assert_eq!(f[0].0, "GDAT");
        assert_eq!(f[1], g("GDET", "ok", "LID=1\nGID=5\nUGID=u-g-i-d\nD-map=caracas\nTID=5\n"));
        assert_eq!(f[2], g("PDAT", "ok", "LID=1\nGID=5\nPID=1\nNAME=Mattias\nUID=7\nTID=5\n"));
        assert_eq!(f[3], g("PDAT", "ok", "LID=1\nGID=5\nPID=2\nNAME=Jen\nUID=8\nP-char=jen\nTID=5\n"));

        r.send(b"GDAT", "LID=1\nGID=6\nTID=6\n");
        r.answer(Err(ApiError::new(ErrorCode::NotFound, "game 6")));
        assert_eq!(r.frames(), vec![g("GDAT", "ngam", "TID=6\n")]);

        // By-player form: the server has no such lookup; answered 'ngam' with a logged error.
        r.send(b"GDAT", "UID=8\nTYPE=G\nTID=7\n");
        assert_eq!(r.frames(), vec![g("GDAT", "ngam", "TID=7\n")]);
        assert!(r.log.text().contains("GDAT by player"));
    }

    /// The host's EGAM for its own game, with the fields and order of the live 2026-10-11 capture (GID, TID and
    /// the LAN address adjusted to this rig). The handling reads only `GID` and `TID`.
    const SELF_EGAM: &str = "PORT=10000\nR-INT-PORT=6001\nR-INT-IP=192.168.1.5\nPTYPE=P\nLID=1\nGID=5\nTID=8\n";

    #[test]
    fn host_enters_its_own_game_locally_like_the_lan_emulator() {
        let mut r = rig();
        hosting(&mut r);
        r.frames();
        r.relay_events();
        r.lobby.take_sent();

        // EGAM reply LID GID (FUN_009ab0e0 → FUN_0099c8d0 + FUN_00990c60), then EGRQ for the host's own PID
        // with FUN_009aa140's fields: no address.
        r.send(b"EGAM", SELF_EGAM);
        assert_eq!(
            r.frames(),
            vec![
                g("EGAM", "ok", "LID=1\nGID=5\nTID=8\n"),
                g("EGRQ", "ok", "LID=1\nGID=5\nNAME=Mattias\nUID=7\nPID=1\nTICKET=0x7\nPTYPE=P\n"),
            ]
        );
        assert!(r.lobby.take_sent().is_empty(), "the server already counts the host in its game");
        assert!(r.relay_events().is_empty(), "no relay peer for the host itself");
        assert!(r.log.text().contains("Theater EGAM from the host for its own game 5: PORT=10000 R-INT-PORT=6001 R-INT-IP=192.168.1.5 PTYPE=P LID=1 GID=5 TID=8"), "{}", r.log.text());

        // EGRS reply TID, then EGEG LID GID PID TICKET UGID EKEY (FUN_009a0e80 → FUN_0099ca30): no address.
        r.send(b"EGRS", "LID=1\nGID=5\nALLOWED=1\nPID=1\nTID=9\n");
        assert_eq!(
            r.frames(),
            vec![
                g("EGRS", "ok", "TID=9\n"),
                g("EGEG", "ok", "LID=1\nGID=5\nPID=1\nTICKET=0x7\nUGID=0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\nEKEY=abcdefghijklmnop\n"),
            ]
        );
        assert!(r.lobby.take_sent().is_empty());
        assert!(r.log.text().contains("game 5: the host entered its own game as PID 1"));

        // Then PENT for itself (live 2026-10-11, 25 ms after the EGEG): echoed locally, as FUN_0099cc60.
        r.send(b"PENT", "LID=1\nGID=5\nPID=1\nTID=10\n");
        assert_eq!(r.frames(), vec![g("PENT", "ok", "PID=1\nTID=10\n")]);
        assert!(r.lobby.take_sent().is_empty(), "players.enter is for accepted joiners");

        // Joiners are still handled as before.
        r.lobby.push(Push::JoinRequest {
            join_id: 9,
            game_id: GameId(5),
            user: UserRef { user_id: UserId(8), name: "Jen".into() },
            slot: 1,
            pid: 2,
        });
        r.pump();
        let f = r.frames();
        assert_eq!((f.len(), f[0].0.as_str()), (1, "EGRQ"));

        // A second self-entry is not something the game does; it fails the connection.
        let e = r.a.on_game_bytes(&req(b"EGAM", SELF_EGAM), r.now).unwrap_err();
        assert!(e.contains("EGAM from the host for its own game 5 again (entry already Entered)"), "{e}");
    }

    #[test]
    fn host_self_entry_edges() {
        // ALLOWED=0 on its own entry: the LAN emulator sends EGEG regardless; so does the ASI, with a warning.
        let mut r = rig();
        hosting(&mut r);
        r.send(b"EGAM", SELF_EGAM);
        r.frames();
        r.send(b"EGRS", "LID=1\nGID=5\nALLOWED=0\nPID=1\nREASON=2\nTID=9\n");
        let f = r.frames();
        assert_eq!((f[0].0.as_str(), f[1].0.as_str()), ("EGRS", "EGEG"));
        assert!(r.log.text().contains("answered its own entry with ALLOWED=Some(0)"), "{}", r.log.text());

        // PENT for the host's own PID before its entry completed fails the connection.
        let mut r = rig();
        hosting(&mut r);
        let e = r.a.on_game_bytes(&req(b"PENT", "LID=1\nGID=5\nPID=1\nTID=9\n"), r.now).unwrap_err();
        assert!(e.contains("PENT for the host's own PID 1 before its entry completed (NotRequested)"), "{e}");

        // EGAM for another game while hosting still fails the connection.
        let mut r = rig();
        hosting(&mut r);
        let e = r.a.on_game_bytes(&req(b"EGAM", "LID=1\nGID=6\nPORT=10000\nTID=8\n"), r.now).unwrap_err();
        assert!(e.contains("EGAM for game 6 while already in or joining a game"), "{e}");

        // EGRS for the host's PID before its EGAM: not a self-entry, and no join request has that PID.
        let mut r = rig();
        hosting(&mut r);
        let e = r.a.on_game_bytes(&req(b"EGRS", "LID=1\nGID=5\nALLOWED=1\nPID=1\nTID=9\n"), r.now).unwrap_err();
        assert!(e.contains("EGRS for PID 1, which has no pending join request"), "{e}");
    }

    #[test]
    fn host_flow_cgam_egrq_egrs_pent_updates_plvt_rgam() {
        let mut r = rig();
        r.send(b"CGAM", CGAM);
        let (id, sent) = r.lobby.last();
        assert_eq!(
            sent,
            Request::GamesCreate(CreateGame {
                name: "Caracas run".into(),
                max_players: 2,
                version: "1.1".into(),
                joinable: Joinability::Open,
                attrs: [("B-U-mission".to_string(), "m01".to_string())].into(),
                privacy: Privacy { room_key: Some("venezuela-42".into()), friends_only: false },
            })
        );
        r.lobby.reply(
            id,
            Ok(Response::GameCreated(GameCreated {
                game_id: GameId(5),
                pid: 1,
                ekey: "abcdefghijklmnop".into(),
                secret: "s3cret".into(),
                ugid: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0".into(),
                relay: assignment(0, "host-token"),
            })),
        );
        r.pump();
        assert_eq!(
            r.frames(),
            vec![g(
                "CGAM",
                "ok",
                "LID=1\nGID=5\nMAX-PLAYERS=2\nJOIN=O\nSECRET=s3cret\nUGID=0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\n\
                 EKEY=abcdefghijklmnop\nTID=7\n"
            )]
        );
        assert_eq!(r.relay_events(), vec!["start game 5 slot 0 token host-token game port 10000"]);

        // Join request push → EGRQ with the joiner's alias as both address pairs.
        r.lobby.push(Push::JoinRequest {
            join_id: 9,
            game_id: GameId(5),
            user: UserRef { user_id: UserId(8), name: "Jen".into() },
            slot: 1,
            pid: 2,
        });
        r.pump();
        assert_eq!(
            r.frames(),
            vec![g(
                "EGRQ",
                "ok",
                "LID=1\nGID=5\nNAME=Jen\nUID=8\nPID=2\nTICKET=0x9\nIP=127.0.0.3\nPORT=10010\nR-INT-IP=127.0.0.3\n\
                 R-INT-PORT=10010\nPTYPE=P\n"
            )]
        );
        assert_eq!(r.relay_events(), vec!["add 1"]);

        // EGRS builder FUN_0097b380: LID GID ALLOWED PID (+REASON when denied).
        r.send(b"EGRS", "LID=1\nGID=5\nALLOWED=1\nPID=2\nTID=8\n");
        assert_eq!(r.answer(Ok(Response::Ok)), Request::JoinRespond { join_id: 9, allowed: true, reason: None });
        assert_eq!(r.frames(), vec![g("EGRS", "ok", "TID=8\n")]);

        r.send(b"PENT", "LID=1\nGID=5\nPID=2\nTID=9\n");
        assert_eq!(r.answer(Ok(Response::Ok)), Request::PlayerEntered { game_id: GameId(5), user_id: UserId(8) });
        assert_eq!(r.frames(), vec![g("PENT", "ok", "PID=2\nTID=9\n")]);

        // Both UGAM forms (FUN_0097b070 / FUN_0097b100), UGDE, UPLA, UBRA.
        r.send(b"UGAM", "LID=1\nGID=5\nJOIN=C\nMAX-PLAYERS=2\nB-maxObservers=0\nB-numObservers=0\nTID=10\n");
        let upd = r.answer(Ok(Response::Ok));
        assert_eq!(
            upd,
            Request::GamesUpdate(UpdateGame {
                game_id: GameId(5),
                name: None,
                max_players: Some(2),
                joinable: Some(Joinability::Closed),
                attrs: None,
                details: None
            })
        );
        r.send(b"UGAM", "LID=1\nGID=5\nNAME=\"Caracas run 2\"\nB-U-mission=m02\nJOIN=O\nRT=0\nTID=11\n");
        let Request::GamesUpdate(u) = r.answer(Ok(Response::Ok)) else { panic!() };
        assert_eq!((u.name.as_deref(), u.joinable), (Some("Caracas run 2"), Some(Joinability::Open)));
        assert_eq!(u.attrs, Some([("B-U-mission".to_string(), "m02".to_string())].into()));
        r.send(b"UGDE", "LID=1\nGID=5\nD-map=caracas\nTID=12\n");
        let Request::GamesUpdate(u) = r.answer(Ok(Response::Ok)) else { panic!() };
        assert_eq!(u.details, Some([("D-map".to_string(), "caracas".to_string())].into()));
        r.send(b"UPLA", "LID=1\nGID=5\nPID=1\nHMO=0\nP-char=mattias\nTID=13\n");
        r.send(b"UBRA", "LID=1\nGID=5\nSTART=1\nTID=14\n");
        assert_eq!(r.frames(), vec![g("UBRA", "ok", "TID=14\n")], "UGAM/UGDE/UPLA get no reply");
        assert!(r.log.text().contains("UPLA PID=Some(1): player attributes [\"P-char\"] are not forwarded"));

        r.send(b"PLVT", "LID=1\nGID=5\nPID=2\nTID=15\n");
        assert_eq!(r.answer(Ok(Response::Ok)), Request::PlayerLeft { game_id: GameId(5), user_id: UserId(8) });
        assert_eq!(r.frames(), vec![g("PLVT", "ok", "TID=15\n")], "PLVT reply TID (FUN_009a10a0)");
        assert_eq!(r.relay_events(), vec!["remove 1"]);

        r.send(b"RGAM", "LID=1\nGID=5\nTID=16\n");
        assert_eq!(r.answer(Ok(Response::Ok)), Request::GamesClose { game_id: GameId(5) });
        assert_eq!(r.frames(), vec![g("RGAM", "ok", "LID=1\nGID=5\nTID=16\n")]);
        assert_eq!(r.relay_events(), vec!["end"]);
    }

    #[test]
    fn host_denies_and_joiner_leaving_first() {
        let mut r = rig();
        hosting(&mut r);
        r.frames();
        r.relay_events();
        let jen = UserRef { user_id: UserId(8), name: "Jen".into() };
        r.lobby.push(Push::JoinRequest { join_id: 9, game_id: GameId(5), user: jen.clone(), slot: 1, pid: 2 });
        r.pump();
        r.frames();
        // The game's REASON (`%d`, FUN_0097b380) is forwarded as its integer.
        r.send(b"EGRS", "LID=1\nGID=5\nALLOWED=0\nPID=2\nREASON=2\nTID=8\n");
        assert_eq!(
            r.answer(Ok(Response::Ok)),
            Request::JoinRespond { join_id: 9, allowed: false, reason: Some(JoinDenyReason::HostDenied { code: 2 }) }
        );
        assert_eq!(r.frames(), vec![g("EGRS", "ok", "TID=8\n")]);
        assert_eq!(r.relay_events(), vec!["add 1", "remove 1"]);

        // A joiner who withdrew before the host answered: logged, alias released, host still answered.
        r.lobby.push(Push::JoinRequest { join_id: 10, game_id: GameId(5), user: jen.clone(), slot: 1, pid: 3 });
        r.pump();
        r.frames();
        r.send(b"EGRS", "LID=1\nGID=5\nALLOWED=1\nPID=3\nTID=9\n");
        r.answer(Err(ApiError::new(ErrorCode::NotFound, "join request 10")));
        assert_eq!(r.frames(), vec![g("EGRS", "ok", "TID=9\n")]);
        assert!(r.log.text().contains("the join request is gone"));

        // An accepted player's departure pushed by the server releases the alias.
        r.lobby.push(Push::JoinRequest { join_id: 11, game_id: GameId(5), user: jen, slot: 1, pid: 4 });
        r.pump();
        r.send(b"EGRS", "LID=1\nGID=5\nALLOWED=1\nPID=4\nTID=10\n");
        r.answer(Ok(Response::Ok));
        r.relay_events();
        r.lobby.push(Push::PlayerLeft { game_id: GameId(5), user_id: UserId(8) });
        r.pump();
        assert_eq!(r.relay_events(), vec!["remove 1"]);
    }

    #[test]
    fn host_denies_a_second_joiner_without_a_mesh() {
        let mut r = rig();
        hosting(&mut r);
        r.frames();
        r.relay_events();
        let jen = UserRef { user_id: UserId(8), name: "Jen".into() };
        let ana = UserRef { user_id: UserId(9), name: "Ana".into() };
        r.lobby.push(Push::JoinRequest { join_id: 9, game_id: GameId(5), user: jen, slot: 1, pid: 2 });
        r.pump();
        assert_eq!(r.frames()[0].0, "EGRQ");

        // A second request while the first still awaits the host's answer: denied by the ASI, never shown.
        r.lobby.push(Push::JoinRequest { join_id: 10, game_id: GameId(5), user: ana.clone(), slot: 2, pid: 3 });
        r.pump();
        assert!(r.frames().is_empty(), "the game is not asked about a joiner it cannot be linked with");
        assert_eq!(
            r.answer(Ok(Response::Ok)),
            Request::JoinRespond { join_id: 10, allowed: false, reason: Some(JoinDenyReason::MeshUnsupported) }
        );
        assert_eq!(r.relay_events(), vec!["add 1"], "no alias for the denied joiner");
        let log = r.log.text();
        assert!(log.contains("ERROR") && log.contains("no joiner-to-joiner relay mesh"), "{log}");

        // Once the first joiner is in the game, the same.
        r.send(b"EGRS", "LID=1\nGID=5\nALLOWED=1\nPID=2\nTID=8\n");
        r.answer(Ok(Response::Ok));
        r.frames();
        r.lobby.push(Push::JoinRequest { join_id: 11, game_id: GameId(5), user: ana.clone(), slot: 2, pid: 4 });
        r.pump();
        assert!(r.frames().is_empty());
        assert_eq!(
            r.answer(Err(ApiError::new(ErrorCode::NotFound, "join request 11"))),
            Request::JoinRespond { join_id: 11, allowed: false, reason: Some(JoinDenyReason::MeshUnsupported) }
        );
        assert!(r.log.text().contains("join request 11: gone before the denial reached the server"));

        // After the joiner leaves, the next request is shown to the game again.
        r.lobby.push(Push::PlayerLeft { game_id: GameId(5), user_id: UserId(8) });
        r.pump();
        r.lobby.push(Push::JoinRequest { join_id: 12, game_id: GameId(5), user: ana, slot: 1, pid: 5 });
        r.pump();
        assert_eq!(r.frames()[0].0, "EGRQ");
    }

    #[test]
    fn joiner_refuses_a_game_of_more_than_two_players() {
        let mut r = rig_for(session(8, "Jen"));
        joining(&mut r);
        r.frames();
        r.lobby.push(Push::JoinAccepted(JoinAccepted { players: 3, ..accepted() }));
        let e = r.a.pump(r.now).unwrap_err();
        assert!(e.contains("reports 3 players present") && e.contains("no joiner-to-joiner relay mesh"), "{e}");
        assert!(r.frames().is_empty(), "no EGEG for a game this ASI cannot link");
        assert!(r.relay_events().is_empty(), "no relay session started");
    }

    #[test]
    fn egrs_reason_must_be_the_games_integer() {
        let mut r = rig();
        hosting(&mut r);
        r.lobby.push(Push::JoinRequest {
            join_id: 9,
            game_id: GameId(5),
            user: UserRef { user_id: UserId(8), name: "Jen".into() },
            slot: 1,
            pid: 2,
        });
        r.pump();
        let e = r.a.on_game_bytes(&req(b"EGRS", "LID=1\nGID=5\nALLOWED=0\nPID=2\nREASON=h\nTID=8\n"), r.now).unwrap_err();
        assert!(e.contains("REASON"), "{e}");
    }

    #[test]
    fn cgam_with_a_queue_is_bad_parameter() {
        let mut r = rig();
        r.send(b"CGAM", &CGAM.replace("QLEN=0", "QLEN=4"));
        assert_eq!(r.frames(), vec![g("CGAM", "bpar", "TID=7\n")]);
        assert!(r.lobby.take_sent().is_empty());
    }

    fn joining(r: &mut Rig) {
        // EGAM fields: GID, PORT, R-INT-IP, R-INT-PORT, PTYPE (catalogue §2, W).
        r.send(b"EGAM", "LID=1\nGID=5\nPORT=10000\nR-INT-IP=192.168.1.9\nR-INT-PORT=10000\nPTYPE=P\nTID=3\n");
        let sent = r.answer(Ok(Response::JoinPending { join_id: 9 }));
        assert_eq!(sent, Request::GamesJoin { game_id: GameId(5), room_key: Some("venezuela-42".into()) });
    }

    fn accepted() -> JoinAccepted {
        JoinAccepted {
            join_id: 9,
            game_id: GameId(5),
            host: UserRef { user_id: UserId(7), name: "Mattias".into() },
            host_slot: 0,
            pid: 2,
            ekey: "abcdefghijklmnop".into(),
            ugid: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0".into(),
            relay: assignment(1, "joiner-token"),
            players: 2,
        }
    }

    #[test]
    fn joiner_flow_egam_egeg_kick() {
        let mut r = rig_for(session(8, "Jen"));
        joining(&mut r);
        assert_eq!(r.frames(), vec![g("EGAM", "ok", "LID=1\nGID=5\nTID=3\n")]);
        r.lobby.push(Push::JoinAccepted(accepted()));
        r.pump();
        assert_eq!(
            r.frames(),
            vec![g(
                "EGEG",
                "ok",
                "LID=1\nGID=5\nPID=2\nTICKET=0x9\nUGID=0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\nEKEY=abcdefghijklmnop\n\
                 HUID=7\nPL=PC\nI=127.0.0.2\nP=10010\nINT-IP=127.0.0.2\nINT-PORT=10010\n"
            )]
        );
        assert_eq!(r.relay_events(), vec!["start game 5 slot 1 token joiner-token game port 10000", "add 0"]);
        r.lobby.push(Push::Kicked { game_id: GameId(5) });
        r.pump();
        assert_eq!(r.frames(), vec![g("KICK", "ok", "LID=1\nGID=5\nPID=2\n")]);
        assert_eq!(r.relay_events(), vec!["end"]);
    }

    #[test]
    fn joiner_denied_not_found_full_cancel_and_removed() {
        let mut r = rig_for(session(8, "Jen"));
        joining(&mut r);
        r.frames();
        r.lobby.push(Push::JoinDenied { join_id: 9, game_id: GameId(5), reason: JoinDenyReason::HostDenied { code: 2 } });
        r.pump();
        assert_eq!(r.frames(), vec![g("EGEG", "jden", "LID=1\nGID=5\nREASON=2\n")]);
        joining(&mut r);
        r.frames();
        r.lobby.push(Push::JoinDenied { join_id: 9, game_id: GameId(5), reason: JoinDenyReason::MeshUnsupported });
        r.pump();
        assert_eq!(r.frames(), vec![g("EGEG", "jden", "LID=1\nGID=5\nREASON=f\n")]);
        joining(&mut r);
        r.frames();
        r.lobby.push(Push::JoinDenied { join_id: 9, game_id: GameId(5), reason: JoinDenyReason::GameRemoved });
        r.pump();
        assert_eq!(r.frames(), vec![g("EGEG", "jden", "LID=1\nGID=5\nREASON=c\n")]);

        r.send(b"EGAM", "LID=1\nGID=6\nPORT=10000\nTID=4\n");
        r.answer(Err(ApiError::new(ErrorCode::NotFound, "game 6")));
        assert_eq!(r.frames(), vec![g("EGAM", "ngam", "TID=4\n")]);
        r.send(b"EGAM", "LID=1\nGID=5\nPORT=10000\nTID=5\n");
        r.answer(Err(ApiError::new(ErrorCode::GameFull, "2/2 players")));
        assert_eq!(r.frames(), vec![g("EGAM", "jden", "REASON=f\nTID=5\n")]);
        r.send(b"EGAM", "LID=1\nGID=5\nPORT=10000\nTID=7\n");
        r.answer(Err(ApiError::new(ErrorCode::GameClosed, "game is closed to joins")));
        assert_eq!(r.frames(), vec![g("EGAM", "jden", "REASON=c\nTID=7\n")]);

        // ECNL while the host has not answered yet withdraws the request.
        joining(&mut r);
        r.frames();
        r.send(b"ECNL", "LID=1\nGID=5\nTID=6\n");
        assert_eq!(r.answer(Ok(Response::Ok)), Request::PlayerLeft { game_id: GameId(5), user_id: UserId(8) });
        assert_eq!(r.frames(), vec![g("ECNL", "ok", "LID=1\nGID=5\nTID=6\n")]);

        // In a game, the host closing it arrives as GREM.
        joining(&mut r);
        r.lobby.push(Push::JoinAccepted(accepted()));
        r.pump();
        r.frames();
        r.lobby.push(Push::GameRemoved { game_id: GameId(5) });
        r.pump();
        assert_eq!(r.frames(), vec![g("GREM", "ok", "LID=1\nGID=5\n")]);
    }

    /// Both sides against a scripted server: the test relays requests to pushes the way `mercs2_mp_server`'s hub
    /// does, and checks that host and joiner agree on PID and TICKET and address each other by alias.
    #[test]
    fn join_flow_both_sides_agree() {
        let mut host = rig_for(session(7, "Mattias"));
        let mut joiner = rig_for(session(8, "Jen"));
        hosting(&mut host);
        host.frames();

        joiner.send(b"EGAM", "LID=1\nGID=5\nPORT=10000\nR-INT-IP=0.0.0.0\nR-INT-PORT=10000\nPTYPE=P\nTID=3\n");
        let (jid, join) = joiner.lobby.last();
        assert!(matches!(join, Request::GamesJoin { game_id: GameId(5), .. }));
        // Server: join id 9, joiner slot 1, PID 2 assigned now.
        joiner.lobby.reply(jid, Ok(Response::JoinPending { join_id: 9 }));
        joiner.pump();
        host.lobby.push(Push::JoinRequest { join_id: 9, game_id: GameId(5), user: UserRef { user_id: UserId(8), name: "Jen".into() }, slot: 1, pid: 2 });
        host.pump();
        let egrq = host.frames().pop().unwrap();
        host.send(b"EGRS", "LID=1\nGID=5\nALLOWED=1\nPID=2\nTID=8\n");
        let (rid, respond) = host.lobby.last();
        assert_eq!(respond, Request::JoinRespond { join_id: 9, allowed: true, reason: None });
        host.lobby.reply(rid, Ok(Response::Ok));
        host.pump();
        joiner.lobby.push(Push::JoinAccepted(accepted()));
        joiner.pump();
        let egeg = joiner.frames().pop().unwrap();

        let field = |text: &str, key: &str| TagFieldReader::new(text.as_bytes()).get_str(key).unwrap().unwrap();
        assert_eq!(field(&egrq.2, "PID"), field(&egeg.2, "PID"));
        assert_eq!(field(&egrq.2, "TICKET"), field(&egeg.2, "TICKET"));
        assert_eq!(field(&egrq.2, "IP"), "127.0.0.3", "host sees the joiner (slot 1) at its alias");
        assert_eq!(field(&egeg.2, "I"), "127.0.0.2", "joiner sees the host (slot 0) at its alias");
        assert_eq!(field(&egeg.2, "EKEY"), "abcdefghijklmnop");
    }

    #[test]
    fn failures_end_the_connection_with_a_reason() {
        let mut r = rig();
        let e = r.a.on_game_bytes(&req(b"RLST", "TID=1\n"), r.now).unwrap_err();
        assert!(e.contains("Theater RLST is not implemented"), "{e}");
        let mut r = rig();
        assert!(r.a.on_game_bytes(&req(b"PING", "\n"), r.now).unwrap_err().contains("without TID"));

        let mut r = rig();
        hosting(&mut r);
        *r.relays.state.lock().unwrap() = Some(RelayState::Failed("relay certificate sha256 00 does not match".into()));
        assert!(r.a.pump(r.now).unwrap_err().contains("relay: relay certificate"));

        // An orderly relay close is waited on for the grace period, then fails the connection.
        let mut r = rig();
        hosting(&mut r);
        *r.relays.state.lock().unwrap() = Some(RelayState::ClosedByRelay);
        r.a.pump(r.now).unwrap();
        r.a.pump(r.now + Duration::from_secs(5)).unwrap();
        let e = r.a.pump(r.now + Duration::from_millis(5001)).unwrap_err();
        assert!(e.contains("the lobby did not say why within 5000 ms"), "{e}");

        // ...and is no failure when the lobby's notice arrives in time.
        let mut r = rig_for(session(8, "Jen"));
        joining(&mut r);
        r.lobby.push(Push::JoinAccepted(accepted()));
        r.pump();
        *r.relays.state.lock().unwrap() = Some(RelayState::ClosedByRelay);
        r.a.pump(r.now + Duration::from_secs(1)).unwrap();
        r.lobby.push(Push::GameRemoved { game_id: GameId(5) });
        r.a.pump(r.now + Duration::from_secs(9)).unwrap();

        let mut r = rig();
        r.lobby.kill("the lobby session ended: no frame from the server for 75 s");
        assert!(r.a.pump(r.now).unwrap_err().contains("no frame from the server"));
        let e = r.a.on_game_bytes(&req(b"GLST", "LID=1\nTID=2\n"), r.now).unwrap_err();
        assert!(e.contains("lobby request games.list"), "{e}");

        // A push for a game this client is not in is a protocol failure, not a silent drop.
        let mut r = rig();
        r.lobby.push(Push::GameRemoved { game_id: GameId(77) });
        assert!(r.a.pump(r.now).unwrap_err().contains("not in"));
    }
}

/// End to end: two Theater adapters on the real lobby WebSocket and the real DTLS relay of an in-process
/// `mercs2_mp_server`, with UDP sockets standing in for each game's tunnel and voice sockets.
#[cfg(test)]
mod e2e {
    use super::*;
    use crate::lobby::LobbyProvider;
    use crate::log::capture;
    use crate::relay::{AliasPlan, ShimFactory, ShimSettings};
    use crate::testserver::{TestServer, wait};
    use mercs2_plasma_proto::frame::{self, Frame};
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

    struct Side {
        a: TheaterAdapter,
        dec: FrameDecoder,
        tunnel: UdpSocket,
        voice: UdpSocket,
        _provider: crate::ws::WsLobbyProvider,
    }

    fn udp() -> UdpSocket {
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        u.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        u
    }

    fn free_base() -> u16 {
        loop {
            let base = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
            if base < 65000 && (0..4).all(|i| UdpSocket::bind(("127.0.0.1", base + i)).is_ok()) {
                return base;
            }
        }
    }

    fn side(srv: &TestServer, name: &str) -> Side {
        let (provider, session) = srv.provider(name);
        let (tunnel, voice) = (udp(), udp());
        let (log, _) = capture::logger();
        let relays = ShimFactory {
            settings: ShimSettings {
                plan: AliasPlan::Ports { ip: Ipv4Addr::LOCALHOST, base_port: free_base() },
                game_ip: Ipv4Addr::LOCALHOST,
                game_voice_port: voice.local_addr().unwrap().port(),
                mtu: 1200,
                handshake_timeout: Duration::from_secs(5),
                poll: Duration::from_millis(20),
            },
            log: log.clone(),
        };
        let settings = Arc::new(TheaterSettings {
            activity_timeout_secs: 240,
            keepalive: Duration::from_secs(60),
            lobby_name: "Online".into(),
            relay_close_grace: Duration::from_secs(5),
        });
        let a = TheaterAdapter::new(settings, provider.handle(true).unwrap(), session, RoomKeyStore::new(None), Arc::new(relays), log);
        Side { a, dec: FrameDecoder::new(1 << 20), tunnel, voice, _provider: provider }
    }

    impl Side {
        fn send(&mut self, kind: &[u8; 4], text: &str) {
            let mut p = text.as_bytes().to_vec();
            p.push(0);
            let bytes = frame::encode(Kind::new(kind), theater::CLIENT_REQUEST_ID, &p).unwrap();
            self.a.on_game_bytes(&bytes, Instant::now()).unwrap();
        }
        /// Pump until a frame of `kind` arrives; returns it.
        fn until(&mut self, kind: &[u8; 4]) -> Frame {
            wait(&format!("{}", String::from_utf8_lossy(kind)), || {
                self.a.pump(Instant::now()).unwrap();
                let bytes: Vec<u8> = self.a.outbound().drain(..).collect();
                self.dec.feed(&bytes);
                let mut found = None;
                while let Some(f) = self.dec.next_frame().unwrap() {
                    if f.kind.0 == *kind && found.is_none() {
                        found = Some(f);
                    }
                }
                found
            })
        }
        fn port(&self) -> u16 {
            self.tunnel.local_addr().unwrap().port()
        }
    }

    fn get(f: &Frame, key: &str) -> String {
        TagFieldReader::new(&f.payload).get_str(key).unwrap().unwrap_or_else(|| panic!("{key} missing"))
    }

    /// Pump both sides while sending `payload` until `rx` gets it; returns the source `rx` saw.
    fn deliver(host: &mut Side, joiner: &mut Side, from_host: bool, voice: bool, to: SocketAddr, payload: &[u8]) -> SocketAddr {
        let mut buf = [0u8; 2048];
        wait("a game datagram through the relay", || {
            host.a.pump(Instant::now()).unwrap();
            joiner.a.pump(Instant::now()).unwrap();
            let (s, r) = if from_host { (&*host, &*joiner) } else { (&*joiner, &*host) };
            let (tx, rx) = if voice { (&s.voice, &r.voice) } else { (&s.tunnel, &r.tunnel) };
            tx.send_to(payload, to).unwrap();
            match rx.recv_from(&mut buf) {
                Ok((n, src)) if &buf[..n] == payload => Some(src),
                _ => None,
            }
        })
    }

    #[test]
    fn host_and_join_through_the_real_server_and_relay() {
        let srv = TestServer::start();
        let mut host = side(&srv, "E2eHost");
        let mut joiner = side(&srv, "E2eJoiner");
        for s in [&mut host, &mut joiner] {
            let lkey = s.a.session.lkey.clone();
            s.send(b"CONN", "PROT=2\nPROD=mercs2-pc\nVERS=1.1\nTID=1\n");
            s.send(b"USER", &format!("LKEY={lkey}\nNAME=x\nTID=2\n"));
        }
        let port = host.port();
        host.send(b"CGAM", &format!("LID=1\nNAME=e2e\nPORT={port}\nINT-PORT={port}\nMAX-PLAYERS=2\nB-version=1.1\nJOIN=O\nTID=3\n"));
        let cgam = host.until(b"CGAM");
        assert_eq!(cgam.id, 0);
        let gid = get(&cgam, "GID");
        assert_eq!(get(&cgam, "EKEY").len(), 16);

        // Browse the way the game does after pnow: GDAT by LID+GID.
        joiner.send(b"GDAT", &format!("LID=1\nGID={gid}\nTID=3\n"));
        let gdat = joiner.until(b"GDAT");
        assert_eq!((get(&gdat, "N"), get(&gdat, "HN"), get(&gdat, "J")), ("e2e".into(), "E2eHost".into(), "O".into()));

        let jport = joiner.port();
        joiner.send(b"EGAM", &format!("LID=1\nGID={gid}\nPORT={jport}\nR-INT-IP=0.0.0.0\nR-INT-PORT={jport}\nPTYPE=P\nTID=4\n"));
        assert_eq!(joiner.until(b"EGAM").id, 0);
        let egrq = host.until(b"EGRQ");
        assert_eq!(get(&egrq, "NAME"), "E2eJoiner");
        host.send(b"EGRS", &format!("LID=1\nGID={gid}\nALLOWED=1\nPID={}\nTID=4\n", get(&egrq, "PID")));
        assert_eq!(host.until(b"EGRS").id, 0);
        let egeg = joiner.until(b"EGEG");
        assert_eq!(egeg.id, 0);
        assert_eq!(get(&egeg, "PID"), get(&egrq, "PID"), "the joiner's PID is the one the host was asked about");
        assert_eq!(get(&egeg, "TICKET"), get(&egrq, "TICKET"));
        assert_eq!(get(&egeg, "EKEY"), get(&cgam, "EKEY"), "both games key ProtoTunnel's RC4 with the same EKEY");
        host.send(b"PENT", &format!("LID=1\nGID={gid}\nPID={}\nTID=5\n", get(&egrq, "PID")));
        assert_eq!(get(&host.until(b"PENT"), "PID"), get(&egrq, "PID"));

        // Each game sends to the address Theater gave it for the other, and sees replies come from there.
        let addr = |f: &Frame, ip: &str, port: &str| -> SocketAddr { format!("{}:{}", get(f, ip), get(f, port)).parse().unwrap() };
        let joiner_as_seen_by_host = addr(&egrq, "IP", "PORT");
        let host_as_seen_by_joiner = addr(&egeg, "I", "P");
        assert_eq!(addr(&egrq, "R-INT-IP", "R-INT-PORT"), joiner_as_seen_by_host);
        assert_eq!(addr(&egeg, "INT-IP", "INT-PORT"), host_as_seen_by_joiner);
        let src = deliver(&mut host, &mut joiner, true, false, joiner_as_seen_by_host, b"tunnel h->j");
        assert_eq!(src, host_as_seen_by_joiner);
        let src = deliver(&mut host, &mut joiner, false, false, host_as_seen_by_joiner, b"tunnel j->h");
        assert_eq!(src, joiner_as_seen_by_host);
        // Voice goes to the peer's address on the voice port (the game's fixed 55123 in production).
        let voice_of = |seen: SocketAddr| SocketAddr::new(seen.ip(), seen.port() + 1);
        deliver(&mut host, &mut joiner, true, true, voice_of(joiner_as_seen_by_host), b"voice h->j");
        deliver(&mut host, &mut joiner, false, true, voice_of(host_as_seen_by_joiner), b"voice j->h");

        host.send(b"RGAM", &format!("LID=1\nGID={gid}\nTID=6\n"));
        assert_eq!(host.until(b"RGAM").id, 0);
        assert_eq!(get(&joiner.until(b"GREM"), "GID"), gid);
    }
}
