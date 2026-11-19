//! `Net.LeaderboardGetScore` and `Net.LeaderboardPushScore`, independent of how they are called. Ported from the
//! Blow It Up Again ASI, where they lived until the leaderboards moved here.
//!
//! PS3 v1.03 is the specification (`docs/reverse_engineer/dlc_engine_bindings.md`):
//!
//! * `Net.LeaderboardGetScore(board, cb[, self])` (`0x00537BA0`): a board that is not a string pushes nil (one
//!   value). Otherwise it reads the callback (`0x00504A88`: a function, and a table after it as `self`), and when
//!   the player is online stores it in the one score slot, replacing the one there (a non-function stores
//!   none), queues the request and returns no value. Offline it returns no value and never calls back.
//! * `Net.LeaderboardPushScore(board, score[, cb[, self]])` (`0x00537D98`): online and with the cheats flag clear
//!   (`0x001C18E0() == 0`), else no value and no callback, before any argument is read. Then a board that is not
//!   a string or a score that is not a number pushes nil; otherwise the callback goes into the one push slot
//!   and the score is queued.
//! * A result is delivered on the game thread (`0x000E79F0`, `0x000E7DA8`): the slot is emptied, then the
//!   callback runs as `cb([self,] board, rank, score)` / `cb([self,] status)` and both references are released
//!   (`0x00507AC8`). A score of 0 with rank 0 means "no entry". Every request has a 10 s timeout.
//!
//! On PC "online" is this ASI's session ([`crate::session`]), and the board lives on the multiplayer server
//! (`GET /v1/leaderboards/{board}/me`, `PUT /v1/leaderboards/{board}/score`, [`crate::worker`]). A request that
//! fails (offline, refused, timed out, any error status) logs one line and calls nothing back, as PS3 never
//! called back.

use crate::cheats::CheatsFlag;
use crate::session::{Lookup, Session, SignedIn};
use crate::worker::{BackendFailure, BackendReply, BackendRequest, Bearer, Outcome as WorkerOutcome};
use mercs2_formats::mod_runtime::PCALL_REFUSED;
use mercs2_formats::mod_runtime::lua::{Lua, Ret, TFUNCTION, TTABLE};
use mercs2_mp_api::ErrorCode;
use mercs2_mp_api::rest::LeaderboardEntry;
use std::time::{Duration, Instant};

/// PS3's timeout for every leaderboard request.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// The scores the server takes: whole numbers from 0 to the game's cash cap (`mrxpmc.lua` clamps cash to it).
pub const SCORE_MAX: u32 = mercs2_mp_api::rules::LEADERBOARD_SCORE_MAX;

/// Which slot a callback or a result belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Score,
    Push,
}

impl Kind {
    pub fn binding(self) -> &'static str {
        match self {
            Kind::Score => "Net.LeaderboardGetScore",
            Kind::Push => "Net.LeaderboardPushScore",
        }
    }
}

/// The Lua stack plus the registry references and the protected call a callback needs.
pub trait LuaRefs: Lua {
    /// The global state of the `lua_State` this stack belongs to (`L->l_G`): the registry references live in, shared by the main thread and every
    /// coroutine of it. A load cycle builds a new one.
    fn global(&self) -> usize;
    /// A registry reference to a copy of argument `i` (0-based, as the `arg_*` readers count), or `None`.
    fn ref_arg(&mut self, i: i32) -> Option<i32>;
    /// Release a reference this state's registry holds; false when m2-sdk.dll refused (the reason is in
    /// m2-sdk.log).
    fn unref(&mut self, r: i32) -> bool;
    /// Push the value a reference holds; false when m2-sdk.dll refused and pushed nothing.
    fn push_ref(&mut self, r: i32) -> bool;
    /// Call the function under `nargs` arguments with no results; 0 when it returned, the Lua status of an
    /// error (logged by m2-sdk.dll, the function and arguments popped), or [`PCALL_REFUSED`] when nothing was
    /// called and the stack is unchanged.
    fn pcall(&mut self, nargs: i32) -> i32;
}

/// A callback held in the registry of global state `g`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Callback {
    pub g: usize,
    pub func: i32,
    pub this: Option<i32>,
}

/// The callback at argument `i` (a function) with an optional `self` table after it, as PS3's `0x00504A88`
/// reads it. Anything else is no callback; a `self` that is not a table is not passed.
pub fn read_callback<L: LuaRefs>(s: &mut L, i: i32, log: &mut dyn FnMut(String)) -> Option<Callback> {
    if s.arg_type(i) != TFUNCTION {
        return None;
    }
    let Some(func) = s.ref_arg(i) else {
        log(format!("[!] could not take a registry reference to the callback (argument {})", i + 1));
        return None;
    };
    let this = if s.arg_type(i + 1) == TTABLE {
        match s.ref_arg(i + 1) {
            Some(r) => Some(r),
            None => {
                log(format!("[!] could not take a registry reference to the callback's self (argument {})", i + 2));
                unref_logged(s, func, log);
                return None;
            }
        }
    } else {
        None
    };
    Some(Callback { g: s.global(), func, this })
}

fn unref_logged<L: LuaRefs>(s: &mut L, r: i32, log: &mut dyn FnMut(String)) {
    if !s.unref(r) {
        log(format!("[!] m2_lua_unref refused registry reference {r} (m2-sdk.log has why)"));
    }
}

fn release<L: LuaRefs>(s: &mut L, cb: Option<Callback>, log: &mut dyn FnMut(String)) {
    if let Some(cb) = cb {
        unref_logged(s, cb.func, log);
        if let Some(t) = cb.this {
            unref_logged(s, t, log);
        }
    }
}

/// A score as the server takes it: a whole number in `0..=SCORE_MAX`. The game's numbers are 32-bit floats,
/// so anything else is a script or engine fault, refused rather than rounded or clamped.
pub fn score_value(n: f64) -> Result<u32, String> {
    if !n.is_finite() || n.fract() != 0.0 || !(0.0..=f64::from(SCORE_MAX)).contains(&n) {
        return Err(format!("the score {n} is not a whole number from 0 to {SCORE_MAX}"));
    }
    Ok(n as u32)
}

/// The board as one URL path segment: every byte but the unreserved ones percent-encoded.
pub fn path_segment(board: &[u8]) -> String {
    let mut out = String::with_capacity(board.len());
    for &b in board {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn shown(board: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(board))
}

/// One request for the worker thread.
#[derive(Clone, PartialEq, Eq)]
pub struct Job {
    pub kind: Kind,
    /// The global state and load cycle the call came from.
    pub g: usize,
    pub cycle: u64,
    pub board: Vec<u8>,
    pub token: String,
    /// The score a push sends; `None` for a score request.
    pub score: Option<u32>,
    pub sent: Instant,
}

impl std::fmt::Debug for Job {
    /// The token never reaches a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Job")
            .field("kind", &self.kind)
            .field("g", &self.g)
            .field("cycle", &self.cycle)
            .field("board", &shown(&self.board))
            .field("score", &self.score)
            .finish()
    }
}

impl Job {
    /// The worker's request for this job.
    pub fn request(&self) -> BackendRequest {
        let (board, token) = (self.board.clone(), Bearer(self.token.clone()));
        match (self.kind, self.score) {
            (Kind::Push, Some(score)) => BackendRequest::LeaderboardPush { board, score, token },
            _ => BackendRequest::LeaderboardMe { board, token },
        }
    }
}

/// What a binding needs from the process.
pub trait Env {
    /// This ASI's session, read now.
    fn session(&mut self) -> Lookup;
    /// Hand a request to the worker thread.
    fn send(&mut self, job: Job) -> Result<(), String>;
    fn now(&self) -> Instant;
    fn log(&mut self, line: String);
}

/// What a request came back with, for the game thread.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// `cb([self,] board, rank, score)`; rank 0 and score 0 is "no entry".
    Score { rank: u32, score: f64 },
    /// `cb([self,] status)`, with the server's rank and best score for the log.
    Pushed { rank: u32, best: u32 },
}

/// A finished request.
#[derive(Clone, Debug, PartialEq)]
pub struct Done {
    pub kind: Kind,
    pub g: usize,
    pub cycle: u64,
    pub board: Vec<u8>,
    pub sent: Instant,
    pub result: Result<Outcome, String>,
}

impl Done {
    /// `Net.LeaderboardGetScore("DlcCon001")`, for log lines.
    pub fn what(&self) -> String {
        format!("{}({})", self.kind.binding(), shown(&self.board))
    }
}

/// The two callback slots, the global state they were taken in, and its load cycle.
#[derive(Debug, Default)]
pub struct Leaderboards {
    score: Option<(Callback, u64)>,
    push: Option<(Callback, u64)>,
    global: Option<usize>,
    cycle: u64,
}

/// What a result whose global state is no longer the current one logs.
pub const STATE_CHANGED: &str = "Lua state changed since the request (load cycle)";

fn signed_in(env: &mut impl Env, what: &str) -> Option<SignedIn> {
    match env.session() {
        Ok(Session::SignedIn(s)) => Some(s),
        Ok(Session::SignedOut) => {
            env.log(format!("[*] {what}: not signed in online; nothing sent, no callback"));
            None
        }
        Err(e) => {
            env.log(format!("[!] {what}: the session cannot be read ({e}); nothing sent, no callback"));
            None
        }
    }
}

impl Leaderboards {
    pub const fn new() -> Self {
        Leaderboards { score: None, push: None, global: None, cycle: 0 }
    }

    fn slot(&mut self, kind: Kind) -> &mut Option<(Callback, u64)> {
        match kind {
            Kind::Score => &mut self.score,
            Kind::Push => &mut self.push,
        }
    }

    /// Put `cb` in the slot, releasing the one it replaces when its global state is still the current one.
    fn replace<L: LuaRefs>(&mut self, s: &mut L, kind: Kind, cb: Option<Callback>, log: &mut dyn FnMut(String)) {
        let cycle = self.cycle;
        let old = std::mem::replace(self.slot(kind), cb.map(|c| (c, cycle)));
        if let Some((old, old_cycle)) = old
            && old.g == s.global()
            && old_cycle == cycle
        {
            release(s, Some(old), log);
        }
    }

    /// Note the global state Lua runs on now. A different one than before is a new load cycle (a main-menu
    /// return or a level load builds a fresh global state, whose registry numbers its references from 1 again):
    /// the slots' references name unrelated values there, so they are dropped without a push, a call or a
    /// release, and replies to earlier requests call nothing back. Returns how many callbacks were dropped.
    pub fn observe(&mut self, g: usize) -> usize {
        match self.global {
            Some(cur) if cur == g => 0,
            None => {
                self.global = Some(g);
                0
            }
            Some(_) => {
                self.global = Some(g);
                self.cycle += 1;
                [self.score.take(), self.push.take()].iter().flatten().count()
            }
        }
    }

    fn observe_logged(&mut self, g: usize, log: &mut dyn FnMut(String)) {
        let dropped = self.observe(g);
        if dropped > 0 {
            log(format!("[*] Lua's global state changed (load cycle): {dropped} leaderboard callback(s) of the old one dropped unreleased"));
        }
    }

    /// `Net.LeaderboardGetScore(board, cb[, self])`.
    pub fn get_score<L: LuaRefs>(&mut self, s: &mut L, env: &mut impl Env) -> Ret {
        self.observe_logged(s.global(), &mut |l| env.log(l));
        let what = Kind::Score.binding();
        let Some(board) = s.arg_string(0) else {
            s.push_nil();
            return Ret::Values(1);
        };
        let what = format!("{what}({})", shown(&board));
        let cb = read_callback(s, 1, &mut |l| env.log(format!("{l} in {what}")));
        let Some(who) = signed_in(env, &what) else {
            release(s, cb, &mut |l| env.log(format!("{l} in {what}")));
            return Ret::Values(0);
        };
        self.replace(s, Kind::Score, cb, &mut |l| env.log(format!("{l} in {what}")));
        let job = Job { kind: Kind::Score, g: s.global(), cycle: self.cycle, board, token: who.token, score: None, sent: env.now() };
        if let Err(e) = env.send(job) {
            env.log(format!("[!] {what}: the request was not queued: {e}"));
        }
        Ret::Values(0)
    }

    /// `Net.LeaderboardPushScore(board, score[, cb[, self]])`.
    pub fn push_score<L: LuaRefs, F: CheatsFlag>(&mut self, s: &mut L, env: &mut impl Env, cheats: &F) -> Ret {
        self.observe_logged(s.global(), &mut |l| env.log(l));
        let what = Kind::Push.binding();
        let Some(who) = signed_in(env, what) else {
            return Ret::Values(0);
        };
        match cheats.read() {
            Ok(false) => {}
            Ok(true) => {
                env.log(format!("[*] {what}: cheats were used in this save; no score is pushed (as PS3), no callback"));
                return Ret::Values(0);
            }
            Err(e) => return Ret::Raise(format!("{what}: the cheats flag: {e}")),
        }
        let (Some(board), Some(n)) = (s.arg_string(0), s.arg_number(1)) else {
            s.push_nil();
            return Ret::Values(1);
        };
        let what = format!("{what}({}, {n})", shown(&board));
        let score = match score_value(n) {
            Ok(v) => v,
            Err(e) => {
                env.log(format!("[!] {what}: {e}; nothing sent, no callback"));
                return Ret::Values(0);
            }
        };
        let cb = read_callback(s, 2, &mut |l| env.log(format!("{l} in {what}")));
        self.replace(s, Kind::Push, cb, &mut |l| env.log(format!("{l} in {what}")));
        let job = Job { kind: Kind::Push, g: s.global(), cycle: self.cycle, board, token: who.token, score: Some(score), sent: env.now() };
        if let Err(e) = env.send(job) {
            env.log(format!("[!] {what}: the request was not queued: {e}"));
        }
        Ret::Values(0)
    }

    /// Take the callback a finished request goes to, on a usable state of global state `g`, emptying its slot as
    /// PS3 does before the call. `None` after one log line for every result that calls nothing back, a result
    /// asked on another global state among them. Run the call with [`call`] after letting go of `self`: the
    /// callback may call these bindings again.
    pub fn take(&mut self, g: usize, done: Done, now: Instant, log: &mut dyn FnMut(String)) -> Option<Delivery> {
        self.observe_logged(g, log);
        let what = done.what();
        if done.g != g || done.cycle != self.cycle {
            log(format!("[*] {what}: {STATE_CHANGED}; no callback"));
            return None;
        }
        let outcome = match done.result {
            Err(e) => {
                log(format!("[!] {what}: {e}; no callback"));
                return None;
            }
            Ok(o) => o,
        };
        let waited = now.saturating_duration_since(done.sent);
        if waited > TIMEOUT {
            log(format!("[!] {what}: the reply came after {} ms, past the {} s timeout; no callback", waited.as_millis(), TIMEOUT.as_secs()));
            return None;
        }
        let cycle = self.cycle;
        match self.slot(done.kind).take() {
            Some((cb, c)) if cb.g == g && c == cycle => Some(Delivery { what, cb, board: done.board, outcome }),
            Some(other) => {
                // `observe` empties the slots on every change of global state, so this is never reached; it is
                // kept so a slot of another state is put back, never called.
                *self.slot(done.kind) = Some(other);
                log(format!("[!] {what}: the callback slot belongs to another global state; no callback"));
                None
            }
            None => {
                log(format!("[*] {what}: {outcome:?}; no callback was given"));
                None
            }
        }
    }
}

/// A callback taken out of its slot, with what to call it with.
#[derive(Debug, PartialEq)]
pub struct Delivery {
    what: String,
    cb: Callback,
    board: Vec<u8>,
    outcome: Outcome,
}

/// Call a taken callback on its state, then release its references. Nothing is called when m2-sdk.dll refuses
/// to push the callback or its `self`. m2-sdk.dll has no export that pops a value, so a callback pushed before
/// its `self` was refused stays on the Lua stack, as do the callback and its arguments when `m2_lua_pcall`
/// refuses to call; both are logged as errors.
pub fn call<L: LuaRefs>(s: &mut L, d: Delivery, log: &mut dyn FnMut(String)) {
    let Delivery { what, cb, board, outcome } = d;
    if !s.push_ref(cb.func) {
        log(format!("[!] {what}: m2_lua_push_ref refused the callback (m2-sdk.log has why); not called"));
        release(s, Some(cb), log);
        return;
    }
    let mut nargs = 0;
    if let Some(t) = cb.this {
        if !s.push_ref(t) {
            log(format!(
                "[!] {what}: m2_lua_push_ref refused the callback's self (m2-sdk.log has why); not called, and the \
                 callback stays on the Lua stack (m2-sdk.dll has no export to pop it)"
            ));
            release(s, Some(cb), log);
            return;
        }
        nargs += 1;
    }
    match outcome {
        Outcome::Score { rank, score } => {
            s.push_string(&board);
            s.push_number(f64::from(rank));
            s.push_number(score);
            nargs += 3;
            log(format!("[*] {what}: rank {rank}, score {score}; calling back"));
        }
        Outcome::Pushed { rank, best } => {
            // SPECULATIVE: PS3 passes the status its ranking listener reports (message 0x55, read at 0x000E7DA8);
            // what values that listener sends is unread. 0 is chosen because no caller reads it: every shipped
            // call passes MrxPmc.GetCashQty() as the last argument, and that is one value, so none passes a callback.
            s.push_number(0.0);
            nargs += 1;
            log(format!("[*] {what}: pushed (rank {rank}, best {best}); calling back with status 0"));
        }
    }
    match s.pcall(nargs) {
        0 => {}
        PCALL_REFUSED => log(format!(
            "[!] {what}: m2_lua_pcall refused to call (m2-sdk.log has why); the callback and its {nargs} argument(s) \
             stay on the Lua stack (m2-sdk.dll has no export to pop them)"
        )),
        status => log(format!("[!] {what}: the callback failed with Lua status {status} (the error is in m2-sdk.log)")),
    }
    release(s, Some(cb), log);
}

/// What a standing from the server means for `kind`: rank 0 with score 0 is "no entry" (a score request only),
/// any other entry has a rank from 1.
fn entry(kind: Kind, e: LeaderboardEntry) -> Result<Outcome, String> {
    let LeaderboardEntry { rank, score } = e;
    match kind {
        Kind::Score if rank == 0 && score == 0 => Ok(Outcome::Score { rank: 0, score: 0.0 }),
        Kind::Score if rank >= 1 => Ok(Outcome::Score { rank, score: f64::from(score) }),
        Kind::Push if rank >= 1 => Ok(Outcome::Pushed { rank, best: score }),
        _ => Err(format!("the reply's rank {rank} and score {score} do not describe one entry")),
    }
}

/// Why a request failed, for its log line.
fn failure(f: BackendFailure) -> String {
    match f {
        BackendFailure::Api(e) => match e.code {
            ErrorCode::Unauthorized => format!("the server rejected the session (expired or revoked; log in online again): {}", e.message),
            ErrorCode::Forbidden => format!("the server refused: {}", e.message),
            ErrorCode::InvalidField => format!("the server refused the board or the score: {}", e.message),
            _ => format!("the server answered {e}"),
        },
        BackendFailure::Transport(t) => t,
    }
}

/// `job` finished with the worker's `outcome`.
pub fn finish(job: &Job, outcome: WorkerOutcome) -> Done {
    let result = match outcome {
        Ok(BackendReply::LeaderboardEntry(e)) => entry(job.kind, e),
        // Only the variant's name: a `SessionCreated` holds a token, which never reaches a log line.
        Ok(BackendReply::AccountCreated(_)) => Err("the worker answered a leaderboard request with AccountCreated".into()),
        Ok(BackendReply::SessionCreated(_)) => Err("the worker answered a leaderboard request with SessionCreated".into()),
        Err(f) => Err(failure(f)),
    };
    Done { kind: job.kind, g: job.g, cycle: job.cycle, board: job.board.clone(), sent: job.sent, result }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SignedIn;
    use mercs2_formats::mod_runtime::lua::fake::{FakeLua, Val, s};
    use mercs2_mp_api::ApiError;
    use std::collections::BTreeMap;

    /// An argument: a value FakeLua knows, or a function.
    #[derive(Clone, Debug, PartialEq)]
    enum Arg {
        V(Val),
        Func(u32),
    }

    /// FakeLua's stack plus a registry, a function type, and a record of protected calls.
    struct TestLua {
        l: usize,
        args: Vec<Arg>,
        fake: FakeLua,
        registry: BTreeMap<i32, Arg>,
        next: i32,
        unrefs: Vec<i32>,
        /// Each pcall's function and arguments.
        calls: Vec<Vec<Arg>>,
        stack: Vec<Arg>,
        fail_ref: bool,
        /// References `push_ref` refuses.
        refuse_push: Vec<i32>,
        /// What `pcall` returns; anything but 0 calls nothing.
        pcall_status: i32,
    }

    impl TestLua {
        fn new(l: usize, args: Vec<Arg>) -> Self {
            let fake = FakeLua::with(args.iter().map(|a| if let Arg::V(v) = a { v.clone() } else { Val::Nil }).collect());
            TestLua {
                l,
                args,
                fake,
                registry: BTreeMap::new(),
                next: 1,
                unrefs: vec![],
                calls: vec![],
                stack: vec![],
                fail_ref: false,
                refuse_push: vec![],
                pcall_status: 0,
            }
        }
        fn with_args(mut self, args: Vec<Arg>) -> Self {
            self.fake = FakeLua::with(args.iter().map(|a| if let Arg::V(v) = a { v.clone() } else { Val::Nil }).collect());
            self.fake.pushed.clear();
            self.args = args;
            self
        }
        fn live_refs(&self) -> usize {
            self.registry.len()
        }
    }

    impl Lua for TestLua {
        fn arg_type(&self, i: i32) -> i32 {
            match usize::try_from(i).ok().and_then(|i| self.args.get(i)) {
                Some(Arg::Func(_)) => TFUNCTION,
                _ => self.fake.arg_type(i),
            }
        }
        fn arg_number(&self, i: i32) -> Option<f64> {
            self.fake.arg_number(i)
        }
        fn arg_bool(&self, i: i32) -> Option<bool> {
            self.fake.arg_bool(i)
        }
        fn arg_string(&self, i: i32) -> Option<Vec<u8>> {
            self.fake.arg_string(i)
        }
        fn arg_object(&self, i: i32) -> Option<u32> {
            self.fake.arg_object(i)
        }
        fn push_nil(&mut self) {
            self.fake.push_nil();
            self.stack.push(Arg::V(Val::Nil));
        }
        fn push_bool(&mut self, b: bool) {
            self.fake.push_bool(b);
            self.stack.push(Arg::V(Val::Bool(b)));
        }
        fn push_number(&mut self, n: f64) {
            self.fake.push_number(n);
            self.stack.push(Arg::V(Val::Num(f64::from(n as f32))));
        }
        fn push_string(&mut self, b: &[u8]) {
            self.fake.push_string(b);
            self.stack.push(Arg::V(Val::Str(b.to_vec())));
        }
    }

    impl LuaRefs for TestLua {
        /// `l` names the global state: the tests' states are each their own.
        fn global(&self) -> usize {
            self.l
        }
        fn ref_arg(&mut self, i: i32) -> Option<i32> {
            if self.fail_ref {
                return None;
            }
            let a = self.args.get(i as usize)?.clone();
            let r = self.next;
            self.next += 1;
            self.registry.insert(r, a);
            Some(r)
        }
        fn unref(&mut self, r: i32) -> bool {
            assert!(self.registry.remove(&r).is_some(), "unref of {r}, which is not held (double unref)");
            self.unrefs.push(r);
            true
        }
        fn push_ref(&mut self, r: i32) -> bool {
            if self.refuse_push.contains(&r) {
                return false;
            }
            self.stack.push(self.registry.get(&r).cloned().unwrap_or(Arg::V(Val::Nil)));
            true
        }
        fn pcall(&mut self, nargs: i32) -> i32 {
            if self.pcall_status == PCALL_REFUSED {
                return PCALL_REFUSED;
            }
            let at = self.stack.len() - nargs as usize - 1;
            let called = self.stack.split_off(at);
            if self.pcall_status == 0 {
                self.calls.push(called);
            }
            self.pcall_status
        }
    }

    struct TestEnv {
        session: Lookup,
        sent: Vec<Job>,
        logs: Vec<String>,
        now: Instant,
    }

    fn env() -> TestEnv {
        TestEnv {
            session: Ok(Session::SignedIn(SignedIn { token: "TOKEN".into(), username: "Mattias".into() })),
            sent: vec![],
            logs: vec![],
            now: Instant::now(),
        }
    }

    impl Env for TestEnv {
        fn session(&mut self) -> Lookup {
            self.session.clone()
        }
        fn send(&mut self, job: Job) -> Result<(), String> {
            self.sent.push(job);
            Ok(())
        }
        fn now(&self) -> Instant {
            self.now
        }
        fn log(&mut self, line: String) {
            assert!(!line.contains("TOKEN"), "a log line carries the token: {line}");
            self.logs.push(line);
        }
    }

    struct Flag(bool);
    impl CheatsFlag for Flag {
        fn read(&self) -> Result<bool, String> {
            Ok(self.0)
        }
        fn write(&mut self, used: bool) -> Result<(), String> {
            self.0 = used;
            Ok(())
        }
    }

    fn v(x: Val) -> Arg {
        Arg::V(x)
    }
    fn st(t: &str) -> Arg {
        Arg::V(s(t))
    }

    fn standing(rank: u32, score: u32) -> WorkerOutcome {
        Ok(BackendReply::LeaderboardEntry(LeaderboardEntry { rank, score }))
    }

    fn api(code: ErrorCode, message: &str) -> WorkerOutcome {
        Err(BackendFailure::Api(ApiError::new(code, message)))
    }

    /// What the tick does: take under the lock, call after.
    fn deliver(lb: &mut Leaderboards, l: &mut TestLua, d: Done, now: Instant, log: &mut dyn FnMut(String)) {
        if let Some(x) = lb.take(l.l, d, now, log) {
            call(l, x, log);
        }
    }

    fn done(job: &Job, result: Result<Outcome, String>) -> Done {
        Done { kind: job.kind, g: job.g, cycle: job.cycle, board: job.board.clone(), sent: job.sent, result }
    }

    #[test]
    fn get_score_with_a_board_that_is_not_a_string_pushes_nil_before_anything_else() {
        for args in [vec![], vec![v(Val::Num(1.0)), Arg::Func(1)], vec![v(Val::Nil)], vec![v(Val::Table)]] {
            let mut l = TestLua::new(7, args.clone());
            let mut e = TestEnv { session: Ok(Session::SignedOut), ..env() };
            assert_eq!(Leaderboards::default().get_score(&mut l, &mut e), Ret::Values(1), "{args:?}");
            assert_eq!(l.fake.pushed, [Val::Nil], "{args:?}");
            assert!(e.sent.is_empty() && e.logs.is_empty() && l.live_refs() == 0, "{args:?}");
        }
    }

    #[test]
    fn get_score_queues_the_me_request_and_holds_the_callback() {
        let mut l = TestLua::new(7, vec![st("DlcCon001"), Arg::Func(1)]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        assert_eq!(lb.get_score(&mut l, &mut e), Ret::Values(0));
        assert!(l.fake.pushed.is_empty(), "no value is returned");
        let [job] = &e.sent[..] else { panic!("{:?}", e.sent) };
        assert_eq!((job.kind, job.board.as_slice(), job.token.as_str(), job.score, job.g), (Kind::Score, &b"DlcCon001"[..], "TOKEN", None, 7));
        assert_eq!(
            job.request(),
            BackendRequest::LeaderboardMe { board: b"DlcCon001".to_vec(), token: Bearer("TOKEN".into()) }
        );
        assert_eq!(l.live_refs(), 1);
        assert!(!format!("{job:?}").contains("TOKEN"));
    }

    #[test]
    fn offline_or_an_unreadable_session_sends_nothing_and_releases_the_refs() {
        for (session, want) in [
            (Ok(Session::SignedOut), "not signed in"),
            (Err("the session lock is poisoned".to_string()), "the session lock is poisoned"),
        ] {
            let mut l = TestLua::new(7, vec![st("DlcCon001"), Arg::Func(1), v(Val::Table)]);
            let mut e = TestEnv { session, ..env() };
            let mut lb = Leaderboards::default();
            assert_eq!(lb.get_score(&mut l, &mut e), Ret::Values(0));
            assert!(e.sent.is_empty(), "{want}");
            assert_eq!(l.live_refs(), 0, "PS3 leaks these; this releases them: {want}");
            let [line] = &e.logs[..] else { panic!("{:?}", e.logs) };
            assert!(line.contains(want) && line.contains("DlcCon001"), "{line}");
        }
    }

    #[test]
    fn the_score_callback_runs_once_with_self_board_rank_and_score_then_is_released() {
        let mut l = TestLua::new(7, vec![st("DlcCon002"), Arg::Func(10), v(Val::Table)]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        lb.get_score(&mut l, &mut e);
        let job = e.sent.pop().unwrap();
        let d = finish(&job, standing(3, 250000));
        let mut logs = vec![];
        deliver(&mut lb, &mut l, d.clone(), e.now, &mut |x| logs.push(x));
        assert_eq!(l.calls, [vec![Arg::Func(10), v(Val::Table), st("DlcCon002"), v(Val::Num(3.0)), v(Val::Num(250000.0))]]);
        assert_eq!(l.live_refs(), 0);
        deliver(&mut lb, &mut l, d, e.now, &mut |x| logs.push(x));
        assert_eq!(l.calls.len(), 1, "one-shot: the slot was emptied");
        assert!(logs.last().unwrap().contains("no callback was given"), "{logs:?}");
    }

    #[test]
    fn no_entry_is_rank_0_score_0() {
        let mut l = TestLua::new(7, vec![st("DlcCon003"), Arg::Func(10)]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        lb.get_score(&mut l, &mut e);
        let job = e.sent.pop().unwrap();
        deliver(&mut lb, &mut l, finish(&job, standing(0, 0)), e.now, &mut |_| {});
        assert_eq!(l.calls, [vec![Arg::Func(10), st("DlcCon003"), v(Val::Num(0.0)), v(Val::Num(0.0))]]);
    }

    #[test]
    fn a_failed_request_logs_one_line_and_calls_nothing_back() {
        let job_for = |lb: &mut Leaderboards, l: &mut TestLua| {
            let mut e = env();
            lb.get_score(l, &mut e);
            e.sent.pop().unwrap()
        };
        for (outcome, want) in [
            (Err(BackendFailure::Transport("cannot connect to mp.example:443: refused".to_string())), "cannot connect"),
            (api(ErrorCode::Unauthorized, "session token unknown or expired"), "rejected the session (expired or revoked; log in online again)"),
            (api(ErrorCode::Forbidden, "this account is banned from leaderboards"), "banned from leaderboards"),
            (api(ErrorCode::InvalidField, "board: must be 1-32 ASCII letters"), "refused the board or the score: board: must be"),
            (api(ErrorCode::Internal, "internal error"), "Internal: internal error"),
            (standing(0, 5), "rank 0 and score 5 do not describe one entry"),
            (Ok(BackendReply::AccountCreated(mercs2_mp_api::rest::AccountCreated { user_id: mercs2_mp_api::UserId(1), username: "u".into() })), "answered a leaderboard request with"),
        ] {
            let mut l = TestLua::new(7, vec![st("DlcCon001"), Arg::Func(10)]);
            let mut lb = Leaderboards::default();
            let job = job_for(&mut lb, &mut l);
            let d = finish(&job, outcome);
            let mut logs = vec![];
            deliver(&mut lb, &mut l, d, job.sent, &mut |x| logs.push(x));
            assert!(l.calls.is_empty(), "{want}");
            let [line] = &logs[..] else { panic!("{logs:?}") };
            assert!(line.contains(want) && line.contains("Net.LeaderboardGetScore(\"DlcCon001\")"), "{want}: {line}");
        }
    }

    #[test]
    fn a_refused_push_leaves_no_callback() {
        // 401, 403 and 422 from PUT .../score: PS3 never called back on a failure.
        for code in [ErrorCode::Unauthorized, ErrorCode::Forbidden, ErrorCode::InvalidField] {
            let mut l = TestLua::new(7, vec![st("DlcCon001"), v(Val::Num(5.0)), Arg::Func(3)]);
            let mut e = env();
            let mut lb = Leaderboards::default();
            lb.push_score(&mut l, &mut e, &Flag(false));
            let job = e.sent.pop().unwrap();
            let mut logs = vec![];
            deliver(&mut lb, &mut l, finish(&job, api(code, "no")), e.now, &mut |x| logs.push(x));
            assert!(l.calls.is_empty() && l.stack.is_empty(), "{code:?}");
            assert!(logs[0].contains("no callback"), "{code:?}: {logs:?}");
        }
    }

    #[test]
    fn a_reply_past_10_seconds_is_dropped() {
        let mut l = TestLua::new(7, vec![st("DlcCon001"), Arg::Func(10)]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        lb.get_score(&mut l, &mut e);
        let job = e.sent.pop().unwrap();
        let d = done(&job, Ok(Outcome::Score { rank: 1, score: 5.0 }));
        let mut logs = vec![];
        deliver(&mut lb, &mut l, d.clone(), job.sent + TIMEOUT + Duration::from_millis(1), &mut |x| logs.push(x));
        assert!(l.calls.is_empty() && logs[0].contains("timeout"), "{logs:?}");
        deliver(&mut lb, &mut l, d, job.sent + TIMEOUT, &mut |x| logs.push(x));
        assert_eq!(l.calls.len(), 1, "10 s exactly is in time");
    }

    #[test]
    fn a_new_call_replaces_the_slot_and_releases_the_old_callback() {
        let mut l = TestLua::new(7, vec![st("DlcCon001"), Arg::Func(10), v(Val::Table)]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        lb.get_score(&mut l, &mut e);
        assert_eq!(l.live_refs(), 2);
        let mut l = l.with_args(vec![st("DlcCon002"), Arg::Func(11)]);
        lb.get_score(&mut l, &mut e);
        assert_eq!((l.live_refs(), l.unrefs.clone()), (1, vec![1, 2]));
        // The first request's reply goes to the callback now in the slot, as PS3's one slot does.
        let first = e.sent.remove(0);
        deliver(&mut lb, &mut l, finish(&first, standing(2, 9)), e.now, &mut |_| {});
        assert_eq!(l.calls, [vec![Arg::Func(11), st("DlcCon001"), v(Val::Num(2.0)), v(Val::Num(9.0))]]);
        // A call without a function empties the slot.
        let mut l = l.with_args(vec![st("DlcCon003"), Arg::Func(12)]);
        lb.get_score(&mut l, &mut e);
        let mut l = l.with_args(vec![st("DlcCon003"), v(Val::Nil)]);
        lb.get_score(&mut l, &mut e);
        assert_eq!(l.live_refs(), 0);
    }

    #[test]
    fn a_self_that_is_not_a_table_is_not_passed_and_a_failed_ref_is_no_callback() {
        let mut l = TestLua::new(7, vec![st("DlcCon001"), Arg::Func(10), st("not a table")]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        lb.get_score(&mut l, &mut e);
        assert_eq!(l.live_refs(), 1);
        let mut lb = Leaderboards::default();
        let mut l = TestLua::new(7, vec![st("DlcCon001"), Arg::Func(10)]);
        l.fail_ref = true;
        let mut e = env();
        lb.get_score(&mut l, &mut e);
        assert_eq!(e.sent.len(), 1, "the request still goes; there is no callback for it");
        assert!(e.logs[0].contains("could not take a registry reference"), "{:?}", e.logs);
    }

    #[test]
    fn a_refused_push_ref_calls_nothing_and_releases_the_refs() {
        // The callback itself refused: nothing is on the stack and nothing is called.
        let mut l = TestLua::new(7, vec![st("DlcCon001"), Arg::Func(10), v(Val::Table)]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        lb.get_score(&mut l, &mut e);
        let job = e.sent.pop().unwrap();
        l.refuse_push = vec![1];
        let mut logs = vec![];
        deliver(&mut lb, &mut l, finish(&job, standing(1, 1)), e.now, &mut |x| logs.push(x));
        assert!(l.calls.is_empty() && l.stack.is_empty() && l.live_refs() == 0, "{logs:?}");
        assert!(logs.iter().any(|x| x.contains("refused the callback (m2-sdk.log has why); not called")), "{logs:?}");

        // Its self refused after the callback was pushed: not called; the callback stays on the stack.
        let mut l = TestLua::new(7, vec![st("DlcCon001"), Arg::Func(10), v(Val::Table)]);
        let mut lb = Leaderboards::default();
        lb.get_score(&mut l, &mut e);
        let job = e.sent.pop().unwrap();
        l.refuse_push = vec![2];
        let mut logs = vec![];
        deliver(&mut lb, &mut l, finish(&job, standing(1, 1)), e.now, &mut |x| logs.push(x));
        assert!(l.calls.is_empty() && l.live_refs() == 0, "{logs:?}");
        assert_eq!(l.stack, [Arg::Func(10)]);
        assert!(logs.iter().any(|x| x.contains("refused the callback's self") && x.contains("stays on the Lua stack")), "{logs:?}");
    }

    #[test]
    fn a_refused_or_failed_pcall_is_logged_and_the_refs_released() {
        for (status, want) in [(PCALL_REFUSED, "m2_lua_pcall refused to call"), (2, "failed with Lua status 2")] {
            let mut l = TestLua::new(7, vec![st("DlcCon001"), Arg::Func(10)]);
            let mut e = env();
            let mut lb = Leaderboards::default();
            lb.get_score(&mut l, &mut e);
            let job = e.sent.pop().unwrap();
            l.pcall_status = status;
            let mut logs = vec![];
            deliver(&mut lb, &mut l, finish(&job, standing(1, 1)), e.now, &mut |x| logs.push(x));
            assert!(l.calls.is_empty() && l.live_refs() == 0, "{want}");
            assert!(logs.iter().any(|x| x.contains(want)), "{want}: {logs:?}");
            if status == PCALL_REFUSED {
                assert_eq!(l.stack.len(), 4, "the callback and its three arguments stay: {:?}", l.stack);
            } else {
                assert!(l.stack.is_empty());
            }
        }
    }

    #[test]
    fn a_reply_after_the_global_state_changed_is_dropped_without_a_push_call_or_unref() {
        let mut old = TestLua::new(7, vec![st("DlcCon001"), Arg::Func(10), v(Val::Table)]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        lb.get_score(&mut old, &mut e);
        let job = e.sent.pop().unwrap();
        // The tick now runs on a new global state (a load cycle): its registry numbers refs from 1 again.
        let mut new = TestLua::new(8, vec![]);
        new.registry.insert(1, Arg::Func(99));
        new.registry.insert(2, v(Val::Table));
        let mut logs = vec![];
        deliver(&mut lb, &mut new, done(&job, Ok(Outcome::Score { rank: 1, score: 1.0 })), e.now, &mut |x| logs.push(x));
        assert!(new.calls.is_empty() && new.stack.is_empty() && new.unrefs.is_empty(), "nothing touches the new registry");
        assert_eq!(new.live_refs(), 2, "the new state's own refs 1 and 2 are left alone");
        assert!(logs.iter().any(|l| l.contains("1 leaderboard callback(s) of the old one dropped unreleased")), "{logs:?}");
        let last = logs.last().unwrap();
        assert!(last.contains("DlcCon001") && last.contains(STATE_CHANGED), "{last}");
    }

    #[test]
    fn a_new_call_on_a_new_global_state_does_not_release_the_old_states_refs() {
        let mut old = TestLua::new(7, vec![st("DlcCon001"), Arg::Func(10)]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        lb.get_score(&mut old, &mut e);
        let mut new = TestLua::new(8, vec![st("DlcCon001"), Arg::Func(20)]);
        new.registry.insert(1, Arg::Func(99));
        new.next = 2;
        lb.get_score(&mut new, &mut e);
        assert!(new.unrefs.is_empty() && new.registry.contains_key(&1), "ref 1 of the new state is someone else's");
        // The new call's own reply is delivered on the new state.
        let job = e.sent.pop().unwrap();
        deliver(&mut lb, &mut new, done(&job, Ok(Outcome::Score { rank: 5, score: 7.0 })), e.now, &mut |_| {});
        assert_eq!(new.calls, [vec![Arg::Func(20), st("DlcCon001"), v(Val::Num(5.0)), v(Val::Num(7.0))]]);
        assert_eq!(new.unrefs, [2]);
    }

    #[test]
    fn a_reply_on_the_same_global_state_is_delivered() {
        let mut l = TestLua::new(7, vec![st("DlcCon004"), Arg::Func(10)]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        lb.get_score(&mut l, &mut e);
        let job = e.sent.pop().unwrap();
        assert_eq!(job.g, 7);
        let mut logs = vec![];
        deliver(&mut lb, &mut l, done(&job, Ok(Outcome::Score { rank: 2, score: 3.0 })), e.now, &mut |x| logs.push(x));
        assert_eq!(l.calls.len(), 1, "{logs:?}");
        assert!(!logs.iter().any(|x| x.contains(STATE_CHANGED)), "{logs:?}");
    }

    #[test]
    fn push_is_gated_on_the_session_and_the_cheats_flag_before_any_argument() {
        for (session, cheats, want) in [
            (Ok(Session::SignedOut), false, "not signed in"),
            (Err("the session lock is poisoned".to_string()), false, "poisoned"),
            (Ok(Session::SignedIn(SignedIn { token: "TOKEN".into(), username: "u".into() })), true, "cheats were used"),
        ] {
            for args in [vec![], vec![st("DlcCon001"), v(Val::Num(5.0)), Arg::Func(1)]] {
                let mut l = TestLua::new(7, args.clone());
                let mut e = TestEnv { session: session.clone(), ..env() };
                assert_eq!(Leaderboards::default().push_score(&mut l, &mut e, &Flag(cheats)), Ret::Values(0), "{want} {args:?}");
                assert!(l.fake.pushed.is_empty() && e.sent.is_empty() && l.live_refs() == 0, "{want} {args:?}");
                assert!(e.logs[0].contains(want), "{:?}", e.logs);
            }
        }
    }

    #[test]
    fn push_with_a_bad_board_or_score_pushes_nil() {
        for args in [vec![], vec![v(Val::Num(1.0)), v(Val::Num(5.0))], vec![st("DlcCon001")], vec![st("DlcCon001"), st("x")]] {
            let mut l = TestLua::new(7, args.clone());
            let mut e = env();
            assert_eq!(Leaderboards::default().push_score(&mut l, &mut e, &Flag(false)), Ret::Values(1), "{args:?}");
            assert_eq!(l.fake.pushed, [Val::Nil], "{args:?}");
            assert!(e.sent.is_empty(), "{args:?}");
        }
    }

    #[test]
    fn push_refuses_a_score_the_server_cannot_hold() {
        for n in [-1.0, 0.5, 1_000_000_064.0, f64::NAN, f64::INFINITY] {
            let mut l = TestLua::new(7, vec![st("DlcCon001"), v(Val::Num(n)), Arg::Func(1)]);
            let mut e = env();
            assert_eq!(Leaderboards::default().push_score(&mut l, &mut e, &Flag(false)), Ret::Values(0), "{n}");
            assert!(e.sent.is_empty() && l.live_refs() == 0, "{n}");
            assert!(e.logs[0].contains("not a whole number from 0 to 1000000000"), "{:?}", e.logs);
        }
        assert_eq!(score_value(0.0), Ok(0));
        assert_eq!(score_value(1e9), Ok(SCORE_MAX));
    }

    #[test]
    fn push_sends_the_score_and_calls_back_with_status_0() {
        let mut l = TestLua::new(7, vec![st("DlcCon004"), v(Val::Num(123456.0)), Arg::Func(3), v(Val::Table)]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        assert_eq!(lb.push_score(&mut l, &mut e, &Flag(false)), Ret::Values(0));
        let job = e.sent.pop().unwrap();
        assert_eq!(
            job.request(),
            BackendRequest::LeaderboardPush { board: b"DlcCon004".to_vec(), score: 123456, token: Bearer("TOKEN".into()) }
        );
        let mut logs = vec![];
        deliver(&mut lb, &mut l, finish(&job, standing(4, 200000)), e.now, &mut |x| logs.push(x));
        assert_eq!(l.calls, [vec![Arg::Func(3), v(Val::Table), v(Val::Num(0.0))]]);
        assert_eq!(l.live_refs(), 0);
        assert!(logs[0].contains("rank 4, best 200000"), "{logs:?}");
    }

    #[test]
    fn a_push_answered_with_no_entry_is_an_error() {
        let mut l = TestLua::new(7, vec![st("DlcCon004"), v(Val::Num(1.0)), Arg::Func(3)]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        lb.push_score(&mut l, &mut e, &Flag(false));
        let job = e.sent.pop().unwrap();
        let mut logs = vec![];
        deliver(&mut lb, &mut l, finish(&job, standing(0, 0)), e.now, &mut |x| logs.push(x));
        assert!(l.calls.is_empty() && logs[0].contains("do not describe one entry"), "{logs:?}");
    }

    #[test]
    fn the_dlcs_own_push_has_no_callback_and_sends_the_cash() {
        // dlccon001.lua:695: Net.LeaderboardPushScore("DlcCon001", MrxPmc.GetCashQty()) with one value.
        let mut l = TestLua::new(7, vec![st("DlcCon001"), v(Val::Num(50000.0))]);
        let mut e = env();
        let mut lb = Leaderboards::default();
        assert_eq!(lb.push_score(&mut l, &mut e, &Flag(false)), Ret::Values(0));
        let job = e.sent.pop().unwrap();
        assert_eq!(job.score, Some(50000));
        let mut logs = vec![];
        deliver(&mut lb, &mut l, finish(&job, standing(1, 50000)), e.now, &mut |x| logs.push(x));
        assert!(l.calls.is_empty() && logs[0].contains("no callback was given"), "{logs:?}");
    }

    #[test]
    fn a_board_is_one_encoded_path_segment() {
        assert_eq!(path_segment(b"DlcCon001"), "DlcCon001");
        assert_eq!(path_segment(b"a/b c?%"), "a%2Fb%20c%3F%25");
        assert_eq!(path_segment(&[0xc3, 0xa9]), "%C3%A9");
    }
}
