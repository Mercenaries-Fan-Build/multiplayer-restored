# multiplayer-restored — in-game test plan

Run before anything is committed. Each step names what to do, what `multiplayer_restored.log` (next to the
ASI) must show, and what to send back. Stop at the first step that fails and send the log plus a screenshot.
Line references are to the client source (`client/src/…`).

## Artifacts

| File | From | sha256 (record before AND after copying) |
|---|---|---|
| `multiplayer_restored.asi` | `client/scripts/build_asi.sh` → `src/multiplayer_restored.asi` | printed by the build script |
| `multiplayer_restored.ini` | `src/multiplayer_restored.ini` (set `[server] base_url`) | — (edited per machine) |

The ASI and ini go in the folder pmc_bb loads plugins from (`scripts\`). Check the hashes with
`certutil -hashfile <file> SHA256` on Windows.

## 0. Server (DigitalOcean)

Follow the server's `README.md` (https://github.com/Mercenaries-Fan-Build/multiplayer-server) → "Deploy on a VM with a public IP", with the Let's Encrypt
**production** directory (the ASI trusts only the public CA bundle, so a staging certificate is refused).

- `openssl s_client -connect <domain>:443 -servername <domain> -tls1_3 </dev/null` → `Protocol : TLSv1.3`,
  issuer Let's Encrypt.
- `docker compose logs mp-server` stays free of errors; keep it open during the test.
- `[games] max_players_limit = 2`.

## 1. Start-up (one PC)

Start the game and stay on the main menu.

- The m2-sdk Shipment is installed: `m2-sdk.dll` is in the game root. Without it the ASI is not loaded at all
  and `pmc_blackbox.log` shows `[FAILED] multiplayer_restored.asi`.
- Log shows, in this order (each line's timestamp shows how long the step before it took):
  1. `m2-sdk.dll 0.4.x (built against 0.4.0)` (`win/mod.rs:346`);
  2. `signature <Fn> -> 0x…` for all eight ProtoSSL functions (`:351`), then `build .text sha256 …` (`:353`),
     then `signature GVInitialize -> 0x…` and `signature GVStartup -> 0x…` (`:356`);
  3. `signature OnlineAccountClear -> 0x… (account name 0x…, password 0x…)` (`lua/win.rs:106`), then `Lua
     namespace Mp (GetRoomKey, SetRoomKey, Logout) added through m2-sdk.dll` (`lua/win.rs:118`);
  4. `TLS connector ready (CA bundle loaded)` (`win/mod.rs:361`), `runtime ready (worker thread, connection
     table)` (`:417`), then `ProtoSSL detours installed: Connect Disconnect Destroy Update Send Recv Stat` (`:419`)
     and `GameSpy Voice disabled (GVInitialize, GVStartup detoured); use external voice chat` (`:420`).
- **Failure looks like:** a message box naming the problem, then the game exits. Send the box text + log.
- Send back: the `build .text sha256` value and which exe you ran (retail / bypass / nodrm). That value pins
  the build in the ASI's table.

## 2. Account + login

Online → **Create Account** with a new username (3–31 letters/digits/`_-.`) and a password (8+ chars).

- Log: `AddAccount: account "<name>" created (user N)` (`fesl.rs:501`). Server log: one `POST /v1/accounts` 201.
- Then **Login** with it. Log: `Login: "<name>" logged in as "<name>" (user N)` (`fesl.rs:485`), then
  `lobby WebSocket connected to <domain>` (`ws.rs:245`).
- Negative: log in with a wrong password → the game shows its "account not found" message (code 101); log
  `Login: server refused: …` (`fesl.rs:507`).
- Negative: create the same username again → the game shows an error; log `server refused: … name_taken`.
- Send back: the exact on-screen text for both negatives (it tells us which game strings the codes map to).

## 3. Lobby + Theater

After login, open the online game list.

- Log: `ProtoSSL ref 0x…: Theater connect served in-process` (`vconn.rs:224`), then `pnow Start N … games.list`
  and `pnow Status N: 0 game(s)` (`fesl.rs:550-593`) — the empty list must render, not hang.
- Any `connection refused: …` or `virtual … failed during …` (`vconn.rs:160/186`) is a failure: send it. It
  names the Theater/FESL message the game sent that we don't handle yet.

## 4. Lua bindings (menu delivery on hold)

How the menu Lua (`src/mp_menu.lua`) reaches the front end is undecided — it is not in the manifest — so the
in-game menu is not part of this run. The ASI still registers the `Mp` namespace:

- Log: `Lua namespace Mp … added through m2-sdk.dll`; and in `m2-sdk.log` (game root), once the front end is
  up, `registered Lua namespace Mp on lua_State 0x…`.
- Room keys for steps 6–7 come from `[privacy] room_key` in the ini.

## 5. Friends path probe

Click through every Friends screen, including **Find Friend** (type any name).

- Send back the full log for this step. It answers whether the game uses FESL `asso` (lines naming
  `asso <TXN>`) or Messenger (a `connection refused: … messenger` line) — static analysis couldn't.

## 6. Two-PC co-op (the real test)

PC **A** hosts, PC **B** joins. Put **B behind a phone hotspot** (CGNAT) if you can.

1. A: host a co-op game. Log A: `hosting game G (relay slot 0)` (`theater.rs:854`). Send the MAX-PLAYERS
   value from the CGAM line — if the server refuses because it is above 2, the log says so.
2. B: open the list → A's game appears (`pnow Status N: 1 game(s)`). Join it.
   - Log B: `join request J for game G queued with the host` (`:864`).
   - Log A: `join request J: "<B>" (user …) asks to join game G` (`:991`).
   - Log B: `joined game G hosted by "<A>" as PID P` (`:1068`), `relay slot 0 of game G is 127.0.0.2:10010 …`
     (`relay.rs:553`).
   - Neither game crashes on the join; the game's built-in voice chat stays off (no `GVInitialize` socket),
     on every OS.
3. Both in game: play a few minutes — move, shoot, enter a vehicle together.
   - Any `alias for slot … got a datagram from …, not the game; dropped` (`relay.rs:515`) or
     `relay session for game G failed: …` (`:215`) → send the log.
4. Network check on B: `netstat -ano | findstr <A's public IP>` shows nothing. B only talks to the server.
5. B leaves → A logs `game G: "<B>" (PID P) left`. A ends the game → B (if still listed) sees it vanish.
6. Host quits while B is in: A ends or quits the game → B's log shows `game G: removed on the server; relay
   session ends`, then the game's ECNL is answered once (no `ECNL for game G, which this client is neither in
   nor joining` errors and no repeated `a new Theater connection takes over` lines); B returns to the lobby.

## 7. Room keys between two PCs

A sets `room_key = 0012345` in the ini and hosts. B with `room_key = none` → game **not** listed. B sets
`0012345` (restart) → listed and joinable. B sets `0099999` → not listed.

## Send back after the run

`multiplayer_restored.log` from both PCs, `docker compose logs mp-server`, the sha256 table above, screenshots of
any message box or wrong-looking screen, and the answers asked for in steps 1, 2, 4, 5 and 6.1.
