# Multiplayer Restored

A Mercenaries 2: World in Flames Shipment that brings back online co-op against a self-hostable server.

The game's EA online services (FESL and Theater) are answered inside the game process by
`multiplayer_restored.asi`. Accounts, the lobby and gameplay traffic go to a
[multiplayer server](https://github.com/Mercenaries-Fan-Build/multiplayer-server) over HTTPS and a DTLS
relay, so no player's address is shown to another player.

## What it installs

| File | Where | What it is |
|---|---|---|
| `multiplayer_restored.asi` | `scripts\` | The client plugin. It finds the game's ProtoSSL and GameSpy Voice functions by byte signature and stops the game with a message if the exe does not match. |
| `multiplayer_restored.ini` | `scripts\` | Required settings; the plugin refuses to start without it, or with a missing or unknown key. |

It requires the [m2-sdk](https://github.com/Mercenaries-Fan-Build/mercs2-sdk) Shipment (`^0.4`), which places
`m2-sdk.dll` in the game root: the plugin imports it, every hook it installs goes through the SDK's shared
MinHook instance, and its `Mp` Lua namespace is registered through the SDK's Lua host. Without that DLL
Windows does not load the plugin at all.

## Setup

1. Install the Shipment with the Modkit or `qm`.
2. Edit `scripts\multiplayer_restored.ini`:
   - `[server] base_url` — the HTTPS address of the server you play on. The shipped `https://mp.invalid`
     never resolves.
   - `[privacy] room_key` — `none` to see public games, or a key of 6–32 letters, digits or `-`; you
     then see and join only games hosted with exactly the same key.
3. Start the game, choose the online option and create an account or log in.

Games hold at most two players: the host and one joiner.

The game's built-in voice chat (GameSpy Voice) is turned off: the plugin detours its start-up so it never
opens a socket or an audio device. Use external voice chat such as Discord. Both players need the same
plugin version; a player whose plugin still forwards in-game voice ends the session with a message saying so.

## For other mods

### The signed-in session: `mr_session_v1`

The plugin exports one function besides `DllMain`, declared in
[`client/include/multiplayer_restored.h`](client/include/multiplayer_restored.h):

```c
typedef struct { uint32_t struct_size; char server_base_url[256]; char token[512]; char username[64]; } MrSessionV1;
int __cdecl mr_session_v1(MrSessionV1 *out);
```

It hands another mod the multiplayer-server session the player signed in with this run (the game's online
**Login**), so that mod can call the server's API as the player with `Authorization: Bearer <token>`.

- **1:** signed in. `*out` holds the server's base URL, the bearer token and the username.
  - The URL is the `[server] base_url` of the ini in canonical form: `https://host[:port][/prefix]`, with the
    port only when it is not 443 and no trailing slash.
  - Every string is NUL-terminated UTF-8.
- **0:** not signed in, including while the plugin is still starting up. `*out` is all zero except
  `struct_size`.
- **-1:** an error, in one of three cases:
  - `out` is NULL, or `out->struct_size` is not `sizeof(MrSessionV1)` (836). Nothing is written.
  - A value does not fit its field. Values are never truncated; `*out` is all zero except `struct_size`, and
    the reason goes to `multiplayer_restored.log`.
  - An internal error. Handled like a value that does not fit.

The session lasts until `Mp.Logout` or the next Login. The token expires when the server says it does; the
server answers an expired or revoked token with HTTP 401. `Mp.Logout` ends the plugin's own use of the token
but does not revoke it (the server's API has no route for that), so a copy a mod took earlier stays valid
until its expiry.

The function is thread-safe and never touches the network. A mod resolves it when it needs it, not in its own
`DllMain`, because the plugin load order is not guaranteed:

```c
HMODULE mr = GetModuleHandleA("multiplayer_restored.asi");
mr_session_v1_fn get = mr ? (mr_session_v1_fn)(void (*)(void))GetProcAddress(mr, "mr_session_v1") : NULL;
```

A mod that uses it lists `{ shipment: multiplayer-restored, version: ">=0.6.0" }` under `load.requires` in its
manifest. A later field means a new `MrSessionV2` and `mr_session_v2`; V1 never changes.

### The HTTPS client: `mercs2_https`

`client/mercs2_https` is the plugin's REST client and TLS policy as a crate other ASIs can use, so they reach
a server under the same trust policy:

- OpenSSL 3, statically linked;
- TLS 1.2 or later, with forward-secret AEAD cipher suites only;
- certificate chains verified against only the embedded Mozilla CA bundle (`client/mercs2_https/ca/`), with
  hostname verification against the certificate's subjectAltName (never its subject CN);
- one blocking request per connection, run from a worker thread, within the caller's `Limits`: connect, I/O
  and whole-request timeouts, and a response body cap sized from the server's API.

Depend on it by this repository's release tag; its test fixtures (`mercs2_https::testing`) are behind the
`testing` feature, for `[dev-dependencies]` only:

```toml
[dependencies]
mercs2_https = { git = "https://github.com/Mercenaries-Fan-Build/multiplayer-restored", tag = "v0.6.0" }

[dev-dependencies]
mercs2_https = { git = "https://github.com/Mercenaries-Fan-Build/multiplayer-restored", tag = "v0.6.0", features = ["testing"] }
```

## Running a server

See the server's README: <https://github.com/Mercenaries-Fan-Build/multiplayer-server>. Its
`max_players_limit` should stay at `2` for this client.

## Building from source

The plugin is built from `client/` for `i686-pc-windows-gnu`; the Rust toolchain is pinned in
`client/rust-toolchain.toml`.

```bash
cd client
bash scripts/fetch_dw2_libgcc.sh   # once per rustc version
bash scripts/build_asi.sh          # writes ../src/multiplayer_restored.asi
cargo test --workspace             # the plugin and mercs2_https
```

Needs `i686-w64-mingw32-gcc` on `PATH`. The m2-sdk.dll bindings, PE reader and signature scanner come from
the published `mercs2_formats` crate. Some tests read the reference executables from the research
repository's `output/_ghidra/securom_dump/`, so the tests run inside that checkout.

## Testing in game

[`TESTING.md`](TESTING.md) is the in-game test plan: what to do at each step and what
`scripts\multiplayer_restored.log` must show.

## License

MIT — see [`LICENSE`](LICENSE).
