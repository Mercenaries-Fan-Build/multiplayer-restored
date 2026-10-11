# Multiplayer Restored

A Mercenaries 2: World in Flames Shipment that brings back online co-op against a self-hostable server.

The game's EA online services (FESL and Theater) are answered inside the game process by
`multiplayer_restored.asi`. Accounts, the lobby and gameplay traffic go to a
[multiplayer server](https://github.com/Mercenaries-Fan-Build/multiplayer-server) over HTTPS and a DTLS
relay, so no player's address is shown to another player.

## What it installs

| File | Where | What it is |
|---|---|---|
| `multiplayer_restored.asi` | `scripts\` | The client plugin. It finds the game's ProtoSSL functions by byte signature and stops the game with a message if the exe does not match. |
| `multiplayer_restored.ini` | `scripts\` | Required settings; the plugin refuses to start without it, or with a missing or unknown key. |

## Setup

1. Install the Shipment with the Modkit or `qm`.
2. Edit `scripts\multiplayer_restored.ini`:
   - `[server] base_url` — the HTTPS address of the server you play on. The shipped `https://mp.invalid`
     never resolves.
   - `[privacy] room_key` — `none` to see public games, or a key of 6–32 letters, digits or `-`; you
     then see and join only games hosted with exactly the same key.
3. Start the game, choose the online option and create an account or log in.

Games hold at most two players: the host and one joiner.

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
cargo test
```

Needs `i686-w64-mingw32-gcc` on `PATH`. Some tests read the reference executables from the research
repository, so the full test suite runs only inside that checkout.

## Testing in game

[`TESTING.md`](TESTING.md) is the in-game test plan: what to do at each step and what
`scripts\multiplayer_restored.log` must show.

## License

MIT — see [`LICENSE`](LICENSE).
