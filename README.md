# KH2 Co-op (mod)

Online co-op for Kingdom Hearts II Final Mix (PC, Steam). Two players run their
own copies of the game; the other player appears in your party as a second
Sora, in the same room, fighting the same enemies. This repository is the game
side of the project: the DLL that runs inside KH2, the runtime that carries the
session over Steam, and the local relay used for solo tests.

**Players: download the launcher** — it installs and updates everything:
[KH2CoopSetup.exe](https://github.com/JayKazma/kh2-coop/raw/main/dist/KH2CoopSetup.exe) (launcher repo: [kh2-coop](https://github.com/JayKazma/kh2-coop)).

## What works

- **Second Sora.** The other player is a clone of Sora in your party, driven by
  their stream: position, animation, HP and MP (own HUD gauge with a portrait).
- **Keyblade sync.** Each clone carries its owner's equipped keyblade; changing
  keyblades mid-room follows.
- **Spells and items replay.** The other player's magic and item casts run on
  their clone through the game's own command path, so motion, effects and
  sound play natively.
- **Rooms and story.** Both players travel the story together; room changes
  follow the host.
- **Two windows on one PC** through a local relay (solo test), tiled borderless
  side by side.
- **Steam sessions.** Online play is Steam-to-Steam by SteamID; no port
  forwarding.

Each player plays on their own save, with their own level, abilities and
equipment.

## Layout

| Path | What |
| --- | --- |
| `inject/` | The DLL loaded into KH2: hooks, clone party, cast replay, weapon sync, HUD, save guard, crash log |
| `runtime/` | `kh2coop_runtime_scaffold.exe`: bridges the DLL's shared memory to the network, Steam broker |
| `server/` | `kh2coop_server.exe`: the relay (used locally for the solo test) |
| `common/` | Protocol, codec, avatar state, interpolation shared by all of the above |
| `tools/kh2ctl/` | `kh2ctl.exe`: launches KH2 with the DLL, kills rig instances |
| `tests/` | Offline tests (no game needed); each prints `ALL CHECKS PASSED` |
| `docs/` | Design notes, reverse-engineering notes, archived plans |

## How it fits together

```
  Player's PC
 ┌──────────────────────────┐
 │ KH2 process              │
 │  ┌────────────────────┐  │ shared memory  ┌─────────┐  Steam / ENet  ┌──────────────┐
 │  │ kh2coop_inject.dll │◄─┼───────────────►│ runtime │◄──────────────►│ other player │
 │  └────────────────────┘  │                └─────────┘                └──────────────┘
 └──────────────────────────┘
```

The DLL reads the local Sora every frame and publishes an `AvatarState`
(position, motion, HP/MP, last cast, equipped weapon). The runtime sends it to
the other player and receives theirs; the DLL drives the clone from it. The
host's game owns enemies and rooms.

## Building

Windows, Visual Studio 2022:

```powershell
cmake -B build -S . -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build --config Release
.\build\Release\kh2coop_world_test.exe      # offline tests
```

Cross-build from Linux (what the launcher releases use; clang + mingw headers):

```sh
tools/inject/build.sh <this repo> <build dir>     # script lives in the kh2-coop launcher repo
```

Binaries land in `<build dir>/out/`: `kh2coop_inject.dll`,
`kh2coop_runtime_scaffold.exe`, `kh2coop_server.exe`, `kh2ctl.exe`. Both
players must run the same protocol version (`common/include/kh2coop/Protocol.hpp`).

## Runtime switches

Set as environment variables by the launcher; all default on.

| Variable | Effect |
| --- | --- |
| `KH2COOP_PARTY_NATIVE`, `KH2COOP_NATIVE_SORA_PRIVATE_STATUS`, `KH2COOP_CLONE_NEUTRAL_INPUT`, `KH2COOP_ALLY_HIT` | The one-clone party |
| `KH2COOP_CAST_REPLAY=0` | Don't replay the other player's casts on their clone |
| `KH2COOP_WEAPON_SYNC=0` / `=1` | Keyblade sync off / diagnostics only |
| `KH2COOP_SAVEGUARD=0` | Let the game write its saves (by default they are sandboxed; the settings file always writes through) |
| `KH2COOP_STEAM_BROKER=1` | Online session over Steam (the launcher sets it for host/join) |

Logs go next to the launcher under `build\rig\logs\` (`kh2coop_inject_<pid>.log`,
runtime and relay logs, crash dumps).

## License

GPL-3.0-or-later. Copyright (C) 2026 Volpestyle (original multiplayer
framework); Copyright (C) 2026 JayKazma (co-op: clone party, cast replay,
keyblade sync, HUD, launcher integration). This program is free software: you
can redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. It is distributed WITHOUT ANY
WARRANTY; see [`LICENSE`](LICENSE).
