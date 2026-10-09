# d1-standin

A local stand-in server for the network protocol of Destiny 1 on PS3 (`BLUS31181`, update 01.24), for use with the
[RPCS3](https://rpcs3.net) emulator and **your own copy of the game**. It answers the title's sign-on, its game
connection and its activity host, on your own machine, so the title can get past its menus and into the world.

This is an early research release. It is a protocol implementation, not a finished private server: expect an empty
world and rough edges (see [Status](#status)).

- It never contacts the original game service, and it is not affiliated with or endorsed by the game's publisher.
- It contains no game files, keys, certificates, savestates or memory dumps. You need your own disc dump, with the
  updates installed the normal way.
- It does not unlock paid content.

## Requirements

- Linux, Python 3.10+ with the `cryptography` package, the `openssl` command line tool.
- RPCS3 with the game installed and updated to 01.24, and an RPCN account (RPCS3's PSN replacement).
- Your decrypted 01.24 executable (`EBOOT.elf`; RPCS3 can decrypt it). The server reads message schemas and hash
  tables from it at run time instead of shipping them.

## Setup

1. Put your decrypted executable at `private/EBOOT.elf`.
2. Run the setup script. It creates a certificate that exists only on your machine, the two game patches that go
   with it (it finds where the title keeps its own root certificate by looking in your executable), and the content
   manifest for your install:

   ```bash
   D1_DISC_PACKAGES="/path/to/PS3_GAME/USRDIR/packages" python3 setup.py
   ```

3. Copy `private/imported_patch.yml` to `~/.config/rpcs3/patches/imported_patch.yml` and enable both entries in
   RPCS3's Patch Manager. What they do:
   - *trust local certificate*: replaces the title's embedded root certificate with yours, so it accepts the local
     sign-on listener. Certificate checking stays on.
   - *unsigned content manifest*: turns off the signature check on the list of content packages. A local server
     cannot produce the original signature.
4. In RPCS3's network settings for the game: Network status *Connected*, PSN status *RPCN*, and paste the contents of
   `config/ip_swap_list.txt` into *IP/Hosts switches*. That sends the title's server host names to `127.0.0.1`.
5. The title binds port 1001, which Linux reserves by default:

   ```bash
   sudo sysctl -w net.ipv4.ip_unprivileged_port_start=1001
   ```

## Running

Start the two helper listeners and the server **before** RPCS3 (each in its own terminal), then boot the game by its
game directory:

```bash
./listeners.sh
```

```bash
./run.sh
```

Press X at the title screen. The server logs every decrypted message it receives and what it answered.

## Status

Works:
- Sign-on, character select / creation, orbit.
- The Director with its destinations; launching the Cosmodrome patrol, the Venus patrol and the Tower.
- Loading into an area and walking between areas, for the areas that have a spawn list (see below).
- Returning to orbit and launching another activity in the same session.
- The character you create is remembered between sessions (`private/state.json`).

Limitations:
- **Update 01.24 only.** Other versions of the game are untested and the setup refuses an executable it does not
  recognise.
- Every character gets the same fixed level-20 starter loadout, whatever class you create.
- **The world is empty.** No enemies, no vendors or other characters, no loot. The server places only the player.
- Single player. One client at a time.
- The vault opens but is empty; nothing can be stored.
- Only some areas have spawn lists; walking into one without a list hangs on the loading icon.
- Most activities other than the three above are untested.

Known bugs:
- A new account is greeted by a row of "unlocked" announcements on first login. Harmless; once per account.
- The screen bounds, brightness and subtitle prompts come back on every start, and character select picks the
  character by itself.
- **Stock RPCS3 crashes when entering any destination** (renderer thread, "illegal instruction" errors followed by
  `Verification failed`). Sign-on, orbit and the Director work on a stock build. The cause is an empty fragment
  shader program the title binds; a fix on the emulator side is not part of this repository yet.
- A horizontal band of wrong colours across the middle of the screen in some areas.
- Low frame rate in the world on mid-range hardware.
- The server's `--bap-auto-resume` option (meant for reloading an emulator savestate; `run.sh` does not use it)
  breaks a second activity launch in the same server session: the client joins but never spawns. Restart the server
  between launches if you turn it on.

## What is not included

Three kinds of data come from the game itself and are therefore not in this repository. Without them the server
still reaches orbit and the Director; with them it can load areas. They go in `private/`:

- `activities.json`: activity names, checksums and start areas.
- `ah_sensor_<activity>.json`: per-area spawn lists.
- `item_art.tsv`: item appearance table (without it the character's gear has no art).

Tools to derive these from your own install are planned; `tools/activity_records.py` already extracts the checksums.

## Layout

| Path | Contents |
|---|---|
| `server/dwstun.py` | entry point: NAT discovery replies, the listening sockets, command line options |
| `server/bap_channel.py` | the encrypted game connection: account, character, inventory, unlock flags, matchmaking |
| `server/activity_host.py` | the activity host: activity state, areas, spawn sequence |
| `server/peer_channel.py`, `server/dtls_peer.py` | the peer link used for public areas |
| `server/rsat.py` | encoder / decoder for the title's schema-described objects |
| `server/tiger.py`, `server/murmur3.py` | hash functions the protocol uses |
| `tools/` | TLS listener, content manifest builder, package reader |

A companion repository with the research notes behind this implementation is planned.

## Acknowledgements

[d1preservation](https://gitlab.com/aknumbers/d1preservation) is a separate project doing the same kind of work for
the PS4 version of the game, with a Rust server and client tooling. Its published notes on message layouts and
connection flow were a map for much of this implementation, and several things here were found faster, or at all,
because that project had already worked them out on PS4. Comments in the code that say "sibling" refer to it.
The two projects are independent; mistakes here are this project's own.

## Licence

Copyright (C) 2026 Magnetesim. Licensed under the GNU Affero General Public License, version 3 (see `LICENSE`).
You may use, change and share this software; if you distribute it or run a changed version as a service for
others, you must make your source available under the same licence.
