# d1-standin

A local stand-in server for the network protocol of Destiny 1 on PS3 (`BLUS31181`, update 01.24), for use with the
[RPCS3](https://rpcs3.net) emulator and **your own copy of the game**. It answers the title's sign-on, its game
connection and its activity host, on your own machine, so the title can get past its menus and into the world.

Version 2. This is a research release. It is a protocol implementation, not a finished private server: expect an empty
world and rough edges (see [Status](#status)).

- It never contacts the original game service, and it is not affiliated with or endorsed by the game's publisher.
- It contains no game files, keys, certificates, savestates or memory dumps. You need your own disc dump, with the
  updates installed the normal way.
- It does not unlock paid content.

## Requirements

- Linux, Python 3.10+ with the `cryptography` package, the `openssl` command line tool.
- RPCS3 with the game installed from your disc and updated to **01.24** (install the update package with RPCS3's
  *File > Install Packages/Raps/Edats*; the title refuses to go online without it).
- An **RPCN account** (RPCS3's PSN replacement; create it in RPCS3's RPCN settings). The title signs in to RPCN
  before it ever talks to this server. If your network blocks RPCN's login port (TCP 31313, e.g. some university
  networks), use another network or a VPN.
- Your decrypted 01.24 executable (`EBOOT.elf`; RPCS3 can decrypt it). The server reads message schemas and hash
  tables from it at run time instead of shipping them.

### Optional: the fast package decoder

The game's content packages are compressed with Oodle LZH. Setup reads them with the open-source
[oodle-lzh](https://github.com/Magnetesim/oodle-lzh) decoder (independent and clean-room, MIT/Apache-2.0). A pure-Python
copy of it is bundled in `tools/oodle_lzh.py`, so setup works without anything extra (its game-data step takes about
7 minutes on a 20-thread laptop, using every core). The Rust version brings that to about a minute; build it and put it
on your `PATH` or at `private/oodle-lzh`:

```bash
git clone https://github.com/Magnetesim/oodle-lzh && cd oodle-lzh && cargo build --release
cp target/release/oodle-lzh /path/to/d1-standin/private/
```

No Oodle DLL is needed. (If you have one, `tools/pkg_extract.py` can still use it; see the comment at its top.)

## Setup

1. Put your decrypted executable at `private/EBOOT.elf`.
2. Run the setup script, pointing it at your disc's package folder. It:
   - creates a certificate that exists only on your machine, and the two game patches that go with it (it finds where
     the title keeps its own root certificate by looking in your executable);
   - builds the content manifest for your install;
   - links the disc's packages into the installed package folder, which the game needs for most of its sound (see
     [Sound](#sound));
   - generates the game data the server needs from your packages: activities, per-area spawn lists, weapon models and
     stats, item appearance, subclass abilities (see [What is not included](#what-is-not-included)).

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

Run `setup.py` again after installing a game update; it regenerates everything from your install.

### Sound

On a console the game copies its disc packages to the hard drive during its first-run install. Under RPCS3 that
install may not have happened, and the game only streams sound from packages in its installed folder: without the
disc packages there, weapons, abilities, impacts, much of the music and some menu sounds are silent. `setup.py` links
the missing disc packages into the installed folder (symlinks, nothing is copied; the list is in the folder's
`.disc_links.txt` if you want to undo it). Boot the game fresh afterwards: a savestate made before the links keeps
the old silence.

## Running

Start the two helper listeners and the server **before** RPCS3 (each in its own terminal), then boot the game by its
game directory:

```bash
./listeners.sh
```

```bash
./run.sh
```

Press X at the title screen. Both scripts print one line per event (`sign-on POST ... -> 200 OK`, `game: create
character`, `activity: launching patrol_deltas_com01`, ...). The server also writes every message it receives and
sends, decrypted, to `private/logs/server-<time>.log`; attach that file when you report a problem. `./run.sh --console
full` prints all of it on the console instead, and `./listeners.sh --verbose` adds the TLS details and request
headers.

## Status

Works:
- Sign-on, character select (it waits for you to pick) and creation, orbit.
- The Director with its destinations; landing in the Cosmodrome patrol and the Tower.
- Loading into an area and walking between areas, including between public areas.
- Weapons fire with their real stats and models; class abilities (super, grenade, melee, jump, sprint) for each
  class's starting subclass (played through on a Titan; Hunter and Warlock use the same generated table).
- Sound, once the disc packages are linked (see [Sound](#sound)).
- Display settings (screen bounds, brightness, subtitles) are remembered.
- Returning to orbit and launching another activity in the same session.
- The character you create is remembered between sessions (`private/state.json`).

Limitations:
- **Update 01.24 only.** Other versions of the game are untested and the setup refuses an executable it does not
  recognise.
- Every character gets the same fixed level-20 starter loadout (weapons and armour), with its class's starting
  subclass.
- **The world is empty.** No enemies, no vendors or other characters, no loot. The server places only the player.
- Single player. One client at a time.
- The vault opens but is empty; nothing can be stored.
- **A new character can only patrol the Cosmodrome.** Patrols on the other planets show "Requirements Not Met" (and
  then a Taken King offer): they unlock through story progress, which the server does not track yet. The spawn lists
  for those areas are generated and ready for when it does.
- Most strikes and Crucible (PvP) maps, and the marathon story missions, have no spawn list in the game's content
  and hang on the loading icon. Patrols, story missions, the Tower and a few strikes have one (92 activities);
  the Crucible needs matchmaking the server does not do yet anyway.
- Only a few of those activities have been played through; the rest are expected to work but are untested.

Known bugs:
- A new account is greeted by a row of "unlocked" announcements on first login. Harmless; once per account.
- The *Set Destination* button on the Director can show a garbled icon.
- **Stock RPCS3 crashes when entering any destination** (renderer thread, "illegal instruction" errors followed by
  `Verification failed`). Sign-on, orbit and the Director work on a stock build. The cause is an empty fragment
  shader program the title binds; a fix on the emulator side is not part of this repository yet.
- A horizontal band of wrong colours across the middle of the screen in some areas.
- Low frame rate in the world on mid-range hardware.

## What is not included

Nothing derived from the game ships in this repository. Everything the server needs from the game is generated by
`setup.py` from your own install into `private/`:

| File | What | Made by |
|---|---|---|
| `activities.json` | activity names, checksums, areas, public areas | `tools/activities.py` |
| `ah_sensor_<activity>.json` | per-area spawn lists | `tools/sensor_fixture.py` |
| `item_gear_index.tsv`, `item_stats.tsv` | weapon models and stats | `tools/item_gear_index.py`, `tools/item_stats.py` |
| `item_art.tsv` | item appearance | `tools/item_art.py` |
| `subclass_abilities.json` | each subclass's starting abilities | `tools/subclass_table.py` |

A spawn list you captured yourself under the same name is kept; setup does not overwrite it.

## Layout

| Path | Contents |
|---|---|
| `server/dwstun.py` | entry point: NAT discovery replies, the listening sockets, command line options |
| `server/bap_channel.py` | the encrypted game connection: account, character, inventory, unlock flags, matchmaking |
| `server/activity_host.py` | the activity host: activity state, areas, spawn sequence |
| `server/peer_channel.py`, `server/dtls_peer.py` | the peer link used for public areas |
| `server/rsat.py` | encoder / decoder for the title's schema-described objects |
| `server/tiger.py`, `server/murmur3.py` | hash functions the protocol uses |
| `tools/` | TLS listener, content manifest builder, package reader and LZH decoder, the game-data generators |

A companion repository with the research notes behind this implementation is planned.

## Acknowledgements

[d1preservation](https://gitlab.com/aknumbers/d1preservation) is a separate project doing the same kind of work for
the PS4 version of the game, with a Rust server and client tooling. Its published notes on message layouts and
connection flow were a map for much of this implementation, and several things here were found faster, or at all,
because that project had already worked them out on PS4. Comments in the code that say "sibling" refer to it.
The two projects are independent; mistakes here are this project's own.

## Licence

Copyright (C) 2026 Myles Hallett. Licensed under the GNU Affero General Public License, version 3 (see `LICENSE`).
You may use, change and share this software; if you distribute it or run a changed version as a service for
others, you must make your source available under the same licence.
