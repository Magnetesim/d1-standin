# d1-standin

A local stand-in server for the network protocol of Destiny 1 on PS3 (`BLUS31181`, update 01.24), for use with the
[RPCS3](https://rpcs3.net) emulator and **your own copy of the game**. It answers the title's sign-on, its game
connection and its activity host, on your own machine, so the title can get past its menus and into the world.

Version 2.1. This is a research release. It is a protocol implementation, not a finished private server: expect an empty
world and rough edges (see [Status](#status)).

- It never contacts the original game service, and it is not affiliated with or endorsed by the game's publisher.
- It contains no game files, keys, certificates, savestates or memory dumps. You need your own disc dump, with the
  updates installed the normal way.
- It does not unlock paid content.

## Requirements

- Linux, Python 3.10+ with the `cryptography` package, `openssl` and `curl`.
- [RPCS3](https://rpcs3.net/download) (the Linux AppImage is fine) with the PS3 firmware installed (*File > Install
  Firmware*). Note: current RPCS3 builds crash in some areas, the first one being The Divide in the Cosmodrome; see
  [The Divide crash](#the-divide-crash) for the fix.
- **Your own disc dump, as a folder** (`PS3_GAME/` inside). [PS3 Disc Dumper](https://github.com/13xforever/ps3-disc-dumper)
  makes one and checks it against the disc's IRD. An `.iso` has to be extracted first.
- An **RPCN account** (RPCS3's PSN replacement; create it in RPCS3: *Configuration > RPCN*). The title signs in to
  RPCN before it ever talks to this server. If your network blocks RPCN's login port (TCP 31313, e.g. eduroam and some
  other university networks), the game waits about two minutes at boot for the connection to fail; use another
  network or a VPN.

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

Clone this repository, then run the setup script. It is a checklist: each step checks whether it is already done, does
it if it can, and otherwise stops and tells you exactly what to do. Run it again until everything is `[ok]`; it
continues where it stopped.

```bash
python3 setup.py --rpcs3 /path/to/rpcs3.AppImage --dump "/path/to/Destiny [BLUS31181]"
```

(Without `--rpcs3` / `--dump` it asks for them, and offers to look in the usual places only if you say yes. Later runs
remember the paths in `private/setup.json`. `--check` only reports; `--yes` answers every question with its default.)

What it does, all from your own install (everything it makes goes to `private/`, which is never part of the repository):
- **Update 01.24**: downloads the official update packages from Sony's update server (12 packages, 10.7 GB, each
  checked against Sony's SHA-1) and installs them into RPCS3, oldest first.
- **The 01.24 executable**: decrypts it with RPCS3 to `private/EBOOT.elf` and checks it really is 01.24 (the disc's own
  executable is older and does not work). The server reads message schemas and hash tables from it at run time
  instead of shipping them.
- **Certificate and game patches**: creates a certificate that exists only on your machine and the two game patches
  that go with it, installs them into RPCS3 and enables them:
  - *trust local certificate*: replaces the title's embedded root certificate with yours, so it accepts the local
    sign-on listener. Certificate checking stays on.
  - *unsigned content manifest*: turns off the signature check on the list of content packages. A local server
    cannot produce the original signature.
  (Only these two. RPCS3's downloadable patch list has a Destiny "HTTPS Bypass" patch; leave it off.)
- **The game's RPCS3 settings**: a custom configuration for this game only, with network *Connected*, PSN *RPCN*, the
  host redirects from `config/ip_swap_list.txt` (they send the title's server names to `127.0.0.1`) and the two colour
  buffer settings the game needs.
- **Sound**: links the disc's packages into the installed folder (see [Sound](#sound)).
- **Content manifest and game data**: activities, per-area spawn lists, weapon models and stats, item appearance,
  subclass abilities (see [What is not included](#what-is-not-included)).

Before it changes anything in RPCS3's folder it lists the files and asks once; every file it edits is backed up next
to the original as `*.before-d1-standin`. Two things stay with you, and setup checks both: the RPCN account, and
port 1001, which the title binds and Linux reserves by default:

```bash
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=1001
```

Run `setup.py --regenerate` after changing your install; it builds the game data again.

### Sound

The game streams sound only from packages it finds in its installed folder on the hard drive; packages that exist
only on the disc are read, but their sound is not played. Without the disc packages there, weapons, abilities,
impacts, much of the music and some menu sounds are silent. `setup.py` links
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

By default every session starts like a first login: the "unlocked" announcements and the screen-bounds prompt come
back, and in-game settings (brightness, button layout) are not kept. `./run.sh --keep-settings` keeps them, but the
game then treats you as a returning player, and the Moon, Venus and Mars ask for The Taken King (fixing that is
planned).

### The Divide crash

Current RPCS3 builds stop with a renderer error when you enter The Divide in the Cosmodrome (and possibly elsewhere):
`Verification failed` in `FragmentProgramDecompiler.cpp`, or `Unimplemented BEM class instruction`, depending on the
build. The game points at an empty (all-zero) shader there, and RPCS3 reads on past it into unrelated memory. It is
reported upstream ([RPCS3/rpcs3#19666](https://github.com/RPCS3/rpcs3/issues/19666)); until RPCS3 fixes it, avoid The
Divide or build RPCS3 with the 20-line fix in [`rpcs3/the-divide-fix.patch`](rpcs3/the-divide-fix.patch):

```bash
git clone --recurse-submodules https://github.com/RPCS3/rpcs3 && cd rpcs3
git apply /path/to/d1-standin/rpcs3/the-divide-fix.patch
```

then build it as RPCS3's [BUILDING.md](https://github.com/RPCS3/rpcs3/blob/master/BUILDING.md) describes, and
point setup at it (`python3 setup.py --rpcs3 /path/to/rpcs3/build/bin/rpcs3`). Tested: five minutes in The Divide
without a problem. The patch was made against RPCS3
master `0ebb63697` (0.0.43-20623); if it no longer applies, the fix may already be upstream.

## Status

Works:
- Sign-on, character select (it waits for you to pick) and creation, orbit.
- The Director with its destinations; landing in the Cosmodrome patrol and the Tower.
- Loading into an area and walking between areas, including between public areas.
- Weapons fire with their real stats and models; class abilities (super, grenade, melee, jump, sprint) for each
  class's starting subclass (played through on a Titan; Hunter and Warlock use the same generated table).
- Sound, once the disc packages are linked (see [Sound](#sound)).
- In-game settings are remembered with `./run.sh --keep-settings` (see [Running](#running)).
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
- **Other planets:** the Director opens them all. Patrol Venus is tested (lands in The Shattered Coast; Ember Caves
  and Headlands walked). The Moon and Mars are untested. With `--keep-settings` they show "Requirements Not Met" and
  a Taken King offer instead.
- Most strikes and Crucible (PvP) maps, and the marathon story missions, have no spawn list in the game's content
  and hang on the loading icon. Patrols, story missions, the Tower and a few strikes have one (92 activities);
  the Crucible needs matchmaking the server does not do yet anyway.
- Only a few of those activities have been played through; the rest are expected to work but are untested.

Known bugs:
- The "unlocked" announcements (2.0.0 update, Crucible, Armsday, ...) show at every login. Harmless; see
  [Running](#running).
- The *Set Destination* button on the Director can show a garbled icon.
- **Current RPCS3 crashes in The Divide** (Cosmodrome); see [The Divide crash](#the-divide-crash) for the fix.
- Current RPCS3 builds sometimes freeze at boot (no picture, one CPU core busy; RPCS3's log repeats
  `semaphore_acquire has timed out`). Close RPCS3 and start again. (On a network that blocks RPCN the game also
  stalls for about two minutes at boot, then continues; that is a different thing, see [Requirements](#requirements).)
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
| `tools/` | TLS listener, update download, content manifest builder, package reader and LZH decoder, the game-data generators |
| `rpcs3/the-divide-fix.patch` | the RPCS3 fix for [The Divide crash](#the-divide-crash) |

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
