#!/usr/bin/env bash
# Starts the stand-in server. Start it (and listeners.sh) BEFORE RPCS3: it must own its ports first.
# usage: ./run.sh [extra dwstun.py arguments]     (later arguments override the ones below)
#
# Optional files in private/ (not part of this repository, see README "What is not included"):
#   EBOOT.elf            your decrypted 01.24 executable - REQUIRED (message schemas and hash tables are read from it)
#   activities.json      activity names, checksums and start areas
#   ah_sensor_*.json     per-activity spawn lists
#   item_art.tsv         item appearance table
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
[[ -f private/EBOOT.elf ]] || { echo "missing private/EBOOT.elf" >&2; exit 1; }
mkdir -p private
ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+'); ip=${ip:-127.0.0.1}

# Sign-in chain: the first frames of the game connection, replayed as they are.
mapfile -t chain < <(python3 -c '
import json
d = json.load(open("config/chains/record-organic.json"))
print(d["greet"]); [print(r) for r in d.get("replies", [])]')
args=(--public-ip "$ip" --map-port 3074 --tcp-sink)
for frame in "${chain[@]}"; do args+=(--tcp-reply-hex "$frame"); done

# Game connection: encrypted channel, a level-20 character with a starter loadout, unlock flags that open the
# Director, the Cosmodrome patrol and the Tower.
args+=(--bap-channel --bap-state-file private/state.json --bap-peer
       --bap-char-stats 20,170,1512 --bap-progressions 117:148000
       --bap-unlock-flags 433,434,435,3136,2147,2313,2499,2500,2503,2504,2505,2506,2527,2541,2551,2568,3262,3556,3585,4980,419,440
       --bap-account-dense10 57,1386 --bap-account-dense 174,221,248 --bap-profile-dense 56,62,70
       --bap-items 710@40e0,1167@43e1,1161@53e2,1163@63e3,1169@73e4,1165@83e5,2221@93e6,2229@103e7,2085@113e8,862@153e11,2227@94,2228@104,2225@114,1853@123e9,2011@143e10,1512@210e12,1800@220e13
       --bap-item-grids full --bap-family4-extra --bap-destination 0xa15e9435 --social-activities 1)
[[ -f private/item_art.tsv ]] && args+=(--bap-item-art private/item_art.tsv --bap-art-dyes)
# A character created in an earlier session (the server records it in private/state.json) is served again.
if [[ -s private/state.json ]]; then cp private/state.json private/account.json; args+=(--bap-account-from private/account.json); fi

# Activity host (the second connection the title opens when it launches an activity).
args+=(--ah-listen 3076 --bap-ah-proxy 127.0.0.1:3076 --ah-start 56 --ah-public 0xd1a0000000000002
       --peer-host player,time,ah,reflect --ah-sensor-route first)

exec python3 -u server/dwstun.py "${args[@]}" "$@"
