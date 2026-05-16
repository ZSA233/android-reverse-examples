#!/usr/bin/env bash
set -euo pipefail

npm run build
frida -H "${FRIDA_HOST:-127.0.0.1:27042}" -f 'com.example.frida_stalker_recompile_fix' -l _agent.js --kill-on-exit
