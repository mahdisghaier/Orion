#!/usr/bin/env bash
# Real netcat listener used as the demo "backdoor" (T1046/T1571-style). No sudo needed.
#   bash scripts/lab/attack_demo.sh start     start the listener on 4444, record the PID
#   bash scripts/lab/attack_demo.sh stop      kill it and clean up
#   bash scripts/lab/attack_demo.sh status    show PID, socket, and how nc resolves
set -uo pipefail

PORT="${PORT:-4444}"
ADDR="${LISTEN_ADDR:-127.0.0.1}"          # loopback is enough for Metricbeat/Wazuh to see it
STATE="$HOME/.orion-lab"
PIDFILE="$STATE/nc.pid"
mkdir -p "$STATE"

NC_PATH=$(command -v nc || true)
[ -n "$NC_PATH" ] || { echo "nc is not installed (sudo apt install netcat-openbsd)"; exit 1; }
NC_REAL=$(readlink -f "$NC_PATH")

# [explain] True when the recorded netcat process is still alive.
running() { [ -s "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

# [explain] Three modes: start the fake backdoor, stop it, or show what is going on.
case "${1:-status}" in
  start)
    if running; then echo "already running, PID $(cat "$PIDFILE")"; exit 0; fi
    if ss -ltn "sport = :$PORT" | grep -q LISTEN; then echo "port $PORT is already in use"; exit 1; fi
    nohup nc -l -k "$ADDR" "$PORT" </dev/null >/dev/null 2>&1 &
    echo $! > "$PIDFILE"
    sleep 1
    if running; then
      echo "listener started: PID $(cat "$PIDFILE") on $ADDR:$PORT"
      echo "nc resolves to: $NC_REAL"
      echo "Metricbeat samples every 30s; Wazuh's port check runs on its own interval."
      echo "Keep it running until you have collected the evidence, then: $0 stop"
    else
      echo "listener failed to start"; rm -f "$PIDFILE"; exit 1
    fi
    ;;
  stop)
    if running; then
      kill "$(cat "$PIDFILE")" && echo "stopped PID $(cat "$PIDFILE")"
    else
      echo "not running"
    fi
    rm -f "$PIDFILE"
    ;;
  status)
    echo "which nc      : $NC_PATH"
    echo "readlink -f   : $NC_REAL"
    if running; then echo "listener PID  : $(cat "$PIDFILE")"; else echo "listener      : not running"; fi
    ss -ltnp "sport = :$PORT" 2>/dev/null
    ;;
  *) echo "usage: $0 start|stop|status"; exit 2 ;;
esac
