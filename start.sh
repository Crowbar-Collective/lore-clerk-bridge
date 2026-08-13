#!/bin/sh
# Two processes, one container: Node serves Express and both gRPC listeners, Caddy
# terminates TLS in front of them.
#
# Neither is supervised by the other, so the container has to exit when either does.
# Otherwise Node dying (a bad port, a failed bind, an unhandled rejection) leaves Caddy
# answering on a healthy-looking port with nothing behind it: every request 502s, the
# container never restarts, and nothing says why.
set -e

node dist/index.js &
node_pid=$!

caddy run --config Caddyfile --adapter caddyfile &
caddy_pid=$!

# Forward shutdown signals so an orchestrator's SIGTERM stops both rather than being
# absorbed by this shell.
trap 'kill "$node_pid" "$caddy_pid" 2>/dev/null; exit 0' INT TERM

# `wait -n` would be tidier but is not in POSIX sh, and this runs under busybox ash.
while kill -0 "$node_pid" 2>/dev/null && kill -0 "$caddy_pid" 2>/dev/null; do
	sleep 2
done

kill "$node_pid" "$caddy_pid" 2>/dev/null || true
echo "start.sh: node or caddy exited, stopping container" >&2
exit 1
