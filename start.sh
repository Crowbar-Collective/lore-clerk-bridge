#!/bin/sh
set -e
node dist/index.js &
exec caddy run --config Caddyfile --adapter caddyfile
