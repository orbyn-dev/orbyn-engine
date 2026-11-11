#!/usr/bin/env bash
# The local stack: start, stop, invites, email codes, reset. docs/local.md explains each command.
set -euo pipefail
cd "$(dirname "$0")/.."
ENV_FILE=".env.local"
dc() { docker compose --env-file "$ENV_FILE" -f compose.yaml -f compose.local.yaml "$@"; }

# The stack's own database inside the compose Postgres; made once, never dropped except by `reset`.
ensure_db() {
  dc up -d postgres >/dev/null
  until dc exec -T postgres pg_isready -U orbyn -d postgres >/dev/null 2>&1; do sleep 1; done
  dc exec -T postgres psql -U orbyn -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='orbyn_local'" | grep -q 1 \
    || dc exec -T postgres psql -U orbyn -d postgres -c "CREATE DATABASE orbyn_local" >/dev/null
}

need_env() {
  [ -f "$ENV_FILE" ] || { echo "no $ENV_FILE yet: run scripts/local.sh setup first" >&2; exit 1; }
  grep -q '^ORBYN_AUTH_SETUP=.\+' "$ENV_FILE" || { echo "$ENV_FILE has no ORBYN_AUTH_SETUP: run scripts/local.sh setup" >&2; exit 1; }
}

case "${1:-}" in
  setup)   # makes .env.local with a sign-in secret, once
    [ -f "$ENV_FILE" ] || cp .env.local.example "$ENV_FILE"
    if grep -q '^ORBYN_AUTH_SETUP=.\+' "$ENV_FILE"; then echo "$ENV_FILE already has a sign-in secret; keeping it"; exit 0; fi
    docker compose -f compose.yaml build migrate
    secret="$(docker compose -f compose.yaml run --rm --no-deps server auth-setup | tail -n 1 | tr -d '\r')"
    [ -n "$secret" ] || { echo "auth-setup printed nothing" >&2; exit 1; }
    # Replace the empty line without printing the secret.
    tmp="$(mktemp)"; sed "s|^ORBYN_AUTH_SETUP=.*|ORBYN_AUTH_SETUP=$secret|" "$ENV_FILE" > "$tmp" && mv "$tmp" "$ENV_FILE"
    echo "wrote the sign-in secret to $ENV_FILE (not shown)";;
  up)      need_env; ensure_db; dc up -d --build; dc ps;;
  down)    dc down;;
  status)  dc ps; curl -fsS http://127.0.0.1:8080/health && echo;;
  invite)  need_env; ensure_db; shift; dc run --rm --no-deps server invite "${@:-create}";;
  codes)   dc logs --no-log-prefix --since "${2:-10m}" worker | grep -i "code" || echo "no codes yet";;
  logs)    dc logs -f "${2:-server}";;
  reset)   dc stop server worker >/dev/null 2>&1 || true; ensure_db; dc exec -T postgres psql -U orbyn -d postgres -c "DROP DATABASE IF EXISTS orbyn_local WITH (FORCE)" >/dev/null; echo "orbyn_local dropped; scripts/local.sh up makes it again";;   # test data only
  *) echo "usage: scripts/local.sh setup|up|down|status|invite [create --count N --label L|list]|codes [since]|logs [service]|reset" >&2; exit 2;;
esac
