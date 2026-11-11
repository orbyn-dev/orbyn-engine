# The local stack

One Engine on one machine, for development and testing before anything goes to staging. It is invite-only like staging and the 8-character email codes appear in the worker log, so nothing is mailed. **Test data only: never real accounts or real user data, and never expose these ports.** Staging is deployed by the owner; see [staging.md](staging.md).

## Needs

Docker with its daemon running, and about 2 GB of disk for the image and the database. Nothing else: the stack builds from this checkout.

## Make it, once

```sh
scripts/local.sh setup
```

This builds the image and writes `.env.local` (ignored by Git) with a sign-in secret (`ORBYN_AUTH_SETUP`). Keep that file: a new secret makes every password made under the old one unusable. The secret is never printed.

## Start, check, stop

```sh
scripts/local.sh up        # builds if the code changed, makes the orbyn_local database, starts Postgres, the API and the worker
scripts/local.sh status    # containers and GET /health
scripts/local.sh down      # stops everything and keeps the data
```

| What | Where |
| --- | --- |
| API | `http://127.0.0.1:8080` |
| Postgres | `127.0.0.1:5432`, user `orbyn`, no password (local only); the stack uses the database `orbyn_local`, so `cargo test` and the `orbyn` database are never touched |
| Browser origins allowed | `http://localhost:5173` (the Planner dev server), `http://localhost:5331` (its preview), `tauri://localhost` and `http://tauri.localhost` (the desktop shells); set `ORBYN_ALLOWED_ORIGINS` in `.env.local` to change them |

A native client sends no `Origin`, so it needs nothing here. If a port is taken, change the left side of the `ports` entry in `compose.yaml` with an override file and tell the other engineers.

## Invites and email codes

Sign-up needs an invite code, then an 8-character code from the email step (any case, hyphen and spaces ignored). Each invite code is printed once and kept nowhere:

```sh
scripts/local.sh invite create --count 3 --label local
scripts/local.sh invite list
scripts/local.sh codes          # the codes the worker "sent" in the last 10 minutes, with their addresses
scripts/local.sh codes 1h       # a longer window
scripts/local.sh invite-code        # makes one invite and prints only its code (for scripts and tests)
scripts/local.sh latest-code a@b.example   # prints only the newest email code for that address
ORBYN_LOCAL_STACK=1 cargo test -p orbyn-device-client --test local_stack -- --ignored   # the device client end to end against this stack
scripts/local.sh logs worker    # follow a service's log (default: server)
```

`ORBYN_MAIL=log-codes` is accepted only with `ORBYN_ENV=staging` and `ORBYN_SIGNUP=invite`, which `compose.local.yaml` sets, and never with a production host.

More than 10 sign-up starts an hour from one address range need a proof of work (HTTP 428); a client solves it itself. The hard cap is 60 an hour.

## Reset

```sh
scripts/local.sh reset     # drops the orbyn_local database; `up` makes a fresh one
```

Everyone's accounts, devices and records in this stack are gone. The next `up` needs new invites. `docker compose down -v` also removes the shared Postgres volume, which `cargo test` uses: do not run it without telling the others, and never run `docker system prune` here.

## What it does not have

No key service (`/v1/keychain/service-key` answers 503), no tunnel, no real mail. Those are staging's (see [staging.md](staging.md)).
