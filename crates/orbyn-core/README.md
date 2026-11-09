# orbyn-core

Server foundation: configuration, the Postgres pool, migrations (from
`/migrations`), the job queue with `FOR UPDATE SKIP LOCKED` leases, mail, calendar
feeds, push payloads and `accounts`: OPAQUE sign-up and sign-in, sessions, trusted
devices, rate limits and the audit log.

## Groups

Each folder under `src/` owns one capability. A new module joins an existing
group; a new group adds its own `README.md` and a row here.

| Group | Owns |
| --- | --- |
| [accounts](src/accounts/README.md) | Sign-up, sign-in, sessions, trusted devices, approvals, second factor, invites, limits, deletion and push tokens |
| [mail](src/mail/README.md) | The message model, the designed bodies and the sender boundary |

Shared by every group, at the crate root: `config`, `db`, `jobs`, `feeds`, `push`
and `email_code`.

## Consumers

- `orbyn-store`, `orbyn-server`, `orbyn-worker` and `orbyn-cli`.

Its Postgres tests are ignored unless run with `--include-ignored` and
`DATABASE_URL`.
