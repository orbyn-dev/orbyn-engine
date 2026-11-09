# orbyn-contracts

Wire types for every API and event. `cargo test -p orbyn-contracts` regenerates `bindings/`; commit them with the types, and run `npm run generate` in orbyn-planner's `web` to copy them.

| Module | Owns |
| --- | --- |
| `health` | Health and API-error bodies |
| `auth` | Accounts, sign-up, sign-in, second factor and deletion |
| `devices` | Device lists, removals and approvals |
| `zones` | Zone listing and deletion |
| `records` | Records, uploads and change pages |
| `keys` | Zone-key envelopes and service-key certification |
| `protection` | Protection settings and their chain |
| `sync` | Sync WebSocket messages |
| `feeds` | Calendar feed fetches |
