# Crates

Each crate has one role. Dependencies point one way: transport and process crates
call providers, providers call primitives, and the contract is a leaf used at the
wire boundary. A device crate never depends on a server crate.

| Crate | Role | Owns |
| --- | --- | --- |
| [orbyn-contracts](orbyn-contracts/README.md) | Contract | Wire types for every API and event; generates the TypeScript bindings |
| [orbyn-crypto](orbyn-crypto/README.md) | Primitive | Symmetric sealing, device keys, key wrapping, signatures and recovery keys |
| [orbyn-sync](orbyn-sync/README.md) | Primitive | Hybrid logical clocks and field-by-field merge |
| [orbyn-auth-client](orbyn-auth-client/README.md) | Primitive | The OPAQUE ciphersuite, the device side of sign-in, the messages devices sign |
| [orbyn-translog](orbyn-translog/README.md) | Primitive | The transparency log's Merkle tree, sparse map, proofs and cosignature rules |
| [orbyn-planner](orbyn-planner/README.md) | Domain | Planner records: tasks, events, lists and repeat rules |
| [orbyn-engineering](orbyn-engineering/README.md) | Domain | Orbyn Engineering records: its zone names and the settings that follow a person |
| [orbyn-client](orbyn-client/README.md) | Device provider | The device sync engine: record encryption, uploads, merges and zone keys; no IO |
| [orbyn-wasm](orbyn-wasm/README.md) | Device consumer | JavaScript bindings for sign-in, device keys and the sync engine |
| [orbyn-core](orbyn-core/README.md) | Server provider | Configuration, Postgres, migrations, jobs, mail, accounts, feeds and push |
| [orbyn-store](orbyn-store/README.md) | Server provider | The record store, keychain, protection chain and purge |
| [orbyn-keyservice](orbyn-keyservice/README.md) | Key service provider | The HSM boundary, service-key certification, envelopes and `keyservice init` |
| [orbyn-keyservice-server](orbyn-keyservice-server/README.md) | Key service provider | The key service's store, roles, log, maps and head building |
| [orbyn-keyservice-client](orbyn-keyservice-client/README.md) | Key service consumer | The client for the key service's mutual-TLS internal API |
| [orbyn-keyservice-daemon](orbyn-keyservice-daemon/README.md) | Key service transport | The internal API, its mutual TLS, audit, publisher and CLI |
| [orbyn-witness](orbyn-witness/README.md) | Witness | Head, map and chain checks, durable state and cosigning |
| [orbyn-server](orbyn-server/README.md) | Transport | The HTTP API and the `/v1/sync` WebSocket |
| [orbyn-worker](orbyn-worker/README.md) | Process | The job runner and the SMTP sender |
| [orbyn-cli](orbyn-cli/README.md) | Process | The `orbyn` binary with every server role |

A new crate needs its own ownership, distribution or build-isolation reason. A new
endpoint belongs in `orbyn-server`, its rule in the owning provider. The allowed
edges are enforced by [check_structure.py](../scripts/check_structure.py) from
`cargo metadata`; adding a dependency is a deliberate change to that list.
