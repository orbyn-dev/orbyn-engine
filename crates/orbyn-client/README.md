# orbyn-client

The device sync engine. It keeps a device's cache of records per zone, encrypts each record with its own key under the zone key, builds atomic uploads, merges conflicts and incoming changes with `orbyn-sync`, and hands zone keys to other trusted devices as signed envelopes. It does no IO: the host makes the HTTP calls, stores the snapshot and passes in the clock. Pure Rust, so it builds for WebAssembly; `orbyn-wasm` wraps it for JavaScript.

| Module | Owns |
| --- | --- |
| `state` | Engine construction, snapshots, clocks and local record access |
| `upload` | Staging, deletes, upload batches and their answers |
| `apply` | Incoming pages, merges, quarantine and refetch handling |
| `keys` | Zone keys, rotation, envelopes to trusted devices and escrow to the service key |
| `crypt` | Record sealing and delete proofs |
| `pairing` | Device approvals |
| `planner` | Planner-record projection |
| `protection` | Protection settings and their verified head |
| `service_key` | Service-key verification and the refusal codes a host branches on |
| `trust` | Pinned peers and signed device lists |
