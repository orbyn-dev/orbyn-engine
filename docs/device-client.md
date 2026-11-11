# The device client

`orbyn-device-client` is the native, async client a desktop app uses to be a device of an Orbyn account. It is built on the IO-free primitives (`orbyn-auth-client`, `orbyn-crypto`, `orbyn-contracts`; later `orbyn-client` and `orbyn-sync`) and adds what they leave out: the call sequence, the transport and typed errors. MIT OR Apache-2.0, and it depends on no app: the Engineering app links it, never the other way. The Planner's web app does the same sequence in TypeScript on `orbyn-wasm`.

It ships in three pull requests:

1. **Sign-up and sign-in** (merged). The design, the crate skeleton and sign-up, sign-in, the re-login and sign-out.
2. **Sync** (this document's second half). Push and pull per zone, zone keys in and out, the notices stream and the status watch.
3. **Approval and the label.** The `app` label bound into the signed register and login messages (merged), the description bound into the approval (merged), and the client API for approval digits, approve and deny, `devices()` and `remove_device` (this document's last section).

## What the host supplies

| Piece | Trait | What it is |
| --- | --- | --- |
| Transport | `DeviceApi` | One call: a `Request` (method, path, optional bearer, JSON body) gives a `Response` (status, `Retry-After`, body) or `Transport`. `HttpApi` is the real one; a test supplies its own. |
| Secrets | `KeyStore` | `load`, `save`, `clear` of one `StoredIdentity`. The OS keychain in the app; `MemoryStore` in tests. |
| Time | `Clock` | Unix seconds, so a test fixes the time a trusted start is signed at. `SystemClock` is the real one. |

`DeviceClient<A, S, C>` holds the three and a `ClientConfig` (the device's name, platform and optional `app` label). With an `app`, the sign-up and sign-in signatures are the v2 messages, which cover the trimmed name, the platform and the app; the client sends the trimmed name so the server verifies the same bytes. Without one it signs the v1 messages.

### What the key store holds, and what it does not

Only what has to outlive a run: the **device keys** (Ed25519 and X25519 secrets), the **account id, device id and email** (identifiers: the email is kept so a re-login needs only the password), the **session token** with its expiry, and the **vault key**. The vault key is 32 random bytes made once on this device; the host seals its own snapshot under it. It is not derived from the password and never leaves the device.

The vault key is kept across sign-ins of the **same account**. If the account id changes (the old account was deleted and the address signed up again), the device gets a **new** vault key, so the new account can never open the old account's snapshot.

The **zone-key cache is not here.** The host keeps zone keys in its own sealed snapshot, so the OS keychain holds one small entry, not a growing store. The OPAQUE export key is never kept. Nothing secret appears in a `Debug` print or an error.

## Sign-up

`begin_sign_up(SignUpRequest { email, password, invite })` runs OPAQUE registration on the device (`register/start`, then the upload), generates the device keys, signs the `orbyn/device-register/v1` message and sends `register/finish`. If the server answers 428 `proof_required`, the client **solves the proof of work itself** (`orbyn_crypto::pow::solve_from`, from a random start, on a blocking thread, at most two rounds) and sends the same request again with the proof. The password is wiped once OPAQUE has used it, and no request body contains it or any encoding of it.

The result is a `PendingSignUp`. It holds the new device's keys **in memory only**: nothing is stored, and dropping it cancels, so an abandoned sign-up leaves nothing behind. `verify_sign_up(&mut pending, code)` sends the emailed code (any case; spaces and hyphens ignored). A wrong code is `InvalidCode` and leaves the sign-up open; `resend_sign_up` asks for a new one. Only on success are the keys, ids, session and a fresh vault key saved. A store that already holds a device is refused up front (`StoreNotEmpty`), and again before the code is sent, so a sign-in that finished in between is never overwritten and the code is not spent.

### A sign-up that could not be saved

The code is spent when the server accepts it: the account exists from then on. If the key store then fails, `verify_sign_up` returns `DeviceError::Store` and the **keys and the session stay in the `PendingSignUp`**, in memory, wiped on drop. `retry_save(&mut pending)` saves them again and sends nothing to the server, so there is no new code and no second account; calling `verify_sign_up` again does the same whatever code is passed. A store that now holds a device is `StoreNotEmpty`.

If the `PendingSignUp` is dropped first (the app quits, or the store never recovers), the account exists and no device holds its keys. The address cannot sign up again, and signing in would need a device that does not exist. The way out is the delete-unused link: ask for it from the sign-in screen's "my sign-up did not finish" path (`POST /v1/accounts/delete-unused {email}`, always answered 202), open the link in the email that comes within 24 hours, and the server erases the account, which was never used, and releases its invite (see `docs/architecture.md`, "Deleting an unused account"); then sign up again. A host shows this path when `verify_sign_up` ended in `Store` and the person leaves without a successful `retry_save`.

## Sign-in

`sign_in(email, password)` runs OPAQUE login. A wrong password fails **on the device** (`LoginFailed`) and nothing more is sent.

- **A device this store already holds** (same email) signs the start with its key, a *trusted start*: it skips the per-email limit that slows password guessing, and the same trusted device skips the second-factor code (its key is the factor). It is the same device, trusted, and needs no approval.
- **Any other device** generates new keys and is **pending** until a trusted device approves it (`NeedsApproval`). A store that holds a different account's device is `StoreNotEmpty`: sign out, forgetting it, first.
- **A second factor** gives `SecondFactor(challenge)`; `complete_second_factor` takes a code or a recovery code. A wrong code is `SecondFactorFailed` and leaves the challenge usable (the server closes it after five).

## The re-login for `reauthentication_required`

Removing a device, turning the second factor off or starting it, changing protection (except the first Standard setting) and signing every session out need a sign-in finished in the last ten minutes (engine#120). The server answers 401 `reauthentication_required` otherwise, which is `DeviceError::ReauthenticationRequired`.

`reauthenticate(password)` is the answer, and **no new route**: the stored email, the same device key and the password, through the ordinary `login/start` (as a trusted start) and `login/finish`. It returns a new, recent session for the same device and replaces the stored token. Then the caller sends the refused request again; the refusal did not use up its signature. A wrong password changes nothing.

## Sign-out

`sign_out(forget)` tells the server when it can (a failure to reach it does not stop the local sign-out) and drops the session. With `forget` the keys and everything else go too, and the next sign-in is a new device that needs approval; without it the keys stay and signing in again is the same device. `sign_out_all()` signs every session of every device out and needs the recent sign-in.

## Errors

| `DeviceError` | When |
| --- | --- |
| `Transport` | No answer: the network failed or timed out |
| `ReauthenticationRequired` | 401 `reauthentication_required`: call `reauthenticate` and retry |
| `InvalidCode` | 400 `invalid_email_code` or `wrong_code` (the approval digits) |
| `RateLimited { retry_after }` | 429, with the `Retry-After` seconds when sent |
| `DeletionScheduled` | 409 `deletion_scheduled` |
| `AccountGone` | A session call got 401 **and** `POST /v1/accounts/status` answered 200 with a deletion time. Nothing else gives it: the app destroys key material on this error |
| `SessionExpired` | 401 `unauthorized` and the account is alive, or the status call failed or answered anything but 200 |
| `TooLarge` | 413 |
| `ApprovalExpired` | 410 `approval_expired`, or the approval is gone (cancelled, used or older than ten minutes) |
| `ApprovalNotReady` | 409 `approval_out_of_order` or `approval_not_confirmed`: the other device has not done its step yet |
| `ApprovalMismatch` | The engine refused the approval (other keys, a reveal that does not match its commitment, other digits, a bad signature) or the server refused the commitment: the approval is cancelled |
| `LastTrustedDevice` | 409 `last_trusted_device` |
| `LoginFailed`, `InviteInvalid`, `SecondFactorFailed`, `DeviceNotTrusted` | the matching server code |
| `NotSignedIn`, `StoreNotEmpty`, `InvalidInput`, `Store`, `Crypto` | local conditions |
| `Server { status, code }` | anything else, carrying only the status and the machine code |

An error never carries a password, a token, a code, a key or a URL. `Request` and `Response` print their method, path or status and **the body's length only**, never the body, and their bodies are wiped on drop, so a logging wrapper or a test double around `DeviceApi` cannot leak a session token or a code. The second-factor code is written straight into a wiped buffer, and the session token is wiped when the answer that carried it is dropped.

## The transport

`HttpApi` is reqwest with **rustls and ring only** (no OpenSSL, no aws-lc). **Redirects are off**: a redirect could carry the bearer token elsewhere, and a redirect is returned as an answer. The address must be `https`, or `http` to a **loopback IP literal** (`127.0.0.1`, `[::1]`) for a local stack, with no user info, query or path. A name such as `localhost` is not a loopback literal, because a name can be made to point anywhere. `is_loopback_literal(address)` is public so the app's "local only" gate can use the same test. Calls time out at 30 seconds, connects at 10, and a response body is capped at 32 MiB (`with_body_limit` lowers it), counted **while reading**, so a server that sends no `Content-Length`, or lies about it, is stopped too.

## Tests

- `tests/client.rs` runs the client against an in-memory engine (`tests/support`) that speaks the **real OPAQUE server side** and checks the real signatures: proof of work, invite, code, trusted start, second factor, re-login after eleven minutes, account gone, rate limit, and that no request body holds the password. The same file serves a raw HTTP reply to check that redirects are not followed and `Retry-After` is read.
- `tests/local_stack.rs` (ignored by default, and skipped with a printed note unless `ORBYN_LOCAL_STACK=1`, so `cargo test -- --include-ignored` in CI passes without a stack) runs sign-up, a second pending device, a wrong password, the re-login and sign-out against the real engine on `scripts/local.sh up`, using `scripts/local.sh invite-code` and `scripts/local.sh latest-code <email>`.

## Sync

The records go in and out as plain fields (`orbyn_sync::Fields`: a value and a stamp for each field, merged field by field). Sealing, opening and the zone keys are inside `orbyn_client::Engine`, which the client opens and the host holds.

- `open_engine(snapshot)` makes the engine for this device: from the host's snapshot, or empty the first time. The snapshot (`engine.snapshot()`, serialisable) holds the zone keys and the cache, so **the host seals it under the vault key** before it touches disk. A snapshot of another account or device is refused.
- The host stages with the engine (`stage`, `delete`, `tick`) and reads with it (`record`, `records`); both work offline and never block.
- `sync_all(&mut engine)` is one pass: the device list (the engine verifies the approvals itself), the zone keys other devices sent (accepted, then the records that could not be opened are tried again), the zone list compared with this device's tokens, and every zone that changed on the server or has local changes, **pulled then pushed**. A zone made here is created on the server with a new key, which is sealed to the account's other trusted devices. `sync_zone` does one zone; `send_keys` hands a zone's keys to the trusted devices (the approver calls it for every zone after an approval).
- A pull follows the change pages; a 410 `token_expired` (on a pull or an upload) starts the zone again, **three times at most**, then the pass fails with `Server { 410, token_expired }`. A push uploads in batches; a 409 `record_changed` merges what the server has and goes again, **eight conflicts at most**, then the pass fails with `Server { 409, record_changed }` and everything stays staged for the next pass. A zone this device has no key for yet is reported (`waiting_for_key`), not failed: another device sends the key. `TooLarge` clears the batch in flight but its records stay dirty, so the next pass builds the same batch and gets `TooLarge` again until the host makes a record smaller or deletes it; the error is how the host learns of it.
- A pass that cannot reach the server is `Transport`, changes nothing and leaves everything staged. Nothing here ever blocks the host's own work.

### Status

`status()` is a `tokio::sync::watch` of `SyncStatus { state, last_synced, last_error }`. The states are `Idle`, `Syncing`, `Offline`, and the ones that need the host to act: `SignedOut`, `ReauthenticationRequired` (call `reauthenticate`), `SessionExpired`, `AccountGone` (the app destroys key material) and `Failed`. The latest value is always there; a failure keeps the last good time.

### Notices

`notices(config)` opens the live stream (`/v1/sync`, a WebSocket over the same address: `wss` for `https`, and `ws` **only for a loopback IP literal**, so a transport that reports some other `http://` address gets no stream; rustls with ring and the web roots). Frames and messages are capped at 16 KiB (a notice is a few hundred bytes), the connect and handshake have a timeout (ten seconds), and the token is written into a wiped buffer for the sign-in message. It signs in first with the session token, then tells the host: `Connected` (compare every zone now: changes made while disconnected are not replayed), `ZoneChanged { zone, token }`, `Resync`, `Disconnected`, `Rejected { code }`. A notice never carries record data; the host answers one with a pass. The library answers the server's pings as it reads; a connection that hears nothing for the idle timeout (two minutes) is dropped. The stream **reconnects by itself** with a delay that doubles from one second to one minute, with up to a fifth of jitter, and starts again from the first delay once the server says `Ready`. `Rejected { code: "unauthorized" }` stops it: the session is gone, so `reauthenticate` and open a new one. Dropping the handle closes the connection.

## Approving devices

The client only moves messages between the engine and the server, in order. Every signature, the digits and every check are the engine's (`Engine::start_approval`, `join_approval[_labelled]`, `confirm_approval`, `finish_approval`, `sign_removal`); the client signs nothing itself.

**The approver** (a trusted device): `start_approval(engine, device_id)` lists the devices, lets the engine refuse a device it trusts or revoked, and opens the approval. `approval_state(&mut approval)` is asked until it answers `Digits { digits, fingerprint }`: it answers `Waiting` until the new device joined, then reveals this device's nonce once (a server that shows other keys than this device started with cancels the approval: `ApprovalMismatch`). The person compares the digits with the new device. Same: `confirm_approval(engine, approval)` fetches the current device list, signs the approval and the endorsement and sends them (the host then calls `send_keys` for each zone); different or cancelled: `deny_approval`.

**The new device**: `pending_approval()` shows an approval when a trusted device started one. `join_approval(engine)` sends this device's nonce; a device that named its app (`ClientConfig.app`) joins with the name, platform and app it signed in with, so its digits match the approver's only if the approver was shown the same description. `device_digits(&joined)` answers `None` until the approver revealed, then the digits (or `ApprovalMismatch`, cancelling). `finish_approval(engine, joined, typed)` is called when the person confirms or types the approver's digits: the engine checks the reveal, the age, the approver's signature and the endorsement and pins the approver and the devices it endorsed, and only then are the digits sent to the server, once. On any failure nothing new is trusted, the approval is cancelled, and a new one is needed. `deny_joined` cancels.

**Removing**: `remove_device(engine, device_id)` signs the removal with a sequence one above every removal the engine counted. A password sign-in older than ten minutes is `ReauthenticationRequired`; the last trusted device is `LastTrustedDevice`.

The label is the device's own signed claim, never proof of which app is running.

### Not here yet

The account's protection chain is not signed by the client; the host's first protection setting follows the rules in [architecture.md](architecture.md).

## One crate to depend on

The app may not depend on or name `orbyn-contracts` (rule D6). Every type of another Engine crate that this crate's public API exposes is therefore **re-exported from `orbyn-device-client`** (the same types, not copies), and `orbyn-client` re-exports the ones its own signatures use:

| From | Re-exported by `orbyn-device-client` | Why |
| --- | --- | --- |
| `orbyn-contracts` | `DevicePlatform`, `DeviceApp`, `DeviceState`, `Device`, `DeviceList`, `DeviceRemoval`, `PendingApproval` | `ClientConfig`, `SessionInfo`, `devices()`, `pending_approval()` and what a device list holds |
| `orbyn-client` | `Engine`, `Snapshot`, `Applied`, `RejectedFields`, `RefusedEnvelope`, `ClientError`, `Peer`, `Local`, `Quarantined`, `Trashed` | `open_engine`, `sync_all`, `SyncReport` and the engine's own return types |
| `orbyn-sync` (through `orbyn-client`) | `Fields`, `Stamp` | staging and reading records |
| `orbyn-crypto` (through `orbyn-client`) | `DeviceKeys`, `DevicePublic` | `StoredIdentity::keys()`, device keys |
| `zeroize` | `Zeroizing` | `Password`, `StoredIdentity` |

`orbyn-client` re-exports, besides those, the other contract types its `Engine` methods take or return (`ZoneList`, `UploadChanges`, `UploadResult`, `RemoveDevice`, `DeleteZone`, `KeyEnvelope`, `NewKeyEnvelope`, `KeyRotation`, `ApprovalNonce`, `CreateApproval`, `ConfirmApproval`, `ProtectionChain`, `ProtectionLink`, `ProtectionLevel`, `SetProtection`, `Record`, `RecordChanged`, `ZoneChanges`).

Left out on purpose: the planner's `Item` and `ItemError` (planner only); the request and response bodies this crate sends and reads internally (`RegisterFinish`, `EmailVerify` and the like) and `orbyn-auth-client`, which no public signature uses; `ApproverPairing` and `DevicePairing`, which `ApproverApproval` and `JoinedApproval` wrap. `DeviceError` carries only strings, numbers and a duration. `tests/single_crate.rs` here and `orbyn-client/tests/reexports.rs` use these types through the one crate, and a check fails if the first names another Engine crate.

### Tests

`orbyn-server/tests/device_client.rs` runs the client over a real loopback socket against the real server on Postgres: two devices, the zone key, a sealed record that the server holds only as ciphertext, a conflict merged both ways, the snapshot round trip, a pending device refused, the whole approval through the client API (digits compared, confirmed and finished), a deny from either side, wrong digits typed, a relabelled listing refused by the server's commitment check, a removal and the last device that stays, offline work kept and sent later, and the notices stream hearing another device's change and being rejected when the session is revoked. `tests/notices.rs` serves the stream by hand to check the sign-in message, the pong, the reconnect and the stop.
