# The device client

`orbyn-device-client` is the native, async client a desktop app uses to be a device of an Orbyn account. It is built on the IO-free primitives (`orbyn-auth-client`, `orbyn-crypto`, `orbyn-contracts`; later `orbyn-client` and `orbyn-sync`) and adds what they leave out: the call sequence, the transport and typed errors. MIT OR Apache-2.0, and it depends on no app: the Engineering app links it, never the other way. The Planner's web app does the same sequence in TypeScript on `orbyn-wasm`.

It ships in three pull requests:

1. **Sign-up and sign-in** (merged). The design, the crate skeleton and sign-up, sign-in, the re-login and sign-out.
2. **Sync** (this document's second half). Push and pull per zone, zone keys in and out, the notices stream and the status watch.
3. **Approval and the label.** Approval digits, approve and deny, `devices()`, `remove_device`, and the device `app` label bound into the signed register message (engine#73).

## What the host supplies

| Piece | Trait | What it is |
| --- | --- | --- |
| Transport | `DeviceApi` | One call: a `Request` (method, path, optional bearer, JSON body) gives a `Response` (status, `Retry-After`, body) or `Transport`. `HttpApi` is the real one; a test supplies its own. |
| Secrets | `KeyStore` | `load`, `save`, `clear` of one `StoredIdentity`. The OS keychain in the app; `MemoryStore` in tests. |
| Time | `Clock` | Unix seconds, so a test fixes the time a trusted start is signed at. `SystemClock` is the real one. |

`DeviceClient<A, S, C>` holds the three and a `ClientConfig` (the device's name and platform).

### What the key store holds, and what it does not

Only what has to outlive a run: the **device keys** (Ed25519 and X25519 secrets), the **account id, device id and email** (identifiers: the email is kept so a re-login needs only the password), the **session token** with its expiry, and the **vault key**. The vault key is 32 random bytes made once on this device; the host seals its own snapshot under it. It is not derived from the password and never leaves the device.

The vault key is kept across sign-ins of the **same account**. If the account id changes (the old account was deleted and the address signed up again), the device gets a **new** vault key, so the new account can never open the old account's snapshot.

The **zone-key cache is not here.** The host keeps zone keys in its own sealed snapshot, so the OS keychain holds one small entry, not a growing store. The OPAQUE export key is never kept. Nothing secret appears in a `Debug` print or an error.

## Sign-up

`begin_sign_up(SignUpRequest { email, password, invite })` runs OPAQUE registration on the device (`register/start`, then the upload), generates the device keys, signs the `orbyn/device-register/v1` message and sends `register/finish`. If the server answers 428 `proof_required`, the client **solves the proof of work itself** (`orbyn_crypto::pow::solve_from`, from a random start, on a blocking thread, at most two rounds) and sends the same request again with the proof. The password is wiped once OPAQUE has used it, and no request body contains it or any encoding of it.

The result is a `PendingSignUp`. It holds the new device's keys **in memory only**: nothing is stored, and dropping it cancels, so an abandoned sign-up leaves nothing behind. `verify_sign_up(&mut pending, code)` sends the emailed code (any case; spaces and hyphens ignored). A wrong code is `InvalidCode` and leaves the sign-up open; `resend_sign_up` asks for a new one. Only on success are the keys, ids, session and a fresh vault key saved. A store that already holds a device is refused up front (`StoreNotEmpty`), and again before the code is sent, so a sign-in that finished in between is never overwritten and the code is not spent.

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
| `InvalidCode` | 400 `invalid_email_code` |
| `RateLimited { retry_after }` | 429, with the `Retry-After` seconds when sent |
| `DeletionScheduled` | 409 `deletion_scheduled` |
| `AccountGone` | A session call got 401 **and** `POST /v1/accounts/status` answered 200 with a deletion time. Nothing else gives it: the app destroys key material on this error |
| `SessionExpired` | 401 `unauthorized` and the account is alive, or the status call failed or answered anything but 200 |
| `TooLarge` | 413 |
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

### Not here yet

The approval flow itself (digits, approve and deny, `remove_device`) and the device `app` label are the next change; the integration test does the approval over HTTP with the engine's own pairing calls until then. The account's protection chain is not signed by the client; the host's first protection setting follows the rules in [architecture.md](architecture.md).

### Tests

`orbyn-server/tests/device_client.rs` runs the client over a real loopback socket against the real server on Postgres: two devices, the zone key, a sealed record that the server holds only as ciphertext, a conflict merged both ways, the snapshot round trip, a pending device refused, offline work kept and sent later, and the notices stream hearing another device's change and being rejected when the session is revoked. `tests/notices.rs` serves the stream by hand to check the sign-in message, the pong, the reconnect and the stop.
