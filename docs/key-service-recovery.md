# Standard account recovery: the contract

**Design, not built.** It settles what [key-service.md](key-service.md) (Recovery, step 5 of *Order of work*) leaves open, against what is built since: the internal API, the public log API, service envelopes (8a to 8c), and the Advanced switch. Read key-service.md first; this note does not repeat the state machine, the 72-hour rule or the device trust rules, and changes them only where it says so. Questions that need a person are at the end.

## What is built, and what this adds

| Built | Not built (this contract) |
| --- | --- |
| Service key per account (P-256, in the HSM), certified and logged (entry kind 1); retire (kind 6) | Recovery rows and their clock in the key service |
| Internal API, mutual TLS, identity checked per endpoint: create-or-get, get, retire | The internal recovery endpoints (below) |
| Public API: head, consistency, entries, lookup, keys | `POST /v1/recovery/cancel` on the public API |
| Service envelopes stored by the record server, never opened | **Opening them**, the one new power |
| Audit is a `tracing` line on the `audit` target (`TracingAudit`) | An off-machine sink |

The service key is **P-256**, not the X25519 key key-service.md still names in places; the recovered device receives zone keys sealed with the device suite (`wrap_key`), as the doc says.

## The opening endpoint

Opening is the only place Orbyn reads a person's keys, so it is one endpoint with one purpose.

- **`POST /internal/v1/recoveries/{id}/finish`**, mutual TLS, allowed identity `orbyn-server` only (the per-endpoint identity rule of key-service-4.md applies: a CA-signed certificate for another client gets 403 and changes nothing).
- **It does not take "open this envelope".** It takes the recovery id, and the record server then supplies, in pages of 100, the account's service envelopes (`zone`, `key_id`, `envelope`, `statement_hash`) and the account's trusted devices. The key service already holds the recovery (the starting device and its keys, recorded at the start), so the caller cannot name a different recipient.
- **The key service decides, not the record server.** It refuses (`recovery_not_ready`) unless its own store shows `ready`: the start's first cosigned head at least 72 hours older than the newest cosigned head (the witness's signed time), no cancel in its log, a witness configured, **an audit sink that is not the tracing one** (below), and the account's service key not retired. The claim `ready` to `finishing` is a compare-and-set.
- **What an envelope must be.** Each must open under *this account's* service key and the label `orbyn/zone-key/v1` with the account, the zone and the key id the page states. A record server that sends another account's envelope, a wrong zone or key id, or a forged one gets that item refused, and the call counts failures: more than 5 in a recovery ends it `cancelled` and raises an audit alert. A record server that **omits** envelopes can only make the recovery incomplete (availability); the page set is checked against a count the record server states at the start and the log records.
- **One at a time.** Each is opened, sealed to the recovered device, signed for by the current identity, and the plaintext zeroed before the next (key-service.md, *Opening one*). Never all of an account's keys in memory at once.
- **Replays** return the stored result and do not open again.
- **The record server learns nothing:** the response is the sealed set, which only the recovered device can open.

Start and email proof are internal calls too (`POST /internal/v1/recoveries` and `.../{id}/email-proven`), but they open nothing: they append the start entry (kind 3), wait for the next cosigned head, and return that head and the inclusion proof. The start time is the head's witnessed time.

## The cancel route

- **Public API, new:** `POST /v1/recovery/cancel` on the key service's own hostname, not through the record server. The body is `orbyn/recovery-cancel/v1` over the account (as the map key), the recovery id and the time, signed by a device key. Entry kind 4.
- **Whose cancel counts:** as key-service.md: the starting device, or any device key that signed a service envelope for the account. The key service has verified those senders' signatures, so it needs no device list from the record server. The record server could add a device of its own and so gain a cancel right; that only lets it block recoveries, which it can already do.
- **Final:** `cancelled` never reverts. Accepted in `waiting_for_email`, `waiting` and `ready`; refused in `finishing` and `sealed` (`recovery_finishing`, `recovery_sealed`).
- **Limits:** 10 per account an hour, counted after the signature checks; a bad signature costs the owner nothing.
- **Cancel by email link** carries no right. The link opens the planner on a trusted device, which signs.
- **Cancel by a device that is the only one left** works the same. After a finish, old devices are removed, so there is nothing to cancel from; that is the end of the road for them (see below).

## Who is told, and over what

| Who | Channel | Can the record server withhold it? |
| --- | --- | --- |
| The owner's address | Email at the email proof, a reminder 24 hours before the end, and one when it finishes or is cancelled | Yes (the worker sends it) |
| Trusted devices | Device list banner "Someone is recovering your account" with Cancel; silent push where it exists | Yes (served by the record server) |
| Trusted devices | **The log check**: every sync and at least daily the device fetches the head and its lookup proof from the key service directly and finds the start entry | **No**, short of controlling the key service's network path |
| Trusted devices | **The 24-hour local notification** if checks stop | **No**: the client schedules it itself |

So the email and the banner are a convenience. The guarantee is the last two rows. The key service sends no email: it holds no addresses by design (the audit names a map key only), and giving it addresses would make it a mail sender with a new secret to keep. Recorded as a decision below.

The email and screens for these are not designed. Every string marked TODO-design goes to the designer before it ships: the recovery notice, the start/finish/cancel emails, the "Someone is recovering your account" banner, and the screen a person sees on the new device while waiting (with the hours left and what the old devices see).

## The audit sink

- **Today** the audit is a `tracing` line on the `audit` target for certification and retire. That stays for development.
- **Recovery needs an off-machine sink** before it can ship: append-only storage outside the key service's hosts with a retention lock. Each record: event, map key, recovery id, device id (public key hash), the time, and the sink's own sequence. No keys, no codes, no emails.
- **Events:** recovery start, email proven, cancel (and by which device), finish claimed, every open (count only, per recovery, not per zone), sealed, committed, cancelled by the key service (and why), every refused finish, identity and KEK rotation.
- **Fail closed:** a start or finish whose audit record cannot be written is refused, like "no witness, no recovery". A recovery therefore needs the sink to be up at the start and again at the finish. A self-hoster without a sink has recovery off (503), the same as without a witness.
- **Which provider is an open decision**, as is who holds the retention lock.

## What an attacker with the email alone can and cannot do

"The email alone" means read access to the mailbox, with no password, no second factor and no device.

**Cannot:**

- **Start a recovery.** A start needs a pending device with a session, and that needs the password, and the second factor when the account has one.
- **Prove the email on a recovery.** `POST /v1/recovery/{id}/email` is answered only for the starting device's own session. Reading the code is not enough.
- **Cancel, finish, or learn a cancel right.** The link in the email carries none.
- **Shorten the wait or open a key.** Time is the witness's, and only the finish opens.
- **Use up the owner's recoveries.** Only an email-proven start counts, and one needs the session.
- **Read the planner.** Nothing in the email is a key.
- **Take the address in a new sign-up.** The address is taken.

**Can:**

- **Read the recovery notices and codes sent to the address,** so learn that the owner is recovering and when (the start entry's time is public in the log anyway).
- **Cause mail to the owner** only through the existing per-address caps; this contract adds none that the mailbox holder can spend.
- **If the owner later starts a recovery, read its code before the owner does.** Useless without the owner's session, but it means the owner's mailbox is part of the trust: that is why the second factor and the 72 hours exist.

**The step up that does matter** is email plus password (the account has no second factor) or email plus password plus second factor. That person can start, prove, wait and finish, and if the owner has no trusted device left there is nobody to cancel. This is the accepted case in key-service.md ("an account with no second factor ... is recovered with its password and email alone, after the wait"). Two more consequences to decide, below: such a person can **block the owner's own recovery** (a second email-proven start answers `recovery_in_progress`) and **use up the 3 starts in 30 days**.

## Interactions with what is already built

- **Account deletion scheduled:** a start and a finish answer 409 `deletion_scheduled`, like removing a device, because a finish removes devices and ends sessions (the deletion grace period already refuses those).
- **Advanced:** a recovery for an Advanced account is refused (`recovery_unavailable`), since no copy exists. The signed setting decides, not a record-server flag. If the setting is Standard but the key service says the key is retired (Advanced then Standard without 8c-2), the answer is the same: **recovery needs 8c-2**.
- **Password change (the #74 flow):** other sessions end on a change; a recovery finish does the same for the removed devices' sessions, and the recovered device must rotate every zone key before uploading, as key-service.md says.
- **Protection chain:** a finish makes no setting. The recovered device pins the service recovery approval as its anchor and signs nothing about the level until it has verified the chain from a device it trusts.
- **Log kinds:** start 3, cancel 4, finish 5 (key-service-4.md reserved 3 to 5 for recovery and the identity map; the identity map takes the next free numbers).
- **Migrations:** key service store only: `recoveries` (id, account map key, device id and keys, state, started_head, email_proven_at, finished_at) with an append-only guard like `service_keys`; the record server gets a pointer row (`account_recoveries`: recovery id, device, state as last told) and the email proof code (a keyed digest, 8 characters, 30 minutes, 5 tries).

## Tests the implementation must carry

- A finish before 72 witnessed hours, with a cancel, with no witness, with the tracing audit sink: each refused, nothing opened (a counting HSM proves it).
- An envelope for another account, a wrong zone or key id, and a forged one are each refused without a plaintext leaving the key service.
- A cancel racing the claim: whichever commits first wins, never both.
- A cancel from a device that never signed an envelope is refused; from the starting device accepted.
- The record server's certificate for another endpoint, and a CA-signed certificate for another client, get 403 on every recovery endpoint.
- An email-alone scenario test: with the mailbox but no session, no call changes any state.
- The key service has no route that opens outside `finish`, listed by a test as in key-service-4.md.

## Decisions needed

1. **Opening by pages from the record server (this note), or the key service holding its own copy of the service envelopes?** A copy would make recovery independent of the record server's database but doubles the places a backup can leak; recommended: pages.
2. **The key service sends no email.** Confirm; the alternative is a mail sender with its own secret.
3. **Audit sink:** provider and retention lock holder (an open decision since key-service.md). Without it recovery is off.
4. **Recovery code format:** key-service.md says 6 digits; sign-up now uses 8 characters (Account Designs v62). Use the same 8 characters, 30 minutes, 5 tries? Designer.
5. **A second email-proven start while one waits:** keep `recovery_in_progress` (owner cannot supersede an attacker who has the password and email), or let a start proven by a longer second-factor-only route supersede? Lead.
6. **Burning the 3 starts in 30 days:** should a start that a trusted device cancelled not count? Lead.
7. **Minimum device-trust age and an owner notice for new devices** (Anh, from #74): do they apply to who may cancel? A device trusted for under an hour cancelling is the thief's best move.
8. **Order:** after 8d (verifier) and 8e (client wrapping and backfill), since a device that cannot verify the log cannot show the notice that makes the 72 hours mean anything.
