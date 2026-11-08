# Standard account recovery: the contract

**Design, not built.** It settles what [key-service.md](key-service.md) (Recovery, step 5 of *Order of work*) leaves open, against what is built since: the internal API, the public log API, service envelopes (8a to 8c), and the Advanced switch. Read key-service.md first; this note does not repeat the state machine, the 72-hour rule or the device trust rules, and changes them only where it says so. Decisions made by Products Research for the owner are marked **Decided** and listed at the end; what is still open is marked **Open**.

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
- **Minimum device-trust age (Decided).** A device may cancel only if it has been trusted for at least **1 hour** at the recovery's start (measured at the start's witnessed time, not now), so a device added just before or during an attack cannot cancel. **The device that started the recovery may cancel its own**, whatever its age. **Open (mechanism):** the key service takes no device list from the record server, so it needs something it can check. Proposal: the cancel carries the device's approval record (the approver's signature and time from `orbyn/device-approval/v1`) and the key service checks it chains to a device that has signed a service envelope for the account and is at least an hour older than the start head's time. Nobody joins an account during a recovery anyway, so measuring at the start loses no honest cancel.
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

**Decided** (needed before open sign-up, not for the invite beta).

- **Where:** append-only object storage with a **compliance-mode retention lock**, in a **separate cloud account used for nothing else**, owned by Anh. S3 Object Lock is recommended; any store with the same lock is acceptable. The key service's writer role can create objects in the bucket and nothing else (no delete, no lock change, no read of other records); the people who run the servers hold no role on that account.
- **The retention lock is held by Anh, never by whoever runs the servers.** Compliance mode means not even the account owner can shorten a retention period or delete a locked object, so the lock outlives a compromised operator. The retention period is set at bucket creation and is not shorter than the longest recovery and rotation history worth keeping (proposal: 7 years); a shorter one is a decision for Anh.
- **Today** the audit is a `tracing` line on the `audit` target for certification and retire (`TracingAudit`). That stays for development and the invite beta. It is not an acceptable sink for recovery.
- **What each record holds:** the event name; the account's **map key** (never the account id or the address); the recovery id; the device id as a hash of its public key; the time (the key service's clock, and the witnessed head time where one exists); the key service's identity version; a per-record sequence number and the hash of the previous record, so a deleted or reordered object shows as a gap in the chain. **No keys, no codes, no emails, no envelope bytes, no zone names.**
- **Events:** recovery start, email proven, cancel (and the device that signed it), finish claimed, opens (a count per recovery, not one per zone), sealed, committed, cancelled by the key service (and why), every refused finish, identity and KEK rotation, certification and retire (as today).
- **Fail closed:** a start or a finish whose audit record cannot be written (the sink is unreachable, the writer role is refused, or the chain does not continue from the last acknowledged object) is **refused**, and nothing is opened. A recovery therefore needs the sink at the start and again at the finish, as it needs a witness. A deployment without the sink has recovery off (503 `recovery_unavailable`), the invite beta included, until it is configured. A self-hoster may point it at their own store with the same lock; the guarantee then rests on who holds that lock.

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

**The step up that does matter** is email plus password (the account has no second factor) or email plus password plus second factor. That person can start, prove, wait and finish, and if the owner has no trusted device left there is nobody to cancel. This is the accepted case in key-service.md ("an account with no second factor ... is recovered with its password and email alone, after the wait"). Two consequences are **Decided**: such a person can **block the owner's own recovery** (a second email-proven start answers `recovery_in_progress`; nothing supersedes a waiting one), and can **use up the 3 starts in 30 days**, because a start that a trusted device cancelled still counts. **Plainly: an owner who then loses every device inside that window waits until it ends.** There is no way around it that would not also let an attacker with the password and the mailbox reset the limit by cancelling their own starts.

## Interactions with what is already built

- **Account deletion scheduled:** a start and a finish answer 409 `deletion_scheduled`, like removing a device, because a finish removes devices and ends sessions (the deletion grace period already refuses those).
- **Advanced:** a recovery for an Advanced account is refused (`recovery_unavailable`), since no copy exists. The signed setting decides, not a record-server flag. If the setting is Standard but the key service says the key is retired (Advanced then Standard without 8c-2), the answer is the same: **recovery needs 8c-2**.
- **Password change (the #74 flow, see the password-change contract):** the same minimum device-trust age of 1 hour applies to a password change; other sessions end on a `change`; a recovery finish ends the removed devices' sessions too, and the recovered device must rotate every zone key before uploading, as key-service.md says.
- **Protection chain:** a finish makes no setting. The recovered device pins the service recovery approval as its anchor and signs nothing about the level until it has verified the chain from a device it trusts.
- **Log kinds:** start 3, cancel 4, finish 5 (key-service-4.md reserved 3 to 5 for recovery and the identity map; the identity map takes the next free numbers).
- **Migrations:** key service store only: `recoveries` (id, account map key, device id and keys, state, started_head, email_proven_at, finished_at) with an append-only guard like `service_keys`; the record server gets a pointer row (`account_recoveries`: recovery id, device, state as last told) and the email proof code (**Decided:** the same 8 characters as sign-up, from the 30-symbol alphabet, shown grouped, 30 minutes, 5 tries; kept as a keyed digest, not derived).

## Tests the implementation must carry

- A finish before 72 witnessed hours, with a cancel, with no witness, with the tracing audit sink: each refused, nothing opened (a counting HSM proves it).
- An envelope for another account, a wrong zone or key id, and a forged one are each refused without a plaintext leaving the key service.
- A cancel racing the claim: whichever commits first wins, never both.
- A cancel from a device that never signed an envelope is refused; from the starting device accepted.
- The record server's certificate for another endpoint, and a CA-signed certificate for another client, get 403 on every recovery endpoint.
- An email-alone scenario test: with the mailbox but no session, no call changes any state.
- The key service has no route that opens outside `finish`, listed by a test as in key-service-4.md.

## Decisions

**Decided** (Products Research, for Anh):

1. **The record server pages in the envelopes.** The key service keeps no copy of service envelopes.
2. **The key service sends no email.**
3. **Audit sink:** append-only object storage, compliance-mode retention lock, separate account used for nothing else, owned by Anh; S3 Object Lock recommended. The lock is Anh's, never the operators'. Fail closed. Needed before open sign-up, not for the invite beta. Detail above.
4. **Recovery code:** 8 characters as in sign-up, 30 minutes, 5 tries.
5. **A second email-proven start while one waits** keeps `recovery_in_progress`; nothing supersedes it.
6. **A start a trusted device cancelled still counts** toward the 3 in 30 days. An owner who then loses every device within the window waits.
7. **Minimum device-trust age of 1 hour** for who may cancel a recovery and for a password change. The device that started a recovery may cancel its own. An account's very first device is exempt for a password change. The owner is told of every password change.
8. **Order:** after 8d (the client verifier) and 8e (client wrapping and backfill), since a device that cannot verify the log cannot show the notice that makes the 72 hours mean anything. This PR stays design-only until both land.

**Open:**

- How the key service checks a device's trust age without a device list (proposal under *The cancel route*).
- Every string: the recovery notice, the start, reminder, finish and cancel emails, the banner, and the waiting screen (the designer, via the coordinator).
- The retention period of the audit bucket (proposal: 7 years; Anh).
