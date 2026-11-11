# Orbyn Engineering on the Engine

What Orbyn Engineering keeps in the account's encrypted record store, and the rules every device follows. The code is `crates/orbyn-engineering` (MIT OR Apache-2.0, no IO, no dependency on any app). The shared test vectors are `crates/orbyn-engineering/tests/vectors/settings.json`; the app runs them too.

## What this is, and is not

- **One account, one zone key set, every trusted device.** Zone keys are wrapped to every trusted device of the account (see Keychain in [architecture.md](architecture.md)). So an Engineering device holds every zone key, the Planner's included, and a Planner device holds Engineering's. **This is not isolation between apps.** Per-app isolation is the later "connected apps" grants (Planned); until then an app on a trusted device can read what any other app of the account stores. Anything that must not reach another app does not belong in a zone.
- **The account is optional** in Engineering. Signed out, everything here stays local. Sync failures never block work.
- **No wire change.** Records are opaque encrypted fields to the server, and a zone name is any 1 to 64 characters. Nothing here needs a new endpoint or a new contract type, so `orbyn-contracts` is unchanged.

## Zones

A zone name is chosen by the client (1 to 64 characters, no control characters; the server checks nothing else). The Planner names its zones by kind and id: `list:<id>`, `project:<id>`, `calendar:<id>`, and the account-level `settings` zone (tags only). Engineering's rule keeps them apart:

> `engineering.<kind>` for a zone of one record set, `engineering.<kind>:<id>` for one per thing. The kind is lowercase letters, digits and `-`, starting with a letter. The id is lowercase letters, digits and `-`. At most 64 characters.

`orbyn_engineering::is_zone_name` checks it. The Planner's names never start with `engineering.`, and no Engineering zone is named `settings`.

| Zone | Record type | Record id | What it holds |
| --- | --- | --- | --- |
| `engineering.settings` | `person_settings` | `person` | Personal settings that follow the person. One record per account. |

**Later, not built:** execution profiles, workflows, prompts, env-set names, personal Crew defaults, trust scores and review memory. Each gets its own zone name under the rule above, designed when it is built.

**Never synced:** the Crew ledger, transcripts, diffs, env-set values, provider keys, join tokens and any secret. A later opt-in may share task summaries and attestation hashes.

## The settings record

One record (`person_settings`, id `person`) in `engineering.settings`. Its fields are a map of field name to value, each with its own hybrid logical clock stamp, and two copies merge **field by field** with `orbyn_sync::merge_remote`: the larger stamp wins each field, so two devices that changed different fields both keep their edits, every device ends with the same record in any order, and a stamp more than an hour ahead of the receiving clock is left out and named. The record is never deleted; a field goes back to its default with `null`. **20 keys sync** (18 plain fields and the two sets) **plus the keybindings**; 19 more never do (below).

### Plain fields

Scalars, enums, numbers, objects and `model_order` are **last writer wins per field**, and `null` means "the default". Keys: at most 64 characters, `a-z 0-9 _ . :` only, and **never starting with `_`**: orbyn-sync's own fields start with it (`_deleted` makes a record read as deleted), so such a name is refused in both directions. A value this version cannot read (a wrong type, an enum value a newer app added) reads as the default and **stays in the record untouched**.

| Key | Kind | Values | Default |
| --- | --- | --- | --- |
| `default_theme` | text | `system`, `light`, `dark`, or a theme id (1 to 64 of `a-z 0-9 _ . : -`) | `system` |
| `default_engine`, `default_model`, `fallback_model`, `text_generation_model`, `default_effort` | text | any | `""` |
| `branch_name_prefix` | text | any | `feat` |
| `branch_name_instructions` | text | any | `""` |
| `response_streaming_mode` | enum | `paragraph`, `turn` | `paragraph` |
| `default_thread_env_mode` | enum | `local`, `worktree` | `local` |
| `branch_naming_mode` | enum | `static`, `semantic`, `custom` | `static` |
| `quit_confirmation` | enum | `direct`, `hold`, `double_press` | `direct` |
| `preview_appearance` | enum | `system`, `light`, `dark` | `system` |
| `auto_thread_titles` | bool | | `true` |
| `open_web_links_in_app` | bool | | `false` |
| `preview_zoom` | number | finite, above 0, up to 10 | `1` |
| `default_model_options` | object | option id to one value (text, number or boolean); at most 500 entries. **Free-form: it must never hold a provider token, key or any secret** (the app's responsibility; the crate cannot tell) | `{}` |
| `model_order` | list | model ids as text, replaced whole by the last writer; at most 500 | `[]` |

### Sets: `favorite_models` and `hidden_models`

One field per element, so an add on one machine and a removal on another merge instead of one list overwriting the other. The field name is **derived**, never the raw id, because model ids contain `-`, `/`, capitals and can be long:

> `<list>.<first 16 characters of the lower-case, unpadded base32 (RFC 4648) of SHA-256(id)>`

The value is the id itself (1 to 512 characters). **Ids are compared by their raw bytes**: the NFC and NFD spellings of a name are two different members (no normalisation, so every port derives the same field). **A removal is `null`** with its own stamp (a tombstone), so a removal on machine A is not undone by an older copy on machine B, and an add stamped after a removal brings the element back. Example: `openrouter/anthropic/claude-sonnet-4-5` in `favorite_models` is the field `favorite_models.zfkx7fd4ugwrihff`. A field whose value does not hash to its own name is not read, and is refused when it arrives from another device.

### Keybindings

One field per rule: `keybinding.<same derivation of SHA-256(key + NUL + when)>`, where `when` is the empty text when the rule has none (a `when` may not be empty, so the two never collide). `cmd+shift+K` with no `when` is `keybinding.z4rjbdh3flaouhs7` and with `when` `inputFocus` it is `keybinding.sraksp7653s72pjx`. The value is the rule `{key, command, when?, remove?}`; `remove: true` is the app's "take the default binding away", and is a rule like any other. **Removing a rule from the record is `null`**, as for sets. Same limits: key 1 to 128, command 1 to 256, `when` 1 to 512 characters.

### Limits, capacity and errors

| Limit | Value |
| --- | --- |
| Field name | 64 characters, `a-z 0-9 _ . :`, not starting with `_` |
| One value | 8 KiB of JSON |
| The record | 64 KiB, as the JSON of its fields with their stamps (the engine accepts 256 KiB per record) |
| A list | 500 entries: set members, keybinding rules, `model_order`, `default_model_options` |

**Real capacity.** The record cap is what a person reaches first. One set element costs about the id's length plus 93 bytes, and about 120 with real stamps (a 13-digit time and a device number of up to 20 digits), so about **360 favourites of 60 characters** fit. The 500-entry list cap is an upper bound that the record cap reaches first for any id longer than about 12 characters.

**Where the cap is enforced: local writes only.** A merge from another device is **always applied** (`accept_remote`), whatever the size, so devices converge: two devices that each added 250 favourites both end with all 500. A local write is refused with `TooLarge` (the message names the 8 KiB, 64 KiB and 500 limits) when it would take the record past 64 KiB **and** make it bigger. A write that does not grow the record (a removal, a reset) is always allowed, so a record that merged past the cap can always be brought back under it.

**Compaction.** A removal leaves a `null` field, which is what stops an older copy bringing the element back. Every local write drops the removals stamped **more than 90 days before the write's own stamp**, so adding and removing many distinct ids does not fill the record for good. **A device that stays offline longer than that, holding an addition that was removed elsewhere, can bring that addition back when it reconnects.** Removals younger than 90 days (exactly 90 days is still kept) are always kept.

Typed errors (`SettingsError`, which never carries the value): `InvalidKey`, `NotSynced`, `TooLarge`, `UnknownKey` (a write to a key this version does not have), `InvalidValue`, `TooFarAhead` (a remote stamp more than an hour ahead). Writes check before they change anything.

### Never synced: `NotSynced`

`environment_icon`, `keep_awake_during_runs`, `background_activity_profile`, `add_project_base_directory`, `provider_instances`, `custom_models`, `observability`, `storage_cleanup`, `worktree_cleanup`, `app_update_mode`, `automatic_git_fetch_minutes`, `provider_health_refresh_minutes`, `prefer_saved_login`, `disabled_engines`, `default_theme_set_at`, and four that **widen what agents may do**: `default_permission_mode`, `default_project_scripts`, `enable_agent_browser_access`, `enable_agent_device_access`. 19 keys in all. Eleven hold paths, provider connections or secrets, or only mean something on one machine. The last four are different: **cross-device escalation**. A setting that widens what agents may do or run (a `full_access` permission mode, project scripts, browser or device access for agents) must be chosen on each machine, because one machine, or a buggy or hostile peer, must not be able to loosen another. The crate refuses all 19 **in both directions**: a write is `NotSynced`, and a field with such a name from another device is dropped and named, so nothing secret or loosening enters by mistake or by a buggy peer.

### Versions and unknown fields

There is no record version. Fields are independent and additive: a newer app adds a key, or an enum value, and an older one **keeps it and passes it on**. That is storage, not permission: **the app must apply only the keys on its own allowlist** and never act on a key it does not know, so a key a newer version added (or a peer invented) is carried but not obeyed. `Settings` wraps the merged fields exactly as stored, so editing a known field never rewrites an unknown one, and `unknown()` lists them. A field's meaning never changes; a change of meaning is a new key.

## Using it

```rust
let mut settings = Settings::from_fields(stored_fields);
settings.set("default_theme", json!("dark"), stamp)?;       // stamp from orbyn_sync::Clock
settings.add("favorite_models", "openrouter/anthropic/claude-sonnet-4-5", stamp)?;
settings.bind(&Rule { key: "cmd+shift+K".into(), command: "thread.new".into(), when: None, remove: false }, stamp)?;
let accepted = settings.accept_remote(&fields_from_the_server, now_millis); // names what it refused
let fields_to_store_and_upload = settings.fields();
```

The device stages those fields as the record `person` of type `person_settings` in zone `engineering.settings` with the device engine (`orbyn-client`), like any other record. The merge and the checks are the same on every device because they are this crate's.

## Test vectors

`settings.json` holds derivations (the exact field names above), key checks, defaults, and scenarios: add on A and remove on B (both orders), concurrent adds, keybindings with and without `when`, a key and an enum value from a newer app, over-limit values, the record cap on local writes and its absence on remote merges, 250 + 250 favourites converging, churn and compaction (a removal at 90 days and younger), `_deleted` from a peer, NFC against NFD, and refused incoming fields. The file says how each op and expectation is read, so an app can run it against its own port.
