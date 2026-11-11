# orbyn-engineering

What Orbyn Engineering keeps in the account's encrypted record store: the names of its zones and record types, and the settings that follow a person across devices, as `orbyn_sync::Fields` so they merge field by field. Pure and synchronous, with no IO and no dependency on any app, so the same code runs in the Engineering app, a test and WebAssembly. The design (zones, records, fields, limits, what never syncs) is in [docs/engineering.md](../../docs/engineering.md); `tests/vectors/settings.json` is the shared input and expected output any client can run.
