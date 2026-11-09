# Feeds

Fetching calendar feeds (ICS) on a device's behalf. Browsers often cannot read a
feed directly and the desktop content policy forbids it, so the engine fetches it.
Because the engine then fetches URLs people choose, every request is checked: HTTPS
on the default port, no credentials in the URL, every resolved address checked at
connection time, private and link-local ranges refused, redirects followed by hand,
and at most 5 MiB, 10 seconds and 60 fetches an hour per account.

| Module | Owns |
| --- | --- |
| `mod.rs` | The fetch policy, the guarded resolver, the limit and the returned body |
