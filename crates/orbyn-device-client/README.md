# orbyn-device-client

The native, async client a desktop app uses to be a device of an Orbyn account: sign-up with an invite, the emailed code and proof of work, sign-in (with a trusted start and the re-login that answers `reauthentication_required`), and sign-out. Built on the IO-free primitives (`orbyn-auth-client`, `orbyn-crypto`, `orbyn-contracts`); it adds the call sequence, the transport (reqwest with rustls and ring only, redirects off) and typed errors. The password never leaves the device. The design is in [docs/device-client.md](../../docs/device-client.md).
