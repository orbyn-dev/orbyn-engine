# Mail

The message model, the designed bodies and the sender boundary. A message's
content is rendered here; the worker supplies the SMTP sender. Nothing in a log
line carries an address, a code or a message body.

| Module | Owns |
| --- | --- |
| `mod.rs` | `Mail`, the message kinds and the `Sender` boundary |
| `render.rs` | Plain-text and HTML bodies, and the grouping of sign-up codes |
