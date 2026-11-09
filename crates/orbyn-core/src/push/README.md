# Push

Silent push: waking a device that subscribed to a zone. A push says nothing. The
sender receives the provider, the device's token, a fixed collapse key and a
message id made from the job and the device; the delivered message is constant, so
no zone, change token, record, account, device or count is in it. The woken device
syncs through its ordinary authenticated path. No token, digest or provider answer
is logged.

| Module | Owns |
| --- | --- |
| `mod.rs` | The push record, the provider boundary, the fixed message and delivery |
