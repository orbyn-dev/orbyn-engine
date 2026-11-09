# Accounts

Sign-up and sign-in with OPAQUE, sessions, trusted devices and approvals, the
second factor, invites, limits, deletion and push tokens.

| Module | Owns |
| --- | --- |
| `email` | Sign-up, email verification and resend |
| `email_code` | The mailed code's alphabet, grouping and typing rules |
| `service` | Account construction and shared request-context helpers |
| `register` | The OPAQUE sign-up steps and the pending sign-up record |
| `login` | The OPAQUE sign-in exchange, sessions and trusted-device checks |
| `sessions` | Session tokens and revocation |
| `devices` | Device registration, the device list and approvals |
| `second_factor` | TOTP enrolment, confirmation, disabling and sign-in |
| `totp` | The TOTP primitive and its sealed secret |
| `invites` | Invite codes for the beta |
| `limits` | Rate limits and their buckets |
| `delete` | Scheduled account deletion and cancellation |
| `delete_unused` | Deletion of an account that never held keys |
| `push_tokens` | Device push tokens |
| `secrets` | The server secret and its derived keys |

Every operation checks its own authorization against the database; a route only
parses and maps.
