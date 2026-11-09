# orbyn-witness

The witness: it checks each head the key service builds, including both map
updates and every account's chain, keeps its state with `fsync` before it answers,
and cosigns with its own time. It also serves `POST /v1/cosign` and
`GET /v1/cosignature`, and provides the cosign client with a threshold and chunked
catch-up. `TestWitness` is behind `test-support`.
