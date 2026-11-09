# orbyn-translog

The transparency log as pure code: the RFC 9162 Merkle tree, inclusion and
consistency proofs with their verifiers, an append-only accumulator, and the
path-compressed sparse Merkle map with membership and non-membership proofs and
the witness's update function. It also carries the cosignature, its verification
and the witness threshold rule. No IO; the same code runs on the key service and
on devices, including WebAssembly.
