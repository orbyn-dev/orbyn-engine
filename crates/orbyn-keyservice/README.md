# orbyn-keyservice

The key service library: the `Hsm` boundary and the operations Standard protection
uses. The KEK, identity keys and log key never leave the HSM; an account key comes
out only wrapped under the KEK, and one envelope is opened at a time. PKCS#11
(SoftHSM and cloud HSMs) is behind the `pkcs11` feature; `MemoryHsm` is behind
`test-support` and never ships. No HTTP and no deployment.
