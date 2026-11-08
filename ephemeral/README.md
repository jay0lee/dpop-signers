# dpop-signer-ephemeral

Ephemeral (in-memory) DPoP signer for testing.

Generates a fresh P-256 key in memory on every instantiation. The key
is never written to disk and is different each time.

## This backend is expected to FAIL

The entire point of this backend is to produce a **valid DPoP proof
signed by the wrong key**. If your refresh token is properly bound to a
different key via DPoP, the server must reject the proof and the refresh
must fail.

If a refresh using this backend **succeeds**, one of the following is true:

1. The server is not enforcing DPoP for this refresh token (the token
   was never DPoP-bound, or DPoP enforcement is disabled).
2. The refresh token was bound to DPoP but the server is accepting
   proofs signed by any valid key, not checking the thumbprint — this
   is a server-side bug.
3. The ephemeral key happened to collide with your real key's
   thumbprint. The odds of this are 1 in 2^128 — roughly the same as
   guessing a specific atom out of all atoms in the observable
   universe, or flipping a coin and getting heads 128 times in a row.
   You should probably buy a lottery ticket.

## Usage

```python
from dpop_signer_ephemeral import EphemeralDPoPSigner

signer = EphemeralDPoPSigner()
# signer.thumbprint will be different every time
```

### With GAM

```bash
gam config dpop true dpop_backend ephemeral save
gam oauth refresh   # EXPECTED: fails with invalid_dpop_proof
```
