# dpop-signer-macos-secureenclave

macOS Secure Enclave DPoP signer for google-auth.

Signs DPoP proof JWTs using a P-256 private key stored in the Mac's Secure
Enclave. No additional pip dependencies — uses ctypes to call
Security.framework directly.

## Install

```bash
pip install dpop-signer-macos-secureenclave
```

## Usage

```python
from dpop_signer_macos_secureenclave import SecureEnclaveDPoPSigner

signer = SecureEnclaveDPoPSigner(label="dpop-signing")
```

## Key Setup (macOS 15+)

Use `sc_auth` to create a Secure Enclave identity. The `-k p-256-ne` flag
creates a P-256 key that is non-exportable (stored in the Secure Enclave).

```bash
sc_auth create-ctk-identity -l dpop-signing -k p-256-ne
```

### With Touch ID protection

Add `-t bio` to require Touch ID (or password) for each signing operation:

```bash
sc_auth create-ctk-identity -l dpop-signing -k p-256-ne -t bio
```

### Verify

```bash
sc_auth list-ctk-identities
```

### About the self-signed certificate

`sc_auth create-ctk-identity` generates a self-signed certificate alongside
the key with a default 1-year validity. There is no flag to change this.
This does not matter — DPoP uses the raw private key for signing, not the
certificate. The key remains usable in the Secure Enclave regardless of
certificate expiry.

### Delete an identity

```bash
# Find the hash
sc_auth list-ctk-identities

# Delete by hash
sc_auth delete-ctk-identity -h <PUBLIC_KEY_HASH>
```

### Algorithm

Only P-256 (ES256) is supported by the Secure Enclave.
