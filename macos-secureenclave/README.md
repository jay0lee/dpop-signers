# dpop-signer-macos-secureenclave

macOS Secure Enclave DPoP signer for google-auth.

Signs DPoP proof JWTs using a P-256 private key stored in the Mac's Secure
Enclave. No additional pip dependencies -- uses ctypes to call
Security.framework directly.

## Install

```bash
pip install dpop-signer-macos-secureenclave
```

## Usage

```python
from dpop_signer_macos_secureenclave import SecureEnclaveDPoPSigner

signer = SecureEnclaveDPoPSigner(label="my-dpop-key")
```

## Key Setup (macOS 15+)

```bash
# Create a P-256 key in the Secure Enclave
sc_auth identities -t se -s "DPoP Signing Key"
```
