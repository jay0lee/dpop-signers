# dpop-signer-windows-tpm

Windows CNG/TPM DPoP signer for google-auth.

Signs DPoP proof JWTs using a private key in the Windows Certificate Store,
which may be backed by the platform TPM. No additional pip dependencies -- uses
ctypes to call CNG (ncrypt) directly.

## Install

```bash
pip install dpop-signer-windows-tpm
```

## Usage

```python
from dpop_signer_windows_tpm import WindowsCNGDPoPSigner

# Find certificate by subject name
signer = WindowsCNGDPoPSigner(subject="DPoP Signing")

# Or by SHA-1 thumbprint
signer = WindowsCNGDPoPSigner(thumbprint="a1b2c3d4...")
```

## Key Setup

```powershell
# Generate a TPM-backed ECDSA P-256 key + self-signed cert
$cert = New-SelfSignedCertificate `
    -Subject "CN=DPoP Signing" `
    -KeyAlgorithm ECDSA_nistP256 `
    -CertStoreLocation Cert:\CurrentUser\My `
    -KeyExportPolicy NonExportable `
    -Provider "Microsoft Platform Crypto Provider"
```
