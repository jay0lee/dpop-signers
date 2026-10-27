# dpop-signer-windows-tpm

Windows CNG/TPM DPoP signer for google-auth.

Signs DPoP proof JWTs using a private key in the Windows Certificate Store,
backed by the platform TPM. No additional pip dependencies — uses ctypes to
call CNG (ncrypt) directly.

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

Use PowerShell to generate a TPM-backed ECDSA P-256 key with a self-signed
certificate. The "Microsoft Platform Crypto Provider" ensures the private key
is created in the TPM and never leaves it.

### Generate a TPM-backed key (30 year cert)

```powershell
New-SelfSignedCertificate `
    -Subject "CN=DPoP Signing" `
    -KeyAlgorithm ECDSA_nistP256 `
    -CertStoreLocation Cert:\CurrentUser\My `
    -KeyExportPolicy NonExportable `
    -Provider "Microsoft Platform Crypto Provider" `
    -NotAfter (Get-Date).AddYears(30)
```

### Verify

```powershell
# List the certificate
Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -eq "CN=DPoP Signing" |
    Format-List Subject, Thumbprint, NotAfter, HasPrivateKey
```

### Use with DPoPSigner

The `subject` parameter matches the CN from `-Subject` (without the `CN=`
prefix). You can also use the certificate's `Thumbprint` shown in the verify
step above:

```python
from dpop_signer_windows_tpm import WindowsCNGDPoPSigner

# By subject — matches -Subject "CN=DPoP Signing" above
signer = WindowsCNGDPoPSigner(subject="DPoP Signing")

# Or by thumbprint from the verify output
signer = WindowsCNGDPoPSigner(thumbprint="A1B2C3D4...")
```

### Confirm TPM backing

```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object Subject -eq "CN=DPoP Signing"
$key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetECDsaPrivateKey($cert)
$key.Key.Provider  # Should show "Microsoft Platform Crypto Provider"
```

### Delete

```powershell
Get-ChildItem Cert:\CurrentUser\My |
    Where-Object Subject -eq "CN=DPoP Signing" |
    Remove-Item
```

### Notes

- The certificate itself is not used for DPoP — it's just the container
  Windows uses to associate with the TPM-backed private key.
- If your machine does not have a TPM, CNG will fall back to software key
  storage. To verify TPM backing, check the provider name as shown above.
- Supported algorithms: ECDSA P-256 (ES256), ECDSA P-384 (ES384), RSA 2048+
  (RS256).
