# dpop-signer-windows-certstore

Windows Certificate Store DPoP signer for google-auth.

Signs DPoP proof JWTs using a certificate's private key stored in the Windows
Certificate Store (`Cert:\CurrentUser\My` or `Cert:\LocalMachine\My`). Works
transparently whether Windows backs the key with the hardware TPM (Platform
Crypto Provider), software key storage, or a smart card. No additional pip
dependencies — uses ctypes to call Windows `crypt32` and `ncrypt` APIs directly.

## Install

```bash
pip install dpop-signer-windows-certstore
```

## Usage

```python
from dpop_signer_windows_certstore import WindowsCertStoreDPoPSigner

# Find certificate by subject name
signer = WindowsCertStoreDPoPSigner(subject="DPoP Signing")

# Or by SHA-1 thumbprint
signer = WindowsCertStoreDPoPSigner(thumbprint="a1b2c3d4...")

# Or look in Cert:\LocalMachine\My (for SSH / scheduled task sessions)
signer = WindowsCertStoreDPoPSigner(
    subject="DPoP Signing",
    store_location="local_machine",
)
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
from dpop_signer_windows_certstore import WindowsCertStoreDPoPSigner

# By subject — matches -Subject "CN=DPoP Signing" above
signer = WindowsCertStoreDPoPSigner(subject="DPoP Signing")

# Or by thumbprint from the verify output
signer = WindowsCertStoreDPoPSigner(thumbprint="A1B2C3D4...")
```

### Confirm TPM backing

```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object Subject -eq "CN=DPoP Signing"
$key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetECDsaPrivateKey($cert)
$key.Key.Provider  # Should show "Microsoft Platform Crypto Provider"
```

### Headless / SSH / Scheduled Tasks (`LocalMachine` store)

Over key-based OpenSSH sessions or non-interactive scheduled tasks (where the
user is not logged on interactively with a password), Windows does not unlock
the user's DPAPI master key, so `CurrentUser\My` software keys fail with
`CryptAcquireCertificatePrivateKey failed (error -2146893802)` (`NTE_BAD_KEYSET`).

Storing the certificate in `Cert:\LocalMachine\My` avoids user DPAPI protection:

1. In an **Administrator** PowerShell prompt, create the certificate in
   `Cert:\LocalMachine\My`:

```powershell
New-SelfSignedCertificate `
    -Subject "CN=DPoP Signing" `
    -KeyAlgorithm ECDSA_nistP256 `
    -CertStoreLocation Cert:\LocalMachine\My `
    -KeyExportPolicy NonExportable `
    -Provider "Microsoft Platform Crypto Provider" `
    -NotAfter (Get-Date).AddYears(30)
```

   (Omit `-Provider "Microsoft Platform Crypto Provider"` if using the default
   Microsoft Software Key Storage Provider.)

2. Grant **Read** permission on the private key to the user or service account
   running the script (by default only `Administrators` and `SYSTEM` have access):
   - **GUI**: Run `certlm.msc`, open **Personal -> Certificates**, right-click
     the certificate -> **All Tasks -> Manage Private Keys...**, and grant
     the account **Read** permission.
   - **CLI (Software KSP)**: Find the `Unique container name` via
     `certutil -store My "DPoP Signing"`, then grant Read access:
     `icacls "C:\ProgramData\Microsoft\Crypto\Keys\<Unique_Container_Name>" /grant "<USER>:(R)"`

3. Pass `store_location="local_machine"`:

```python
signer = WindowsCertStoreDPoPSigner(
    subject="DPoP Signing",
    store_location="local_machine",
)
```

### Delete

```powershell
Get-ChildItem Cert:\CurrentUser\My |
    Where-Object Subject -eq "CN=DPoP Signing" |
    Remove-Item
```

### Notes

- The certificate itself is not used for DPoP — it's the container Windows
  uses to associate with the managed private key (whether hardware TPM, software
  key storage, or smart card).
- If your machine does not have a TPM, Windows falls back to software key
  storage. To verify TPM backing, check the provider name as shown above.
- Supported algorithms: ECDSA P-256 (`ES256`) and RSA 2048+ (`RS256`).
