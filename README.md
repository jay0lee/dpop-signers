# DPoP Signers for google-auth

Hardware-backed [DPoP (RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449) signer
implementations for use with
[google-auth](https://github.com/googleapis/google-cloud-python/tree/main/packages/google-auth)'s
`DPoPCredentials`.

Each signer is a separate pip package so you only install the dependencies you
need.

## Packages

| Package | Platform | Hardware | Extra deps |
|---------|----------|----------|------------|
| [dpop-signer-yubikey](yubikey/) | Any | YubiKey PIV | `yubikey-manager` |
| [dpop-signer-fido2-previewsign](fido2-previewsign/) | Any | FIDO2 CTAP 2.3 (previewSign) | `fido2` |
| [dpop-signer-macos-secureenclave](macos-secureenclave/) | macOS | Secure Enclave | none |
| [dpop-signer-windows-tpm](windows-tpm/) | Windows | TPM (via CNG) | none |
| [dpop-signer-linux-tpm](linux-tpm/) | Linux | TPM 2.0 | `tpm2-pytss` |
| [dpop-signer-ecp](ecp/) | Any | Enterprise Certificate Proxy | none |

## Install

```bash
# From PyPI (once published):
pip install dpop-signer-yubikey

# From GitHub:
pip install "dpop-signer-yubikey @ git+https://github.com/jay0lee/dpop-signers.git#subdirectory=yubikey"
```

## Usage

Every signer implements the `google.auth.dpop.DPoPSigner` interface and plugs
directly into `DPoPCredentials`:

```python
from dpop_signer_yubikey import YubiKeyDPoPSigner
from google.oauth2.dpop_credentials import DPoPCredentials

signer = YubiKeyDPoPSigner(pin="123456")

creds = DPoPCredentials(
    token=None,
    dpop_signer=signer,
    refresh_token="...",
    token_uri="https://oauth2.googleapis.com/token",
    client_id="...",
    client_secret="...",
)
```

## Touch / Biometric / PIN Requirements

| Signer | Touch per sign? | PIN/biometric per sign? | Unattended? |
|--------|----------------|------------------------|-------------|
| Software (PEM) | No | No | Yes |
| YubiKey PIV (slot 9c) | No | Once per session | Yes |
| FIDO2 previewSign | **Yes, every time** | Once per session | **No** |
| macOS Secure Enclave | No | Optional (if created with `-t bio`) | Depends |
| Windows CNG/TPM | No | No | Yes |
| Linux TPM | No | No | Yes |
| ECP | No | No | Yes |

## License

Apache 2.0
