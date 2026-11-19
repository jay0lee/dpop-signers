# dpop-signer-pkcs11

PKCS#11 DPoP signer for google-auth.

Works with any PKCS#11 (Cryptoki) module across Linux, macOS, and Windows:
- **Linux:** `tpm2-pkcs11`, `OpenSC`, `libykcs11`, `SoftHSM2`, enterprise/cloud HSMs
- **macOS:** `OpenSC` (`brew install opensc`), `SoftHSM2` (`brew install softhsm`), YubiKey `libykcs11`, `native-pkcs11`
- **Windows:** OpenSC (`opensc-pkcs11.dll`), YubiKey Manager (`libykcs11.dll`), SoftHSM2 (`softhsm2-x64.dll`), HSM vendor DLLs, `native-pkcs11`

Supports [RFC 7512](https://www.rfc-editor.org/rfc/rfc7512) `pkcs11:` URIs as
the primary configuration input, plus optional keyword overrides. Supports
`ES256` (P-256), `ES384` (P-384), and `RS256` (RSA).

## Install

```bash
pip install dpop-signer-pkcs11
```

## Usage

### Using an RFC 7512 `pkcs11:` URI

Pass the same `pkcs11:` URI used by CLI tools (`p11tool`, `pkcs11-tool`,
OpenSSL `pkcs11-provider`):

```python
import getpass
from dpop_signer_pkcs11 import PKCS11DPoPSigner
from google_auth_oauthlib.flow import InstalledAppFlow

# 1. Full URI including module-path and PIN source:
signer = PKCS11DPoPSigner(
    "pkcs11:token=tpm2;object=dpop;id=%01"
    "?module-path=/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so"
    "&pin-source=file:/run/secrets/tpm-pin"
)

# 2. URI for key selection + runtime PIN callback + deferred Flow factory:
flow = InstalledAppFlow.from_client_secrets_file(
    "client_secrets.json",
    scopes=["openid"],
    dpop_signer=lambda: PKCS11DPoPSigner(
        "pkcs11:token=YubiKey%20PIV;id=%02?module-name=libykcs11",
        pin=lambda: getpass.getpass("PIV PIN: "),
    ),
)
```

### Using keyword arguments or `PKCS11_MODULE`

```python
from dpop_signer_pkcs11 import PKCS11DPoPSigner

signer = PKCS11DPoPSigner(
    module_path="/opt/homebrew/lib/softhsm/libsofthsm2.so",
    token_label="dpop",
    key_label="dpop-key",
    pin="1234",
)
```

## Supported RFC 7512 URI Attributes

- **Path attributes (`;`):** `token`, `object`, `id` (percent-encoded `CKA_ID` bytes, e.g. `%01%02`), `slot-id`, `serial`, `manufacturer`, `model`, `type`
- **Query attributes (`&`):** `module-path`, `module-name` (resolved via `p11-kit` module configs or standard PKCS#11 directories), `pin-value`, `pin-source` (`file:/path/to/pin`)

Any explicit keyword arguments (`module_path=`, `pin=`, `token_label=`, `key_label=`, `cka_id=`, `slot_id=`, `token_serial=`) override the corresponding URI attribute.

## Common Module Paths

| Backend | OS | Typical `module-path` |
|---------|----|-----------------------|
| `tpm2-pkcs11` | Linux | `/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so` |
| `OpenSC` | Linux | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |
| `OpenSC` | macOS (Homebrew) | `/opt/homebrew/lib/opensc-pkcs11.so` |
| `OpenSC` | Windows | `C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll` |
| `SoftHSM2` | Linux | `/usr/lib/softhsm/libsofthsm2.so` |
| `SoftHSM2` | macOS (Homebrew) | `/opt/homebrew/lib/softhsm/libsofthsm2.so` |
