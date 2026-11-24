# dpop-signer-fido2-previewsign

FIDO2 CTAP 2.3 `previewSign` DPoP signer for google-auth.

Signs DPoP proof JWTs using a hardware-backed ECDSA P-256 key on a FIDO2
security key via the experimental `previewSign` CTAP2 extension. The private
key is generated on-chip and **never leaves the hardware**.

> **WARNING**: The `previewSign` extension is an experimental preview
> specification ([WebAuthn Sign Extension](https://github.com/yubicolabs/webauthn-sign-extension))
> and is subject to change. Use at your own risk.

## Supported Hardware

Any FIDO2 security key that implements the `previewSign` CTAP2 extension:

- **YubiKey 5 Series** with firmware 5.8+
- **Yubico Security Key** with firmware 5.8+
- Other CTAP 2.3 authenticators implementing the sign extension

## Install

```bash
pip install dpop-signer-fido2-previewsign
```

Requires the [python-fido2](https://github.com/Yubico/python-fido2) library
(`fido2 >= 2.2.0`).

> **NOTE**: By default (`require_up=False`), `generate_signing_credential()`
> provisions the key with `PreviewSignOptions.Unattended = 0` so only the
> one-time key creation requires a touch, and subsequent DPoP signatures run
> silently via CTAP2 `options={"up": False}`. Pass `require_up=True` or
> `require_uv=True` if you want touch or PIN/biometric confirmation on every
> signature. See the [comparison table](#comparison-with-other-signers) below.

## How It Works

Unlike the PIV-based `dpop-signer-yubikey` which uses the YubiKey's PIV
applet (PKCS#11-style), this signer uses the FIDO2/CTAP2 protocol directly:

1. **Key Generation**: A FIDO2 `makeCredential` operation with the
   `previewSign` extension creates a hardware-backed ECDSA P-256 signing
   key via ARKG (Asynchronous Remote Key Generation).
2. **Signing**: A FIDO2 `getAssertion` operation with the `previewSign`
   extension sends the raw to-be-signed bytes to the authenticator, which
   returns a standard ECDSA P-256 signature.
3. **No PIV needed**: Does not use the PIV applet, management keys, or
   X.509 certificates.

## Key Generation

Generate a signing credential directly on the security key:

```python
from dpop_signer_fido2_previewsign import generate_signing_credential

# Insert your security key and run:
signer = generate_signing_credential()
# Prompts once for touch (and FIDO2 PIN if configured).
# Pass resident_key=True to store as a discoverable passkey visible in
# Yubico Authenticator, require_up=True for touch per sign, require_uv=True
# for PIN/biometric verification per sign, or pin="..." for non-interactive PIN.

# Save the credential for later use (no private key leaves the device)
import json
saved = json.dumps(signer.to_dict())
print(saved)
```

The `generate_signing_credential()` function will:
1. Find a connected FIDO2 device supporting `previewSign`
2. Prompt for touch confirmation once (and PIN if configured on the key)
3. Create an on-device ECDSA P-256 / ARKG signing key
4. Return a signer ready to produce DPoP proofs (unattended by default)

## Restoring a Previously Generated Credential

```python
import json
from dpop_signer_fido2_previewsign import Fido2PreviewSignDPoPSigner

saved = json.loads(open("fido2_dpop_credential.json").read())
signer = Fido2PreviewSignDPoPSigner.from_dict(saved)
```

## Use with DPoPCredentials

```python
from dpop_signer_fido2_previewsign import (
    Fido2PreviewSignDPoPSigner,
    generate_signing_credential,
)
from google.oauth2.dpop_credentials import DPoPCredentials

# Generate a new credential (first time only)
signer = generate_signing_credential()

# Or restore a saved credential lazily so hardware isn't accessed until refresh:
# creds = DPoPCredentials.from_authorized_user_file(
#     "credentials.json",
#     dpop_signer=lambda: Fido2PreviewSignDPoPSigner.from_dict(saved_data),
# )

creds = DPoPCredentials.from_authorized_user_file(
    "credentials.json", dpop_signer=signer
)
```

## Comparison with Other Signers

| Feature | fido2-previewsign | yubikey (PIV) |
|---------|-------------------|---------------|
| Protocol | FIDO2/CTAP2 | PIV/CCID |
| Key types | ES256 only | ES256, ES384, RS256 |
| Hardware | Any CTAP 2.3 key | YubiKey only |
| PIV management key | Not needed | Required for key gen |
| X.509 certificate | Not needed | Required by PIV |
| PIN | Optional (if configured / `require_uv=True`) | PIV PIN (once per session) |
| Touch per sign | Optional (No by default; `require_up=True`) | No (slot 9c after PIN) |
| Unattended use | Yes (default, `require_up=False`) | Yes |
| Discoverable (passkey) | Optional (`resident_key=True`, default `False`) | N/A |
| Key generation | On-device via ARKG (`-65539` / `-7`) | On-device via PIV |
| Maturity | Experimental preview | Stable |

## Key Generation Parameters

```python
generate_signing_credential(
    rp_id="dpop.local",      # Relying party ID
    rp_name="DPoP Signing",  # Relying party display name
    user_id=None,            # Random 32 bytes if omitted
    user_name="dpop-signer", # User name for the credential
    key_id=None,             # Optional custom key identifier
    device=None,             # Optional pre-resolved CtapHidDevice
    user_interaction=None,   # Optional UserInteraction for PIN/touch
    require_up=False,        # True = require physical touch per signature
    require_uv=False,        # True = require PIN/biometric per signature
    resident_key=False,      # True = discoverable credential in Yubico Authenticator
    pin=None,                # Optional FIDO2 PIN (non-interactive)
)
```

## Constructor Parameters

```python
Fido2PreviewSignDPoPSigner(
    credential_id=b"...",    # FIDO2 credential ID from registration
    key_handle=b"...",       # ARKG key handle from previewSign
    public_key_bytes=b"...", # CBOR-encoded COSE public key
    rp_id="dpop.local",      # Relying party ID (must match registration)
    key_id=None,             # Optional custom key identifier
    device=None,             # Optional pre-resolved CtapHidDevice
    user_interaction=None,   # Optional UserInteraction for PIN/touch
    additional_args=None,    # CBOR ARKG signing args (for ESP256-split keys)
    require_up=False,        # True = require touch per signature
    require_uv=False,        # True = require PIN/biometric per signature
    pin=None,                # Optional FIDO2 PIN (non-interactive)
)
```

## Persistence

Save and restore credentials (no private key material is included):

```python
import json

# Save
data = signer.to_dict()
with open("fido2_dpop_credential.json", "w") as f:
    json.dump(data, f)

# Restore
with open("fido2_dpop_credential.json") as f:
    data = json.load(f)
signer = Fido2PreviewSignDPoPSigner.from_dict(data)
```

## Troubleshooting

### "No FIDO2 HID device found"

Make sure your security key is plugged in via USB. Bluetooth/NFC
are not supported for CTAP HID.

### "previewSign extension not supported"

Your security key firmware does not support `previewSign`. Check:
- YubiKey: requires firmware 5.8+ (`ykman info`)
- Other keys: check manufacturer documentation

### Platform restrictions

On some platforms (particularly Windows), the OS may intercept FIDO2
requests. Use a direct USB connection and avoid platform authenticator
passthrough when possible.
