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

> **NOTE**: Like the other `dpop-signer-*` packages,
> `dpop-signer-fido2-previewsign` only references an existing credential at
> runtime. If provisioned with `flags=0` (`PreviewSignOptions.Unattended`),
> only the one-time credential creation requires a touch, and subsequent
> DPoP signatures run silently via `require_up=False` (default). Pass
> `require_up=True` or `require_uv=True` if you want touch or PIN/biometric
> confirmation on every signature. See the
> [comparison table](#comparison-with-other-signers) below.

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

## Key Setup

Because `ykman` and browser/OS passkey UIs do not yet expose the CTAP 2.3
`previewSign` extension, run this minimal one-time Python snippet (requires
`fido2 >= 2.2.0`) to provision a credential and save `fido2_dpop_credential.json`:

```python
import json, os
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.ctap2.base import AttestationResponse, Ctap2
from fido2.hid import CtapHidDevice
from fido2.webauthn import AttestationObject

flags = 0  # 0 = unattended (no touch per sign), 1 = require UP, 5 = require UP+UV
resident_key = False  # True = discoverable passkey visible in Yubico Authenticator

dev = next(d for d in CtapHidDevice.list_devices() if "previewSign" in (Ctap2(d).get_info().extensions or []))
print("Touch your security key once to create the previewSign credential...")
att = Ctap2(dev).make_credential(
    os.urandom(32),
    {"id": "dpop.local", "name": "DPoP Signing"},
    {"id": os.urandom(32), "name": "dpop-signer"},
    [{"type": "public-key", "alg": -7}],
    extensions={"previewSign": {3: [-7, -65539], 4: flags}},
    options={"rk": True} if resident_key else None,
)

alg = att.auth_data.extensions["previewSign"].get(3)
att_resp = AttestationResponse.from_dict(cbor.decode(att.unsigned_extension_outputs["previewSign"][7]))
att_obj = AttestationObject.create(att_resp.fmt, att_resp.auth_data, att_resp.att_stmt)
key_handle = att_obj.auth_data.credential_data.credential_id
public_key_bytes = cbor.encode(att_obj.auth_data.credential_data.public_key)
additional_args = None
if alg == -65539:  # YubiKey 5.8 ESP256-split ARKG
    pk_cose, args = CoseKey.parse(cbor.decode(public_key_bytes)).derive_public_key(os.urandom(32), os.urandom(16))
    public_key_bytes = cbor.encode(dict(pk_cose))
    additional_args = cbor.encode(args)

saved = {
    "credential_id": att.auth_data.credential_data.credential_id.hex(),
    "key_handle": key_handle.hex(),
    "public_key_bytes": public_key_bytes.hex(),
    "rp_id": "dpop.local",
    "key_id": None,
    "require_up": bool(flags & 1),
    "require_uv": bool(flags & 4),
    **({"additional_args": additional_args.hex()} if additional_args else {}),
}
with open("fido2_dpop_credential.json", "w") as f:
    json.dump(saved, f, indent=2)
```

*(Note: if your YubiKey has a FIDO2 PIN set and requires PIN for `makeCredential`, get a `pin_uv_param` via `ClientPin` / `Fido2Client` during provisioning.)*

## Usage

```python
import json
from dpop_signer_fido2_previewsign import Fido2PreviewSignDPoPSigner

with open("fido2_dpop_credential.json") as f:
    signer = Fido2PreviewSignDPoPSigner.from_dict(json.load(f))
```

## Use with DPoPCredentials

```python
import json
from dpop_signer_fido2_previewsign import Fido2PreviewSignDPoPSigner
from google.oauth2.dpop_credentials import DPoPCredentials

with open("fido2_dpop_credential.json") as f:
    saved_data = json.load(f)

creds = DPoPCredentials.from_authorized_user_file(
    "credentials.json",
    dpop_signer=lambda: Fido2PreviewSignDPoPSigner.from_dict(saved_data),
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
| Discoverable (passkey) | Optional (`options={"rk": True}`, default non-resident) | N/A |
| Key generation | On-device via ARKG (`-65539` / `-7`) | On-device via PIV |
| Maturity | Experimental preview | Stable |

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
    pin=None,                # Optional FIDO2 PIN string or callable (raises Fido2PINRequiredError if needed and omitted)
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
