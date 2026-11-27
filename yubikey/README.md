# dpop-signer-yubikey

YubiKey PIV DPoP signer for google-auth.

Signs DPoP proof JWTs using a private key stored in a YubiKey's PIV applet.

## Install

```bash
pip install dpop-signer-yubikey
```

Requires [yubikey-manager](https://docs.yubico.com/software/yubikey/tools/ykman/)
(`ykman`) to be installed.

## Usage

```python
import getpass
from dpop_signer_yubikey import YubiKeyDPoPSigner, YubiKeyPINRequiredError

# Static PIN or deferred callable (invoked lazily on sign(), cached for session):
signer = YubiKeyDPoPSigner(pin="123456")
signer = YubiKeyDPoPSigner(slot="9a", pin=lambda: getpass.getpass("PIV PIN: "))

# If PIN is omitted and the slot requires verification, sign() raises
# YubiKeyPINRequiredError so the caller can decide how to prompt or fail.
```

## Key Setup

YubiKey PIV uses X.509 certificates. DPoP only needs the private key for
signing — the certificate is just a container that the YubiKey requires. Set
a long validity (10950 days = 30 years) so it never becomes a problem.

### Generate a P-256 key and self-signed certificate (slot 9c)

Slot `9c` (Digital Signature) is recommended — it never requires touch
confirmation after PIN entry.

```bash
# Generate the private key on the YubiKey (never leaves the device)
ykman piv keys generate -a ECCP256 9c pubkey.pem

# Create a self-signed certificate (30 year validity)
ykman piv certificates generate \
    -s "CN=DPoP Signing" \
    -d 10950 \
    9c pubkey.pem

# Clean up the public key file (it's stored on the YubiKey)
rm pubkey.pem
```

### Verify

```bash
ykman piv info
```

### Use with DPoPSigner

The `slot` parameter matches the slot you generated the key in (above: `9c`).
The default slot is `9c` (SIGNATURE), so if you used that you can omit it:

```python
from dpop_signer_yubikey import YubiKeyDPoPSigner

# Matches the key generated in slot 9c above
signer = YubiKeyDPoPSigner(pin="123456")

# Or explicitly specify the slot
signer = YubiKeyDPoPSigner(slot="9c", pin="123456")
```

### Available slots

| Slot | Name | Touch policy |
|------|------|-------------|
| `9a` | Authentication | May require touch per operation |
| `9c` | Digital Signature | No touch after PIN (recommended) |
| `9d` | Key Management | Varies |
| `9e` | Card Authentication | No PIN required |

### PIN

The default PIV PIN is `123456`. Change it:

```bash
ykman piv access change-pin
```

`dpop-signer-yubikey` never reads from stdin or prompts on its own. Pass `pin=`
as either a string or a zero-argument callable (for example `lambda: getpass.getpass(...)`);
omitting it on a PIN-protected slot or passing a wrong PIN raises
`YubiKeyPINRequiredError`.
