# dpop-signer-yubikey

YubiKey PIV DPoP signer for google-auth.

Signs DPoP proof JWTs using a private key stored in a YubiKey's PIV applet.

## Install

```bash
pip install dpop-signer-yubikey
```

## Usage

```python
from dpop_signer_yubikey import YubiKeyDPoPSigner

signer = YubiKeyDPoPSigner(pin="123456")
# or: signer = YubiKeyDPoPSigner(slot="9a", pin="123456")
```

## Key Setup

Generate a key on the YubiKey (slot 9c = Digital Signature):

```bash
ykman piv keys generate -a ECCP256 9c pubkey.pem
ykman piv certificates generate -s "DPoP" 9c pubkey.pem
```
