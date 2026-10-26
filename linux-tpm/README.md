# dpop-signer-linux-tpm

Linux TPM 2.0 DPoP signer for google-auth.

Signs DPoP proof JWTs using a persistent key on a TPM 2.0 device via
`tpm2-pytss`.

## Install

```bash
pip install dpop-signer-linux-tpm
```

Requires `tpm2-tss` system libraries. On Debian/Ubuntu:

```bash
sudo apt install libtss2-dev
```

## Usage

```python
from dpop_signer_linux_tpm import LinuxTPMDPoPSigner

signer = LinuxTPMDPoPSigner(handle=0x81000001)
```

## Key Setup

```bash
# Create a primary key under the owner hierarchy
tpm2_createprimary -C o -g sha256 -G ecc256 -c primary.ctx

# Create a signing key
tpm2_create -C primary.ctx -g sha256 -G ecc256 \
    -u key.pub -r key.priv -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign"

# Load and persist at handle 0x81000001
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_evictcontrol -C o -c key.ctx 0x81000001
```
