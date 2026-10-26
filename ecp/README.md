# dpop-signer-ecp

Google Enterprise Certificate Proxy (ECP) DPoP signer for google-auth.

Signs DPoP proof JWTs using the enterprise certificate managed by Google's ECP
binary. No additional pip dependencies -- communicates with the ECP helper via
subprocess.

## Install

```bash
pip install dpop-signer-ecp
```

## Usage

```python
from dpop_signer_ecp import ECPDPoPSigner

signer = ECPDPoPSigner()
# or with explicit config: ECPDPoPSigner(config_path="/path/to/certificate_config.json")
```

## Prerequisites

The [Enterprise Certificate Proxy](https://cloud.google.com/sdk/docs/enterprise-cert-overview)
binary must be installed and configured.
