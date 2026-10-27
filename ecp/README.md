# dpop-signer-ecp

Google Enterprise Certificate Proxy (ECP) DPoP signer for google-auth.

Signs DPoP proof JWTs using the enterprise certificate managed by Google's ECP
binary. No additional pip dependencies — communicates with the ECP helper via
subprocess.

## Install

```bash
pip install dpop-signer-ecp
```

## Usage

```python
from dpop_signer_ecp import ECPDPoPSigner

signer = ECPDPoPSigner()
# or with explicit config:
signer = ECPDPoPSigner(config_path="/path/to/certificate_config.json")
```

## Key Setup

ECP keys and certificates are provisioned by your organization's
administrator. There is no end-user key generation step.

### Prerequisites

1. The [Enterprise Certificate Proxy](https://cloud.google.com/sdk/docs/enterprise-cert-overview)
   binary must be installed.
2. A `certificate_config.json` file must be present at one of:
   - The path passed to `config_path`
   - `~/.config/gcloud/certificate_config.json` (Linux/macOS)
   - `%APPDATA%/gcloud/certificate_config.json` (Windows)

### Verify ECP is configured

```bash
gcloud auth enterprise-certificate-config list
```

### Use with DPoPSigner

If your `certificate_config.json` is in the default location, no parameters
are needed. Otherwise pass the path explicitly:

```python
from dpop_signer_ecp import ECPDPoPSigner

# Auto-discovers certificate_config.json in default locations
signer = ECPDPoPSigner()

# Or specify the config file path
signer = ECPDPoPSigner(config_path="/path/to/certificate_config.json")
```

### Notes

- The private key is managed by ECP and may be backed by a platform keystore
  (macOS Keychain, Windows Certificate Store, or PKCS#11 on Linux).
- Certificate lifecycle (issuance, renewal, revocation) is handled by your
  organization — no manual key generation is needed.
