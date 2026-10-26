# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Linux TPM 2.0 DPoP Signer (RFC 9449).

Uses ``tpm2-pytss`` (the official Python TPM2 bindings) to sign with
a persistent key stored directly in TPM non-volatile storage.  No
SQLite token database, no PKCS#11 middleware.

Supports ES256 (P-256 ECDSA) and RS256 (RSA PKCS#1 v1.5).

Prerequisites::

    # System packages (Debian/Ubuntu)
    sudo apt install tpm2-tools libtss2-dev

    # Python package
    pip install tpm2-pytss

Key setup::

    # Create an unrestricted P-256 signing key as a primary key
    tpm2_createprimary -C o -G ecc256:ecdsa-sha256 -c primary.ctx \\
        -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign'

    # Persist it at handle 0x81000001
    tpm2_evictcontrol -C o -c primary.ctx 0x81000001

    # Verify it
    tpm2_readpublic -c 0x81000001

Usage::

    from linux_tpm_dpop import LinuxTPMDPoPSigner

    signer = LinuxTPMDPoPSigner(handle=0x81000001)
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Mapping, Optional

from google.auth import _helpers
from google.auth.dpop import DPoPSigner

try:
    from tpm2_pytss import (
        ESAPI,
        ESYS_TR,
        TPM2_ALG,
        TPM2_RH,
        TPM2_ST,
        TPM2B_DIGEST,
        TPMT_SIG_SCHEME,
        TPMT_TK_HASHCHECK,
    )
    _TPM2_AVAILABLE = True
except ImportError as _import_err:
    _TPM2_AVAILABLE = False
    _IMPORT_ERROR = _import_err

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class LinuxTPMDPoPError(Exception):
    """Error raised by Linux TPM DPoP operations."""
    pass


class LinuxTPMDPoPSigner(DPoPSigner):
    """DPoP signer backed by a Linux TPM 2.0 persistent key.

    Uses ``tpm2-pytss`` to communicate with the TPM via the Enhanced
    System API (ESAPI).  The private key never leaves the TPM.

    Only unrestricted signing keys are supported (keys created without
    the ``restricted`` attribute), because DPoP requires signing
    externally-computed digests.

    Args:
        handle (int): Persistent TPM handle for the signing key
            (e.g., ``0x81000001``).
        tcti (Optional[str]): TCTI connection string.  Defaults to
            ``None`` which uses the default TCTI (typically
            ``device:/dev/tpmrm0``).
        auth (Optional[str]): Authorization value (password) for the
            key, if one was set during provisioning.
        key_id (Optional[str]): Custom identifier for this key.
    """

    def __init__(
        self,
        handle=0x81000001,
        tcti=None,
        auth=None,
        key_id=None,
    ):
        if not _TPM2_AVAILABLE:
            raise LinuxTPMDPoPError(
                f"tpm2-pytss is not installed: {_IMPORT_ERROR}. "
                "Install with: pip install tpm2-pytss"
            )

        self._handle_int = handle
        self._tcti = tcti
        self._auth = auth
        self._custom_key_id = key_id

        # Connect to TPM and read the public key.
        self._algorithm, self._public_jwk = self._read_public_key()

        logger.info(
            "Linux TPM DPoP signer initialized: handle=0x%08x, "
            "algorithm=%s, thumbprint=%s...",
            handle, self._algorithm, self.thumbprint[:16],
        )

    def _get_esapi(self):
        """Create a new ESAPI context."""
        return ESAPI(tcti=self._tcti)

    def _read_public_key(self):
        """Read the public portion of the TPM key and build a JWK."""
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        ectx = self._get_esapi()
        try:
            key_handle = ectx.tr_from_tpmpublic(self._handle_int)
            pub, _, _ = ectx.read_public(key_handle)
        finally:
            ectx.close()

        pub_area = pub.publicArea

        # EC key
        if pub_area.type == TPM2_ALG.ECC:
            curve_id = pub_area.parameters.eccDetail.curveID
            # TPM2_ECC_NIST_P256 = 0x0003
            if curve_id != 0x0003:
                raise LinuxTPMDPoPError(
                    f"Unsupported TPM EC curve ID 0x{curve_id:04x}. "
                    "Only NIST P-256 (ES256) is supported for DPoP."
                )

            x_bytes = bytes(pub_area.unique.ecc.x)
            y_bytes = bytes(pub_area.unique.ecc.y)

            # Pad to 32 bytes if shorter
            x_bytes = x_bytes.rjust(32, b"\x00")
            y_bytes = y_bytes.rjust(32, b"\x00")

            jwk = {
                "kty": "EC",
                "crv": "P-256",
                "x": _helpers.unpadded_urlsafe_b64encode(
                    x_bytes
                ).decode("ascii"),
                "y": _helpers.unpadded_urlsafe_b64encode(
                    y_bytes
                ).decode("ascii"),
            }
            return "ES256", jwk

        # RSA key
        elif pub_area.type == TPM2_ALG.RSA:
            n_bytes = bytes(pub_area.unique.rsa)
            # The exponent; 0 means the default 65537
            exp = pub_area.parameters.rsaDetail.exponent
            if exp == 0:
                exp = 65537
            e_bytes = exp.to_bytes(
                (exp.bit_length() + 7) // 8, byteorder="big"
            )

            jwk = {
                "kty": "RSA",
                "n": _helpers.unpadded_urlsafe_b64encode(
                    n_bytes
                ).decode("ascii"),
                "e": _helpers.unpadded_urlsafe_b64encode(
                    e_bytes
                ).decode("ascii"),
            }
            return "RS256", jwk

        raise LinuxTPMDPoPError(
            f"Unsupported TPM key type 0x{pub_area.type:04x}. "
            "Only ECC (ES256) and RSA (RS256) are supported."
        )

    def sign(self, data):
        """Signs data using the TPM-resident private key.

        The input is hashed with SHA-256 before being sent to the TPM.
        A null validation ticket is used (required for unrestricted
        keys signing externally-computed digests).

        For ECDSA, the TPM returns separate R and S values which are
        concatenated to raw R||S format for JWS.  For RSA, the TPM
        returns PKCS#1 v1.5 signature bytes directly.

        Args:
            data (bytes): The ASCII signing input.

        Returns:
            bytes: The signature bytes.

        Raises:
            LinuxTPMDPoPError: If signing fails.
        """
        digest = hashlib.sha256(data).digest()

        ectx = self._get_esapi()
        try:
            key_handle = ectx.tr_from_tpmpublic(self._handle_int)

            # Set authorization if provided.
            if self._auth:
                ectx.tr_set_auth(key_handle, self._auth)

            # Build signing scheme.
            scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL)

            # Null validation ticket for externally-hashed data.
            validation = TPMT_TK_HASHCHECK(
                tag=TPM2_ST.HASHCHECK,
                hierarchy=TPM2_RH.NULL,
            )

            try:
                signature = ectx.sign(
                    key_handle=key_handle,
                    digest=TPM2B_DIGEST(digest),
                    in_scheme=scheme,
                    validation=validation,
                    session1=ESYS_TR.PASSWORD,
                )
            except Exception as exc:
                raise LinuxTPMDPoPError(
                    f"TPM signing failed: {exc}.  Ensure the key at "
                    f"handle 0x{self._handle_int:08x} is an unrestricted "
                    "signing key (no 'restricted' attribute)."
                ) from exc

        finally:
            ectx.close()

        return self._extract_signature(signature)

    def _extract_signature(self, tpm_sig):
        """Convert a TPMT_SIGNATURE to raw bytes for JWS."""
        sig_alg = tpm_sig.sigAlg

        if sig_alg == TPM2_ALG.ECDSA:
            r_bytes = bytes(tpm_sig.signature.ecdsa.signatureR)
            s_bytes = bytes(tpm_sig.signature.ecdsa.signatureS)
            # Pad each to 32 bytes for P-256
            r_bytes = r_bytes.rjust(32, b"\x00")
            s_bytes = s_bytes.rjust(32, b"\x00")
            return r_bytes + s_bytes

        elif sig_alg == TPM2_ALG.RSASSA:
            return bytes(tpm_sig.signature.rsassa.sig)

        raise LinuxTPMDPoPError(
            f"Unsupported TPM signature algorithm 0x{sig_alg:04x}."
        )

    @property
    def algorithm(self):
        """str: ``'ES256'`` or ``'RS256'`` depending on the TPM key."""
        return self._algorithm

    @property
    def public_jwk(self):
        """Mapping[str, Any]: RFC 7517 public JWK dict."""
        return self._public_jwk

    @property
    def key_id(self):
        """Optional[str]: Key identifier."""
        if self._custom_key_id:
            return self._custom_key_id
        return f"tpm:0x{self._handle_int:08x}"
