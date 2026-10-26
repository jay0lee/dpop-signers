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

"""Enterprise Certificate Proxy (ECP) DPoP Signer (RFC 9449).

This module implements :class:`google.auth.dpop.DPoPSigner` using Google's
enterprise-certificate-proxy (ECP) shared library.  The private key material
lives in the platform certificate store (macOS Keychain, Windows CNG/CAPI,
Linux PKCS#11) and is accessed through the same ``ecp_client`` signer library
that google-auth already uses for mTLS.

Only ES256 (P-256 + SHA-256) and RS256 (RSA + SHA-256) are supported because
ECP's ``SignForPython`` accepts a pre-hashed SHA-256 digest.

Setup:
    1. Install and configure enterprise-certificate-proxy:
       https://github.com/googleapis/enterprise-certificate-proxy

    2. Ensure your ``~/.config/gcloud/certificate_config.json`` (or the
       path you pass) contains a valid ``libs.ecp_client`` entry pointing
       to the compiled signer library.

Usage::

    from ecp_dpop import ECPDPoPSigner
    from google_auth_oauthlib.flow import InstalledAppFlow

    signer = ECPDPoPSigner()  # uses default certificate_config.json
    flow = InstalledAppFlow.from_client_secrets_file(
        "client_secrets.json",
        scopes=["openid"],
        dpop_signer=signer,
    )
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import sys
from typing import Any, Mapping, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from google.auth import _helpers
from google.auth.dpop import DPoPSigner, der_to_raw_ecdsa_signature

logger = logging.getLogger(__name__)

# Default certificate config path (matches gcloud CLI convention).
_DEFAULT_CERT_CONFIG_PATHS = [
    os.path.join(
        os.environ.get("APPDATA", ""),
        "gcloud",
        "certificate_config.json",
    )
    if os.name == "nt"
    else os.path.expanduser("~/.config/gcloud/certificate_config.json"),
]


class ECPDPoPError(Exception):
    """Base error for ECP DPoP operations."""
    pass


class ECPConfigError(ECPDPoPError):
    """Raised when the enterprise certificate config is missing or invalid."""
    pass


class ECPSigningError(ECPDPoPError):
    """Raised when the ECP signer library fails a signing operation."""
    pass


def _find_cert_config(config_path=None):
    """Resolves the enterprise certificate config file path.

    Args:
        config_path: Explicit path, or None to search defaults.

    Returns:
        str: Absolute path to the certificate config JSON.

    Raises:
        ECPConfigError: If no config file can be found.
    """
    if config_path:
        path = os.path.expanduser(config_path)
        if not os.path.isfile(path):
            raise ECPConfigError(
                f"Enterprise cert config not found at: {path}"
            )
        return os.path.abspath(path)

    # Also check GOOGLE_API_CERTIFICATE_CONFIG env var.
    env_path = os.environ.get("GOOGLE_API_CERTIFICATE_CONFIG")
    if env_path and os.path.isfile(env_path):
        return os.path.abspath(env_path)

    for candidate in _DEFAULT_CERT_CONFIG_PATHS:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)

    raise ECPConfigError(
        "No enterprise certificate config found. Searched: {}. "
        "Set GOOGLE_API_CERTIFICATE_CONFIG or pass config_path explicitly.".format(
            ", ".join(_DEFAULT_CERT_CONFIG_PATHS)
        )
    )


def _load_signer_lib(signer_lib_path):
    """Loads the ECP signer shared library and sets up ctypes signatures.

    This mirrors google.auth.transport._custom_tls_signer.load_signer_lib().

    Args:
        signer_lib_path: Path to the ecp_client shared library.

    Returns:
        ctypes.CDLL: The loaded library with configured argtypes/restypes.

    Raises:
        ECPConfigError: If the library cannot be loaded.
    """
    try:
        lib = (
            ctypes.CDLL(signer_lib_path, winmode=0)
            if sys.version_info >= (3, 8) and os.name == "nt"
            else ctypes.CDLL(signer_lib_path)
        )
    except OSError as exc:
        raise ECPConfigError(
            f"Failed to load ECP signer library at '{signer_lib_path}': {exc}"
        ) from exc

    # GetCertPemForPython(configFilePath *C.char, certHolder *byte, certHolderLen int) -> certLen
    lib.GetCertPemForPython.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    lib.GetCertPemForPython.restype = ctypes.c_int

    # SignForPython(configFilePath *C.char, digest *byte, digestLen int,
    #               sigHolder *byte, sigHolderLen int) -> sigLen
    lib.SignForPython.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    lib.SignForPython.restype = ctypes.c_int

    return lib


def _get_cert_pem(signer_lib, config_path):
    """Retrieves the client certificate PEM from the ECP signer library.

    Two-pass call: first to get the length, second to fill the buffer.

    Args:
        signer_lib: Loaded ctypes signer library.
        config_path: Path to the certificate config JSON.

    Returns:
        bytes: The PEM-encoded certificate.

    Raises:
        ECPConfigError: If the certificate cannot be retrieved.
    """
    config_bytes = config_path.encode("utf-8")

    # First call: get cert length.
    cert_len = signer_lib.GetCertPemForPython(config_bytes, None, 0)
    if cert_len == 0:
        raise ECPConfigError(
            "ECP signer library returned empty certificate. "
            "Check your enterprise certificate configuration."
        )

    # Second call: fill buffer.
    cert_holder = ctypes.create_string_buffer(cert_len)
    signer_lib.GetCertPemForPython(config_bytes, cert_holder, cert_len)
    return bytes(cert_holder)


def _sign_digest(signer_lib, config_path, digest):
    """Signs a pre-computed SHA-256 digest using the ECP signer library.

    Args:
        signer_lib: Loaded ctypes signer library.
        config_path: Path to the certificate config JSON.
        digest: 32-byte SHA-256 digest.

    Returns:
        bytes: The DER-encoded signature.

    Raises:
        ECPSigningError: If signing fails.
    """
    config_bytes = config_path.encode("utf-8")
    digest_array = (ctypes.c_char * len(digest)).from_buffer(bytearray(digest))

    # Reserve 2000 bytes for signature (RSA=256, EC=70-72).
    sig_holder_len = 2000
    sig_holder = ctypes.create_string_buffer(sig_holder_len)

    sig_len = signer_lib.SignForPython(
        config_bytes,
        digest_array,
        len(digest),
        sig_holder,
        sig_holder_len,
    )

    if sig_len == 0:
        raise ECPSigningError(
            "ECP signer library failed to sign the digest. "
            "Check that the certificate private key is accessible."
        )

    return bytes(sig_holder[:sig_len])


def public_key_to_jwk(public_key):
    """Converts a cryptography public key to JWS algorithm and RFC 7517 JWK.

    Args:
        public_key: An :class:`ec.EllipticCurvePublicKey` or
            :class:`rsa.RSAPublicKey`.

    Returns:
        Tuple[str, Mapping[str, Any], int]:
            (algorithm_name, public_jwk_dict, curve_byte_size).
            curve_byte_size is 0 for RSA keys.

    Raises:
        ValueError: If the key type or curve is unsupported for DPoP.
    """
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve
        if isinstance(curve, ec.SECP256R1):
            alg = "ES256"
            crv_size = 32
            crv_name = "P-256"
        else:
            raise ValueError(
                f"Unsupported curve for ECP DPoP: {curve.name}. "
                "Only P-256 (ES256) is supported because ECP uses SHA-256 digests."
            )

        pub_numbers = public_key.public_numbers()
        x_bytes = pub_numbers.x.to_bytes(crv_size, byteorder="big")
        y_bytes = pub_numbers.y.to_bytes(crv_size, byteorder="big")

        jwk = {
            "kty": "EC",
            "crv": crv_name,
            "x": _helpers.unpadded_urlsafe_b64encode(x_bytes).decode("ascii"),
            "y": _helpers.unpadded_urlsafe_b64encode(y_bytes).decode("ascii"),
        }
        return alg, jwk, crv_size

    elif isinstance(public_key, rsa.RSAPublicKey):
        alg = "RS256"
        pub_numbers = public_key.public_numbers()
        e_bytes = pub_numbers.e.to_bytes(
            (pub_numbers.e.bit_length() + 7) // 8, byteorder="big"
        )
        n_bytes = pub_numbers.n.to_bytes(
            (pub_numbers.n.bit_length() + 7) // 8, byteorder="big"
        )
        jwk = {
            "kty": "RSA",
            "n": _helpers.unpadded_urlsafe_b64encode(n_bytes).decode("ascii"),
            "e": _helpers.unpadded_urlsafe_b64encode(e_bytes).decode("ascii"),
        }
        return alg, jwk, 0

    raise ValueError(f"Unsupported key type for ECP DPoP: {type(public_key)}")


class ECPDPoPSigner(DPoPSigner):
    """DPoP Signer backed by Google's Enterprise Certificate Proxy (ECP).

    The private key resides in the platform certificate store and is never
    exported.  Signing is performed via the ECP signer library's
    ``SignForPython`` function, which accepts a pre-hashed SHA-256 digest.

    Only ES256 and RS256 are supported (ECP signs SHA-256 digests only).

    Args:
        config_path (Optional[str]): Path to the enterprise certificate JSON
            config file.  Defaults to ``~/.config/gcloud/certificate_config.json``
            or the ``GOOGLE_API_CERTIFICATE_CONFIG`` environment variable.
        key_id (Optional[str]): Optional custom key identifier.
    """

    def __init__(self, config_path=None, key_id=None):
        self._config_path = _find_cert_config(config_path)
        self._custom_key_id = key_id

        # Load the signer library.
        with open(self._config_path, "r") as f:
            cert_config = json.load(f)

        libs = cert_config.get("libs", {})
        signer_lib_path = libs.get("ecp_client")
        if not signer_lib_path:
            raise ECPConfigError(
                "Enterprise cert config is missing 'libs.ecp_client'. "
                f"Config file: {self._config_path}"
            )

        if not os.path.isfile(signer_lib_path):
            raise ECPConfigError(
                f"ECP signer library not found at: {signer_lib_path}"
            )

        self._signer_lib = _load_signer_lib(signer_lib_path)
        logger.info("Loaded ECP signer library from %s", signer_lib_path)

        # Retrieve certificate and extract public key.
        cert_pem = _get_cert_pem(self._signer_lib, self._config_path)
        cert = x509.load_pem_x509_certificate(cert_pem)
        self._public_key = cert.public_key()

        # Determine algorithm and build JWK.
        alg, jwk, crv_size = public_key_to_jwk(self._public_key)
        self._algorithm = alg
        self._public_jwk = jwk
        self._crv_size = crv_size

        logger.info(
            "ECP DPoP signer initialized: algorithm=%s, thumbprint=%s",
            self._algorithm,
            self.thumbprint[:16] + "...",
        )

    @property
    def algorithm(self):
        """str: The JWS signing algorithm ('ES256' or 'RS256')."""
        return self._algorithm

    @property
    def public_jwk(self):
        """Mapping[str, Any]: The public key as an RFC 7517 JWK dict."""
        return self._public_jwk

    @property
    def key_id(self):
        """Optional[str]: Identifier for this ECP-backed key."""
        return self._custom_key_id or f"ecp:{os.path.basename(self._config_path)}"

    def sign(self, data):
        """Signs the input bytes using the platform certificate store via ECP.

        The data is first hashed with SHA-256, then the digest is passed to
        ECP's ``SignForPython``.  For ECDSA keys, the DER-encoded signature
        is converted to raw (R || S) format per RFC 7515 Section 3.4.

        Args:
            data (bytes): The ASCII data to sign (typically
                ``b'<b64url_header>.<b64url_payload>'``).

        Returns:
            bytes: The raw signature bytes.

        Raises:
            ECPSigningError: If the ECP library fails to produce a signature.
        """
        # Hash the data with SHA-256 (ECP expects a pre-hashed digest).
        digest = hashlib.sha256(data).digest()

        # Call ECP to sign the digest.
        der_sig = _sign_digest(self._signer_lib, self._config_path, digest)

        # For ECDSA, convert DER to raw (R || S).
        if self._algorithm.startswith("ES"):
            return der_to_raw_ecdsa_signature(der_sig, self._crv_size)

        return der_sig
