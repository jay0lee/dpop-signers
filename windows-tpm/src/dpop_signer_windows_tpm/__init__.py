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

"""Windows CNG / TPM DPoP Signer (RFC 9449).

Uses ctypes to call ``crypt32.dll`` and ``ncrypt.dll`` directly.
No pip dependencies beyond google-auth.  TPM-backed keys are
transparently supported -- CNG routes signing to the TPM when the
key was provisioned with the Microsoft Platform Crypto Provider.

Supports ES256 (P-256 ECDSA) and RS256 (RSA PKCS#1 v1.5).

Key setup (TPM-backed, non-exportable)::

    # PowerShell -- creates a P-256 key in the TPM via Platform Crypto Provider
    New-SelfSignedCertificate ``
      -Subject "CN=DPoP Client" ``
      -KeyAlgorithm ECDSA_nistP256 ``
      -KeyExportPolicy NonExportable ``
      -Provider "Microsoft Platform Crypto Provider" ``
      -CertStoreLocation "Cert:\\CurrentUser\\My"

    # To list certificates and their thumbprints:
    Get-ChildItem Cert:\\CurrentUser\\My | Format-Table Subject, Thumbprint

Usage::

    from windows_dpop import WindowsCNGDPoPSigner

    # Find by subject name
    signer = WindowsCNGDPoPSigner(subject="DPoP Client")

    # Or find by SHA-1 thumbprint (hex string)
    signer = WindowsCNGDPoPSigner(thumbprint="A1B2C3D4...")
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import hashlib
import logging
import sys
from typing import Any, Mapping, Optional

if sys.platform != "win32":
    raise ImportError("windows_dpop is only supported on Windows")

from google.auth import _helpers
from google.auth.dpop import DPoPSigner

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DLL loading
# ---------------------------------------------------------------------------

_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_ncrypt = ctypes.WinDLL("ncrypt", use_last_error=True)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CERT_STORE_PROV_SYSTEM = 10
_CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
_X509_ASN_ENCODING = 0x00000001
_PKCS_7_ASN_ENCODING = 0x00010000
_ENCODING = _X509_ASN_ENCODING | _PKCS_7_ASN_ENCODING

_CERT_FIND_SUBJECT_STR = 0x00080007
_CERT_FIND_SHA1_HASH = 0x00010000

_CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000
_CRYPT_ACQUIRE_CACHE_FLAG = 0x00000001
_BCRYPT_PAD_PKCS1 = 0x00000002


# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------

class _CRYPT_HASH_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


class _BCRYPT_PKCS1_PADDING_INFO(ctypes.Structure):
    _fields_ = [
        ("pszAlgId", wintypes.LPCWSTR),
    ]


class _CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", ctypes.POINTER(ctypes.c_byte)),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", ctypes.c_void_p),
        ("hCertStore", ctypes.c_void_p),
    ]


# ---------------------------------------------------------------------------
# Function signatures
# ---------------------------------------------------------------------------

# CertOpenStore
_crypt32.CertOpenStore.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, ctypes.c_void_p,
]
_crypt32.CertOpenStore.restype = ctypes.c_void_p

# CertFindCertificateInStore
_crypt32.CertFindCertificateInStore.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
    wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
]
_crypt32.CertFindCertificateInStore.restype = ctypes.POINTER(_CERT_CONTEXT)

# CryptAcquireCertificatePrivateKey
_crypt32.CryptAcquireCertificatePrivateKey.argtypes = [
    ctypes.POINTER(_CERT_CONTEXT), wintypes.DWORD, ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.BOOL),
]
_crypt32.CryptAcquireCertificatePrivateKey.restype = wintypes.BOOL

# CertFreeCertificateContext
_crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
_crypt32.CertFreeCertificateContext.restype = wintypes.BOOL

# CertCloseStore
_crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
_crypt32.CertCloseStore.restype = wintypes.BOOL

# NCryptSignHash
_ncrypt.NCryptSignHash.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_void_p, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
]
_ncrypt.NCryptSignHash.restype = wintypes.LONG

# NCryptFreeObject
_ncrypt.NCryptFreeObject.argtypes = [ctypes.c_void_p]
_ncrypt.NCryptFreeObject.restype = wintypes.LONG


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _open_my_store():
    """Open the CurrentUser\\MY certificate store."""
    h_store = _crypt32.CertOpenStore(
        _CERT_STORE_PROV_SYSTEM,
        0, None,
        _CERT_SYSTEM_STORE_CURRENT_USER,
        ctypes.c_wchar_p("MY"),
    )
    if not h_store:
        raise WindowsCNGDPoPError(
            f"CertOpenStore failed (error {ctypes.get_last_error()})."
        )
    return h_store


def _find_cert_by_subject(h_store, subject):
    """Find a certificate by subject CN substring."""
    cert_ctx = _crypt32.CertFindCertificateInStore(
        h_store, _ENCODING, 0,
        _CERT_FIND_SUBJECT_STR,
        ctypes.c_wchar_p(subject),
        None,
    )
    if not cert_ctx:
        raise WindowsCNGDPoPError(
            f"No certificate found with subject containing '{subject}'. "
            "Use Get-ChildItem Cert:\\CurrentUser\\My to list certificates."
        )
    return cert_ctx


def _find_cert_by_thumbprint(h_store, thumbprint_hex):
    """Find a certificate by SHA-1 thumbprint (hex string)."""
    thumb_bytes = bytes.fromhex(thumbprint_hex)
    blob_array = (ctypes.c_byte * len(thumb_bytes))(*thumb_bytes)
    blob = _CRYPT_HASH_BLOB()
    blob.cbData = len(thumb_bytes)
    blob.pbData = blob_array

    cert_ctx = _crypt32.CertFindCertificateInStore(
        h_store, _ENCODING, 0,
        _CERT_FIND_SHA1_HASH,
        ctypes.byref(blob),
        None,
    )
    if not cert_ctx:
        raise WindowsCNGDPoPError(
            f"No certificate found with thumbprint '{thumbprint_hex}'. "
            "Use Get-ChildItem Cert:\\CurrentUser\\My to list certificates."
        )
    return cert_ctx


def _acquire_ncrypt_key(cert_ctx):
    """Acquire a CNG (NCrypt) key handle from a certificate context."""
    h_key = ctypes.c_void_p()
    key_spec = wintypes.DWORD()
    caller_free = wintypes.BOOL()

    ok = _crypt32.CryptAcquireCertificatePrivateKey(
        cert_ctx,
        _CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | _CRYPT_ACQUIRE_CACHE_FLAG,
        None,
        ctypes.byref(h_key),
        ctypes.byref(key_spec),
        ctypes.byref(caller_free),
    )
    if not ok:
        raise WindowsCNGDPoPError(
            f"CryptAcquireCertificatePrivateKey failed "
            f"(error {ctypes.get_last_error()}).  "
            "Ensure the certificate has an associated private key."
        )
    return h_key.value, caller_free.value


def _extract_public_key_from_cert(cert_ctx):
    """Parse the DER certificate to extract the public key for JWK.

    Uses the cryptography library (already a google-auth dependency)
    to parse the X.509 certificate embedded in the CERT_CONTEXT.
    """
    from cryptography import x509

    der_bytes = ctypes.string_at(
        cert_ctx.contents.pbCertEncoded,
        cert_ctx.contents.cbCertEncoded,
    )
    cert = x509.load_der_x509_certificate(der_bytes)
    return cert.public_key()


def _public_key_to_jwk(public_key):
    """Convert a cryptography public key to (algorithm, JWK dict)."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve
        if not isinstance(curve, ec.SECP256R1):
            raise WindowsCNGDPoPError(
                f"Unsupported EC curve for DPoP: {curve.name}. "
                "Only P-256 (ES256) and RSA (RS256) are supported."
            )
        nums = public_key.public_numbers()
        x_bytes = nums.x.to_bytes(32, byteorder="big")
        y_bytes = nums.y.to_bytes(32, byteorder="big")
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _helpers.unpadded_urlsafe_b64encode(x_bytes).decode("ascii"),
            "y": _helpers.unpadded_urlsafe_b64encode(y_bytes).decode("ascii"),
        }
        return "ES256", jwk

    elif isinstance(public_key, rsa.RSAPublicKey):
        nums = public_key.public_numbers()
        e_bytes = nums.e.to_bytes(
            (nums.e.bit_length() + 7) // 8, byteorder="big",
        )
        n_bytes = nums.n.to_bytes(
            (nums.n.bit_length() + 7) // 8, byteorder="big",
        )
        jwk = {
            "kty": "RSA",
            "n": _helpers.unpadded_urlsafe_b64encode(n_bytes).decode("ascii"),
            "e": _helpers.unpadded_urlsafe_b64encode(e_bytes).decode("ascii"),
        }
        return "RS256", jwk

    raise WindowsCNGDPoPError(
        f"Unsupported key type: {type(public_key).__name__}"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class WindowsCNGDPoPError(Exception):
    """Error raised by Windows CNG DPoP operations."""
    pass


class WindowsCNGDPoPSigner(DPoPSigner):
    """DPoP signer backed by Windows CNG / TPM.

    Uses ctypes to call ``crypt32.dll`` and ``ncrypt.dll``.
    No pip dependencies beyond google-auth.  TPM-backed keys are
    transparently supported -- CNG routes to the TPM automatically
    when the key was created with the Platform Crypto Provider.

    Supports ES256 (P-256) and RS256 (RSA).

    Args:
        subject (str): Certificate subject CN substring to search
            for in ``Cert:\\CurrentUser\\My``.
        thumbprint (str): SHA-1 thumbprint hex string (alternative
            to *subject*).
        key_id (Optional[str]): Custom identifier for this key.
    """

    def __init__(
        self,
        subject=None,
        thumbprint=None,
        key_id=None,
    ):
        if not subject and not thumbprint:
            raise ValueError(
                "Either 'subject' or 'thumbprint' must be provided."
            )

        self._custom_key_id = key_id
        self._h_key = None
        self._caller_free_key = False

        # Open cert store and find certificate
        h_store = _open_my_store()
        try:
            if thumbprint:
                cert_ctx = _find_cert_by_thumbprint(h_store, thumbprint)
            else:
                cert_ctx = _find_cert_by_subject(h_store, subject)

            try:
                # Acquire CNG key handle
                self._h_key, self._caller_free_key = _acquire_ncrypt_key(
                    cert_ctx
                )

                # Extract public key from certificate DER
                pub_key = _extract_public_key_from_cert(cert_ctx)
                self._algorithm, self._public_jwk = _public_key_to_jwk(
                    pub_key
                )
            finally:
                _crypt32.CertFreeCertificateContext(cert_ctx)
        finally:
            _crypt32.CertCloseStore(h_store, 0)

        logger.info(
            "Windows CNG DPoP signer initialized: algorithm=%s, "
            "thumbprint=%s...",
            self._algorithm, self.thumbprint[:16],
        )

    @property
    def algorithm(self):
        """str: ``'ES256'`` or ``'RS256'`` depending on the certificate key."""
        return self._algorithm

    @property
    def public_jwk(self):
        """Mapping[str, Any]: RFC 7517 public JWK dict."""
        return self._public_jwk

    @property
    def key_id(self):
        """Optional[str]: Key identifier."""
        return self._custom_key_id

    def sign(self, data):
        """Signs data using CNG ``NCryptSignHash``.

        The input is hashed with SHA-256 before signing.  For ECDSA,
        CNG returns raw R||S bytes (exactly what JWS ES256 requires --
        no conversion needed).  For RSA, CNG returns PKCS#1 v1.5
        signature bytes.

        Args:
            data (bytes): The ASCII signing input.

        Returns:
            bytes: The signature bytes.

        Raises:
            WindowsCNGDPoPError: If signing fails.
        """
        digest = hashlib.sha256(data).digest()

        # Set up padding info for RSA; ECDSA needs none.
        if self._algorithm == "RS256":
            padding_info = _BCRYPT_PKCS1_PADDING_INFO()
            padding_info.pszAlgId = "SHA256"
            p_padding = ctypes.cast(
                ctypes.pointer(padding_info), ctypes.c_void_p
            )
            flags = _BCRYPT_PAD_PKCS1
        else:
            p_padding = None
            flags = 0

        # First call: query required buffer size.
        cb_result = wintypes.DWORD(0)
        status = _ncrypt.NCryptSignHash(
            self._h_key, p_padding,
            digest, len(digest),
            None, 0,
            ctypes.byref(cb_result),
            flags,
        )
        if status != 0:
            raise WindowsCNGDPoPError(
                f"NCryptSignHash size query failed (0x{status:08X})."
            )

        # Second call: perform signing.
        sig_buf = ctypes.create_string_buffer(cb_result.value)
        actual_size = wintypes.DWORD(0)
        status = _ncrypt.NCryptSignHash(
            self._h_key, p_padding,
            digest, len(digest),
            sig_buf, cb_result.value,
            ctypes.byref(actual_size),
            flags,
        )
        if status != 0:
            raise WindowsCNGDPoPError(
                f"NCryptSignHash failed (0x{status:08X})."
            )

        return sig_buf.raw[:actual_size.value]

    def __del__(self):
        if self._h_key and self._caller_free_key:
            try:
                _ncrypt.NCryptFreeObject(self._h_key)
            except Exception:
                pass
