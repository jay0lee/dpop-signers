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

"""macOS Secure Enclave DPoP Signer (RFC 9449).

Uses ctypes to call Security.framework and CoreFoundation directly.
No pip dependencies beyond google-auth.

Only ES256 (P-256) is supported -- this is a Secure Enclave hardware
limitation.  RSA and P-384 keys cannot be created in the SE.

Key setup (macOS 15+, Secure Enclave)::

    # Create a Secure Enclave-backed identity
    sc_auth create-ctk-identity -t com.apple.setoken

    # List available identities
    sc_auth list-ctk-identities

Usage::

    from macos_dpop import SecureEnclaveDPoPSigner

    signer = SecureEnclaveDPoPSigner(label="com.apple.security.ctkidentity.XXXXXX")
"""

from __future__ import annotations

import ctypes
import logging
import sys
from typing import Any, Mapping, Optional

if sys.platform != "darwin":
    raise ImportError("macos_dpop is only supported on macOS")

from google.auth import _helpers
from google.auth.dpop import DPoPSigner, der_to_raw_ecdsa_signature

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CoreFoundation and Security.framework ctypes bridge
# ---------------------------------------------------------------------------

_CF = ctypes.CDLL(
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
)
_Sec = ctypes.CDLL(
    "/System/Library/Frameworks/Security.framework/Security"
)

# -- CoreFoundation function signatures --

_CF.CFRelease.argtypes = [ctypes.c_void_p]
_CF.CFRelease.restype = None

_CF.CFDataCreate.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long,
]
_CF.CFDataCreate.restype = ctypes.c_void_p

_CF.CFDataGetLength.argtypes = [ctypes.c_void_p]
_CF.CFDataGetLength.restype = ctypes.c_long

_CF.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
_CF.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_ubyte)

_CF.CFStringCreateWithCString.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32,
]
_CF.CFStringCreateWithCString.restype = ctypes.c_void_p

_CF.CFDictionaryCreateMutable.argtypes = [
    ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p,
]
_CF.CFDictionaryCreateMutable.restype = ctypes.c_void_p

_CF.CFDictionarySetValue.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
]
_CF.CFDictionarySetValue.restype = None

# -- Security function signatures --

_Sec.SecItemCopyMatching.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
]
_Sec.SecItemCopyMatching.restype = ctypes.c_int32

_Sec.SecIdentityCopyPrivateKey.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
]
_Sec.SecIdentityCopyPrivateKey.restype = ctypes.c_int32

_Sec.SecKeyCopyPublicKey.argtypes = [ctypes.c_void_p]
_Sec.SecKeyCopyPublicKey.restype = ctypes.c_void_p

_Sec.SecKeyCopyExternalRepresentation.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
]
_Sec.SecKeyCopyExternalRepresentation.restype = ctypes.c_void_p

_Sec.SecKeyCreateSignature.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
]
_Sec.SecKeyCreateSignature.restype = ctypes.c_void_p

# -- Constants --

_kCFStringEncodingUTF8 = 0x08000100
_errSecSuccess = 0
_errSecItemNotFound = -25300

# CoreFoundation constants
_kCFBooleanTrue = ctypes.c_void_p.in_dll(_CF, "kCFBooleanTrue")

# Dictionary callback struct addresses (passed as pointers)
_kCFTypeDictKeyCallBacks = ctypes.addressof(
    ctypes.c_byte.in_dll(_CF, "kCFTypeDictionaryKeyCallBacks")
)
_kCFTypeDictValCallBacks = ctypes.addressof(
    ctypes.c_byte.in_dll(_CF, "kCFTypeDictionaryValueCallBacks")
)

# Security constants (each is a global CFStringRef)
_kSecClass = ctypes.c_void_p.in_dll(_Sec, "kSecClass")
_kSecClassIdentity = ctypes.c_void_p.in_dll(_Sec, "kSecClassIdentity")
_kSecClassKey = ctypes.c_void_p.in_dll(_Sec, "kSecClassKey")
_kSecAttrLabel = ctypes.c_void_p.in_dll(_Sec, "kSecAttrLabel")
_kSecAttrApplicationTag = ctypes.c_void_p.in_dll(
    _Sec, "kSecAttrApplicationTag"
)
_kSecAttrKeyType = ctypes.c_void_p.in_dll(_Sec, "kSecAttrKeyType")
_kSecAttrKeyTypeECSECPrimeRandom = ctypes.c_void_p.in_dll(
    _Sec, "kSecAttrKeyTypeECSECPrimeRandom"
)
_kSecReturnRef = ctypes.c_void_p.in_dll(_Sec, "kSecReturnRef")
_kSecMatchLimit = ctypes.c_void_p.in_dll(_Sec, "kSecMatchLimit")
_kSecMatchLimitOne = ctypes.c_void_p.in_dll(_Sec, "kSecMatchLimitOne")
_kSecAlgECDSAMsgSHA256 = ctypes.c_void_p.in_dll(
    _Sec, "kSecKeyAlgorithmECDSASignatureMessageX962SHA256"
)


# ---------------------------------------------------------------------------
# CF helper functions
# ---------------------------------------------------------------------------

class _CFScope:
    """Tracks Core Foundation objects and releases them on exit.

    Use as a context manager to ensure all CF objects created within
    the scope are released, even on error.
    """

    def __init__(self):
        self._refs = []

    def track(self, ref):
        """Register a CF reference for release.  Returns the ref."""
        if ref:
            self._refs.append(ref)
        return ref

    def __enter__(self):
        return self

    def __exit__(self, *args):
        for ref in reversed(self._refs):
            try:
                _CF.CFRelease(ref)
            except Exception:
                pass
        self._refs.clear()


def _cf_string(s):
    """Create a CFStringRef from a Python string.  Caller must CFRelease."""
    ref = _CF.CFStringCreateWithCString(
        None, s.encode("utf-8"), _kCFStringEncodingUTF8
    )
    if not ref:
        raise RuntimeError(f"CFStringCreateWithCString failed for: {s}")
    return ref


def _cf_data(b):
    """Create a CFDataRef from Python bytes.  Caller must CFRelease."""
    ref = _CF.CFDataCreate(None, b, len(b))
    if not ref:
        raise RuntimeError("CFDataCreate failed")
    return ref


def _bytes_from_cf_data(cf_data_ref):
    """Extract Python bytes from a CFDataRef."""
    length = _CF.CFDataGetLength(cf_data_ref)
    ptr = _CF.CFDataGetBytePtr(cf_data_ref)
    return bytes(ptr[:length])


def _cf_dict(entries):
    """Create a CFMutableDictionaryRef.  Caller must CFRelease.

    Args:
        entries: Iterable of (key, value) pairs.  Each element must be
            a ctypes c_void_p instance or an integer pointer value.
    """
    d = _CF.CFDictionaryCreateMutable(
        None, 0, _kCFTypeDictKeyCallBacks, _kCFTypeDictValCallBacks,
    )
    if not d:
        raise RuntimeError("CFDictionaryCreateMutable failed")
    for k, v in entries:
        _CF.CFDictionarySetValue(d, k, v)
    return d


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SecureEnclaveDPoPError(Exception):
    """Error raised by Secure Enclave DPoP operations."""
    pass


class SecureEnclaveDPoPSigner(DPoPSigner):
    """DPoP signer backed by macOS Secure Enclave or Keychain.

    Uses ctypes to Security.framework.  No pip dependencies beyond
    google-auth itself.

    Only ES256 (P-256 + SHA-256) is supported because the Secure
    Enclave only supports P-256 elliptic curve keys.

    Args:
        label (str): Keychain identity label to search for.  Use
            ``sc_auth list-ctk-identities`` to find the label for a Secure
            Enclave identity.
        application_tag (Union[str, bytes]): Application tag for
            standalone key lookup (alternative to *label*).
        key_id (Optional[str]): Custom identifier for this key.
    """

    def __init__(
        self,
        label=None,
        application_tag=None,
        key_id=None,
    ):
        if not label and not application_tag:
            raise ValueError(
                "Either 'label' or 'application_tag' must be provided."
            )

        self._custom_key_id = key_id
        self._label = label
        self._private_key_ref = None  # SecKeyRef, released in __del__

        if label:
            self._private_key_ref = self._find_identity_key(label)
        else:
            self._private_key_ref = self._find_key_by_tag(application_tag)

        self._public_jwk = self._extract_public_jwk()

        logger.info(
            "Secure Enclave DPoP signer initialized: thumbprint=%s...",
            self.thumbprint[:16],
        )

    # -- Key discovery --

    @staticmethod
    def _find_identity_key(label):
        """Find a Keychain identity by label and return its private key."""
        with _CFScope() as scope:
            cf_label = scope.track(_cf_string(label))
            query = scope.track(_cf_dict([
                (_kSecClass, _kSecClassIdentity),
                (_kSecAttrLabel, cf_label),
                (_kSecReturnRef, _kCFBooleanTrue),
                (_kSecMatchLimit, _kSecMatchLimitOne),
            ]))

            result = ctypes.c_void_p()
            status = _Sec.SecItemCopyMatching(query, ctypes.byref(result))

            if status == _errSecItemNotFound:
                raise SecureEnclaveDPoPError(
                    f"No identity found with label '{label}'. "
                    "Run 'sc_auth list-ctk-identities' to list available identities."
                )
            if status != _errSecSuccess:
                raise SecureEnclaveDPoPError(
                    f"SecItemCopyMatching failed (OSStatus {status})."
                )

            identity = scope.track(result.value)

            key_ref = ctypes.c_void_p()
            status = _Sec.SecIdentityCopyPrivateKey(
                identity, ctypes.byref(key_ref)
            )
            if status != _errSecSuccess:
                raise SecureEnclaveDPoPError(
                    f"SecIdentityCopyPrivateKey failed (OSStatus {status})."
                )

            # Return retained key ref -- caller (instance) owns it.
            return key_ref.value

    @staticmethod
    def _find_key_by_tag(tag):
        """Find a private key by application tag."""
        if isinstance(tag, str):
            tag = tag.encode("utf-8")

        with _CFScope() as scope:
            cf_tag = scope.track(_cf_data(tag))
            query = scope.track(_cf_dict([
                (_kSecClass, _kSecClassKey),
                (_kSecAttrKeyType, _kSecAttrKeyTypeECSECPrimeRandom),
                (_kSecAttrApplicationTag, cf_tag),
                (_kSecReturnRef, _kCFBooleanTrue),
                (_kSecMatchLimit, _kSecMatchLimitOne),
            ]))

            result = ctypes.c_void_p()
            status = _Sec.SecItemCopyMatching(query, ctypes.byref(result))

            if status == _errSecItemNotFound:
                raise SecureEnclaveDPoPError(
                    f"No key found with application tag '{tag!r}'. "
                    "Ensure the key exists in the Keychain."
                )
            if status != _errSecSuccess:
                raise SecureEnclaveDPoPError(
                    f"SecItemCopyMatching failed (OSStatus {status})."
                )

            return result.value

    def _extract_public_jwk(self):
        """Extract the public key and build an RFC 7517 JWK dict."""
        pub_key = _Sec.SecKeyCopyPublicKey(self._private_key_ref)
        if not pub_key:
            raise SecureEnclaveDPoPError("SecKeyCopyPublicKey returned NULL.")
        try:
            error = ctypes.c_void_p()
            pub_data = _Sec.SecKeyCopyExternalRepresentation(
                pub_key, ctypes.byref(error)
            )
            if not pub_data:
                raise SecureEnclaveDPoPError(
                    "SecKeyCopyExternalRepresentation failed."
                )
            try:
                raw = _bytes_from_cf_data(pub_data)
            finally:
                _CF.CFRelease(pub_data)
        finally:
            _CF.CFRelease(pub_key)

        # ANSI X9.63 uncompressed point: 0x04 || X (32) || Y (32)
        if len(raw) != 65 or raw[0] != 0x04:
            raise SecureEnclaveDPoPError(
                f"Unexpected public key format ({len(raw)} bytes, "
                f"first byte 0x{raw[0]:02x}).  Expected 65-byte "
                "uncompressed EC point."
            )

        x_bytes = raw[1:33]
        y_bytes = raw[33:65]
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _helpers.unpadded_urlsafe_b64encode(x_bytes).decode("ascii"),
            "y": _helpers.unpadded_urlsafe_b64encode(y_bytes).decode("ascii"),
        }

    # -- DPoPSigner interface --

    @property
    def algorithm(self):
        """str: Always ``'ES256'`` (Secure Enclave P-256 only)."""
        return "ES256"

    @property
    def public_jwk(self):
        """Mapping[str, Any]: RFC 7517 public JWK dict."""
        return self._public_jwk

    @property
    def key_id(self):
        """Optional[str]: Key identifier."""
        if self._custom_key_id:
            return self._custom_key_id
        return f"se:{self._label or 'tag'}"

    def sign(self, data):
        """Signs data using the Secure Enclave private key.

        Security.framework hashes the data internally using
        ``kSecKeyAlgorithmECDSASignatureMessageX962SHA256``.
        The DER-encoded X9.62 signature is converted to raw R||S
        for JWS/ES256.

        Args:
            data (bytes): The ASCII signing input.

        Returns:
            bytes: 64-byte raw R||S signature.

        Raises:
            SecureEnclaveDPoPError: If signing fails.
        """
        cf_data = _cf_data(data)
        try:
            error = ctypes.c_void_p()
            sig_ref = _Sec.SecKeyCreateSignature(
                self._private_key_ref,
                _kSecAlgECDSAMsgSHA256,
                cf_data,
                ctypes.byref(error),
            )
            if not sig_ref:
                raise SecureEnclaveDPoPError(
                    "SecKeyCreateSignature failed.  Possible causes: "
                    "biometric authentication required but the Python "
                    "interpreter is not code-signed, or the key access "
                    "control policy denied the operation."
                )
            try:
                der_sig = _bytes_from_cf_data(sig_ref)
                return der_to_raw_ecdsa_signature(der_sig, 32)
            finally:
                _CF.CFRelease(sig_ref)
        finally:
            _CF.CFRelease(cf_data)

    def __del__(self):
        if self._private_key_ref:
            try:
                _CF.CFRelease(self._private_key_ref)
            except Exception:
                pass
