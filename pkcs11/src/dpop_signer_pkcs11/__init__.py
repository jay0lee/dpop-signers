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

"""PKCS#11 DPoP Signer (RFC 9449) with RFC 7512 URI support.

This module implements :class:`google.auth.dpop.DPoPSigner` using
``python-pkcs11`` so keys stored in any PKCS#11 token (``tpm2-pkcs11``,
OpenSC smart cards, ``libykcs11``, HSMs, SoftHSM2, or ``native-pkcs11``)
can sign DPoP proofs across Linux, macOS, and Windows.

Usage with an RFC 7512 ``pkcs11:`` URI::

    from dpop_signer_pkcs11 import PKCS11DPoPSigner

    signer = PKCS11DPoPSigner(
        "pkcs11:token=tpm2;object=dpop;id=%01"
        "?module-path=/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so"
        "&pin-value=1234"
    )
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import sys
import threading
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from google.auth.dpop import DPoPSigner

try:
    import pkcs11 as _p11

    _PKCS11_AVAILABLE = True
except ImportError as _import_err:  # pragma: no cover
    _p11 = None
    _PKCS11_AVAILABLE = False
    _IMPORT_ERROR = _import_err

logger = logging.getLogger(__name__)

# DER-encoded OIDs for supported EC named curves in CKA_EC_PARAMS.
_EC_PARAMS_TO_CURVE = {
    b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07": ("ES256", "P-256", 32, "sha256"),
    b"\x06\x05\x2b\x81\x04\x00\x22": ("ES384", "P-384", 48, "sha384"),
}

_ALLOWED_URI_TYPES = frozenset({"private", "public", "cert"})

_P11_KIT_MODULE_DIRS = (
    "/etc/pkcs11/modules",
    "/usr/share/p11-kit/modules",
    "/usr/local/share/p11-kit/modules",
    "/opt/homebrew/share/p11-kit/modules",
)

_DEFAULT_MODULE_SEARCH_DIRS = (
    "/usr/lib/x86_64-linux-gnu/pkcs11",
    "/usr/lib/aarch64-linux-gnu/pkcs11",
    "/usr/lib64/pkcs11",
    "/usr/lib/pkcs11",
    "/usr/lib/softhsm",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib",
    "/opt/homebrew/lib/pkcs11",
    "/opt/homebrew/lib/softhsm",
    "/opt/homebrew/lib",
    "/usr/local/lib/pkcs11",
    "/usr/local/lib/softhsm",
    "/usr/local/lib",
)


class PKCS11DPoPError(Exception):
    """Base error for PKCS#11 DPoP operations."""


class PKCS11ConfigError(PKCS11DPoPError):
    """Raised when the PKCS#11 URI, module, token, or key config is invalid."""


class PKCS11PINRequiredError(PKCS11DPoPError):
    """Raised when a PKCS#11 token requires a PIN or the PIN is invalid."""


_PKCS11_PIN_ERROR_NAMES = frozenset({
    "PinExpired",
    "PinIncorrect",
    "PinInvalid",
    "PinLenRange",
    "PinLocked",
    "UserNotLoggedIn",
    "UserPinNotInitialized",
})


def _is_pkcs11_pin_error(exc):
    """Returns True if *exc* represents a PKCS#11 PIN or login failure."""
    return type(exc).__name__ in _PKCS11_PIN_ERROR_NAMES


def _b64url_encode(data):
    """Encodes bytes as unpadded URL-safe base64 ASCII text."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _parse_kv_pairs(segment, sep, is_query=False):
    """Splits a delimited URI segment into raw (key, value) pairs."""
    if not segment:
        return []
    pairs = []
    for item in segment.split(sep):
        if not item:
            continue
        if "=" not in item:
            raise ValueError(
                f"Malformed attribute '{item}' in PKCS#11 URI (expected 'key=value')."
            )
        key, raw_value = item.split("=", 1)
        key = key.strip().lower()
        if not key:
            raise ValueError("Empty attribute name in PKCS#11 URI.")
        pairs.append((key, raw_value))
    return pairs


def _read_pin_source(pin_source):
    """Reads a PIN from an RFC 7512 pin-source value (``file:/...`` or path)."""
    if pin_source.startswith("file://"):
        parsed = urllib.parse.urlparse(pin_source)
        path = urllib.parse.unquote(parsed.path)
    elif pin_source.startswith("file:"):
        path = urllib.parse.unquote(pin_source[5:])
    else:
        path = urllib.parse.unquote(pin_source)

    path = os.path.expanduser(path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().rstrip("\r\n")
    except OSError as exc:
        raise PKCS11ConfigError(
            f"Failed to read PKCS#11 PIN from pin-source '{pin_source}': {exc}"
        ) from exc


def parse_pkcs11_uri(uri):
    """Parses an RFC 7512 ``pkcs11:`` URI into attribute fields.

    Supports standard path attributes (``token``, ``object``, ``id``,
    ``slot-id``, ``serial``, ``manufacturer``, ``model``, ``type``) and
    common query attributes (``module-path``, ``module-name``,
    ``pin-value``, ``pin-source``).

    Args:
        uri (str): The ``pkcs11:...`` URI string.

    Returns:
        dict: Parsed attributes ready for :class:`PKCS11DPoPSigner`.

    Raises:
        ValueError: If *uri* is malformed or uses a disallowed ``type``.
    """
    if not isinstance(uri, str) or not uri.lower().startswith("pkcs11:"):
        raise ValueError("PKCS#11 URI must start with 'pkcs11:'.")

    body = uri[7:]
    if "?" in body:
        path_part, query_part = body.split("?", 1)
    else:
        path_part, query_part = body, ""

    parsed = {}
    for key, raw_value in _parse_kv_pairs(path_part, ";"):
        if key == "id":
            parsed["cka_id"] = urllib.parse.unquote_to_bytes(raw_value)
            continue

        value = urllib.parse.unquote(raw_value)
        if key == "token":
            parsed["token_label"] = value
        elif key == "object":
            parsed["key_label"] = value
        elif key == "slot-id":
            try:
                parsed["slot_id"] = int(value, 10)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid PKCS#11 URI slot-id '{value}': expected integer."
                ) from exc
        elif key == "serial":
            parsed["token_serial"] = value
        elif key == "manufacturer":
            parsed["manufacturer"] = value
        elif key == "model":
            parsed["model"] = value
        elif key == "type":
            obj_type = value.lower()
            if obj_type not in _ALLOWED_URI_TYPES:
                raise ValueError(
                    f"Unsupported PKCS#11 URI type '{value}'. "
                    f"Expected one of: {', '.join(sorted(_ALLOWED_URI_TYPES))}."
                )
            parsed["object_type"] = obj_type

    for key, raw_value in _parse_kv_pairs(query_part, "&", is_query=True):
        value = urllib.parse.unquote(raw_value)
        if key == "module-path":
            parsed["module_path"] = value
        elif key == "module-name":
            parsed["module_name"] = value
        elif key == "pin-value":
            parsed["pin"] = value
        elif key == "pin-source":
            parsed["pin_source"] = value

    return parsed


def _normalize_cka_id(value):
    """Normalizes ``cka_id`` from bytes or colon/hex string into bytes."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        cleaned = value.replace(":", "").strip()
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(
                f"Invalid cka_id hex string '{value}'. Pass bytes or hex."
            ) from exc
    raise TypeError("cka_id must be bytes or a hex string.")


def _lookup_p11_kit_module(module_name):
    """Resolves ``module-name`` from p11-kit ``*.module`` config files."""
    filename = (
        module_name
        if module_name.endswith(".module")
        else f"{module_name}.module"
    )
    for directory in _P11_KIT_MODULE_DIRS:
        cfg_path = os.path.join(directory, filename)
        if not os.path.isfile(cfg_path):
            continue
        try:
            with open(cfg_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped.startswith("#") or ":" not in stripped:
                        continue
                    k, v = stripped.split(":", 1)
                    if k.strip() == "module":
                        return v.strip()
        except OSError:
            continue
    return None


def _resolve_module_path(module_path=None, module_name=None):
    """Finds the PKCS#11 shared library path (.so / .dylib / .dll)."""
    if module_path:
        expanded = os.path.abspath(os.path.expanduser(module_path))
        if not os.path.isfile(expanded):
            raise PKCS11ConfigError(f"PKCS#11 module not found at: {expanded}")
        return expanded

    if module_name:
        configured = _lookup_p11_kit_module(module_name)
        if configured:
            if os.path.isabs(configured):
                if os.path.isfile(configured):
                    return configured
            else:
                module_name = configured

        ext = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
        candidates = [module_name]
        if not module_name.endswith((".so", ".dylib", ".dll")):
            candidates.extend(
                [
                    f"{module_name}{ext}",
                    f"{module_name}.so",
                    f"lib{module_name}{ext}",
                    f"lib{module_name}.so",
                ]
            )
        for directory in _DEFAULT_MODULE_SEARCH_DIRS:
            for candidate in candidates:
                full = os.path.join(directory, candidate)
                if os.path.isfile(full):
                    return full
        raise PKCS11ConfigError(
            f"Could not locate PKCS#11 module '{module_name}'. "
            "Specify module_path explicitly or via '?module-path=...'."
        )

    env_path = os.environ.get("PKCS11_MODULE")
    if env_path:
        expanded = os.path.abspath(os.path.expanduser(env_path))
        if not os.path.isfile(expanded):
            raise PKCS11ConfigError(
                f"PKCS11_MODULE points to missing file: {expanded}"
            )
        return expanded

    raise PKCS11ConfigError(
        "No PKCS#11 module specified. Pass module_path=..., "
        "'pkcs11:...?module-path=...', or set PKCS11_MODULE."
    )


def _norm_attr(value):
    """Normalizes Cryptoki fixed-width string attributes."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    return str(value).strip()


def _find_matching_token(
    lib,
    *,
    slot_id=None,
    token_label=None,
    token_serial=None,
    manufacturer=None,
    model=None,
):
    """Finds the single PKCS#11 token matching the specified attributes."""
    matches = []
    for slot in lib.get_slots(token_present=True):
        if slot_id is not None and slot.slot_id != slot_id:
            continue
        token = slot.get_token()
        if token_label is not None and _norm_attr(token.label) != token_label:
            continue
        if token_serial is not None and _norm_attr(token.serial) != token_serial:
            continue
        if (
            manufacturer is not None
            and _norm_attr(token.manufacturer_id) != manufacturer
        ):
            continue
        if model is not None and _norm_attr(token.model) != model:
            continue
        matches.append((slot.slot_id, token))

    if not matches:
        raise PKCS11ConfigError(
            "No matching PKCS#11 token found. Verify the token is present and "
            "matches token/serial/slot-id attributes."
        )
    if len(matches) > 1:
        labels = ", ".join(
            f"slot={sid} label={_norm_attr(tok.label)!r}" for sid, tok in matches
        )
        raise PKCS11ConfigError(
            f"Multiple PKCS#11 tokens matched ({labels}). "
            "Specify token=, serial=, or slot-id= to disambiguate."
        )
    return matches[0][1]


def _unwrap_der_octet_string(data):
    """Extracts the payload from a DER OCTET STRING if wrapped, else returns raw."""
    if not data or len(data) < 2 or data[0] != 0x04:
        return data
    # Check whether data is already raw uncompressed EC point 04 || X || Y
    if len(data) in (65, 97) and data[1] != len(data) - 2:
        return data
    length_byte = data[1]
    if length_byte < 0x80:
        header_len = 2
        payload_len = length_byte
    else:
        num_len_bytes = length_byte & 0x7F
        header_len = 2 + num_len_bytes
        if header_len > len(data):
            return data
        payload_len = int.from_bytes(data[2:header_len], "big")
    if header_len + payload_len == len(data):
        return data[header_len:]
    return data


def _jwk_from_cryptography_public_key(public_key):
    """Builds ``(algorithm, jwk_dict, crv_size, hash_name)`` from an X.509 public key."""
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve
        if isinstance(curve, ec.SECP256R1):
            alg, crv_name, crv_size, hash_name = "ES256", "P-256", 32, "sha256"
        elif isinstance(curve, ec.SECP384R1):
            alg, crv_name, crv_size, hash_name = "ES384", "P-384", 48, "sha384"
        else:
            raise PKCS11DPoPError(
                f"Unsupported EC curve '{curve.name}' for DPoP. "
                "Supported curves: P-256 (ES256), P-384 (ES384)."
            )
        nums = public_key.public_numbers()
        x_bytes = nums.x.to_bytes(crv_size, "big")
        y_bytes = nums.y.to_bytes(crv_size, "big")
        jwk = {
            "kty": "EC",
            "crv": crv_name,
            "x": _b64url_encode(x_bytes),
            "y": _b64url_encode(y_bytes),
        }
        return alg, jwk, crv_size, hash_name

    if isinstance(public_key, rsa.RSAPublicKey):
        nums = public_key.public_numbers()
        n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
        e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
        jwk = {
            "kty": "RSA",
            "n": _b64url_encode(n_bytes),
            "e": _b64url_encode(e_bytes),
        }
        return "RS256", jwk, 0, "sha256"

    raise PKCS11DPoPError(
        f"Unsupported public key type '{type(public_key).__name__}' for DPoP."
    )


def _strip_leading_zeros(raw):
    """Strips redundant leading 0x00 bytes from unsigned big-endian integers."""
    stripped = bytes(raw).lstrip(b"\x00")
    return stripped or b"\x00"


def _jwk_from_pkcs11_public_key(pub_obj):
    """Builds ``(algorithm, jwk_dict, crv_size, hash_name)`` from CKO_PUBLIC_KEY."""
    key_type = pub_obj[_p11.Attribute.KEY_TYPE]
    if key_type == _p11.KeyType.EC:
        ec_params = bytes(pub_obj[_p11.Attribute.EC_PARAMS])
        curve_info = _EC_PARAMS_TO_CURVE.get(ec_params)
        if not curve_info:
            raise PKCS11DPoPError(
                "Unsupported EC curve in PKCS#11 public key. "
                "Supported curves: P-256 (ES256), P-384 (ES384)."
            )
        alg, crv_name, crv_size, hash_name = curve_info
        raw_point = _unwrap_der_octet_string(bytes(pub_obj[_p11.Attribute.EC_POINT]))
        expected_len = 1 + 2 * crv_size
        if len(raw_point) != expected_len or raw_point[0] != 0x04:
            raise PKCS11DPoPError(
                f"Unexpected CKA_EC_POINT format ({len(raw_point)} bytes; expected "
                f"{expected_len}-byte uncompressed EC point)."
            )
        x_start = 1
        y_start = 1 + crv_size
        x_bytes = raw_point[x_start:y_start]
        y_bytes = raw_point[y_start:expected_len]
        jwk = {
            "kty": "EC",
            "crv": crv_name,
            "x": _b64url_encode(x_bytes),
            "y": _b64url_encode(y_bytes),
        }
        return alg, jwk, crv_size, hash_name

    if key_type == _p11.KeyType.RSA:
        n_bytes = _strip_leading_zeros(pub_obj[_p11.Attribute.MODULUS])
        e_bytes = _strip_leading_zeros(pub_obj[_p11.Attribute.PUBLIC_EXPONENT])
        jwk = {
            "kty": "RSA",
            "n": _b64url_encode(n_bytes),
            "e": _b64url_encode(e_bytes),
        }
        return "RS256", jwk, 0, "sha256"

    raise PKCS11DPoPError(
        f"Unsupported PKCS#11 key type '{key_type}' for DPoP."
    )


class PKCS11DPoPSigner(DPoPSigner):
    """DPoP signer backed by any PKCS#11 (Cryptoki) module.

    Supports RFC 7512 ``pkcs11:`` URIs as well as explicit keyword arguments
    across Linux, macOS, and Windows PKCS#11 libraries.

    Args:
        uri (Optional[str]): An RFC 7512 ``pkcs11:...`` URI specifying the
            token, key object, module, and/or PIN source.
        module_path (Optional[str]): Path to the PKCS#11 shared library
            (``.so``, ``.dylib``, or ``.dll``). Overrides URI ``module-path``
            and ``PKCS11_MODULE``.
        token_label (Optional[str]): PKCS#11 token label (URI ``token=``).
        key_label (Optional[str]): Key / certificate object label (URI ``object=``).
        cka_id (Optional[Union[bytes, str]]): Object ``CKA_ID`` bytes or hex
            string (URI ``id=``).
        pin (Optional[Union[str, Callable[[], str]]]): User PIN string or
            zero-argument callable returning the PIN (invoked at most once).
        slot_id (Optional[int]): Numeric PKCS#11 slot ID (URI ``slot-id=``).
        token_serial (Optional[str]): Token serial number (URI ``serial=``).
        key_id (Optional[str]): Optional DPoP credential metadata ``key_id``
            override.
    """

    def __init__(
        self,
        uri=None,
        *,
        module_path=None,
        token_label=None,
        key_label=None,
        cka_id=None,
        pin=None,
        slot_id=None,
        token_serial=None,
        key_id=None,
    ):
        if not _PKCS11_AVAILABLE:
            raise PKCS11DPoPError(
                f"python-pkcs11 is not installed: {_IMPORT_ERROR}. "
                "Install with: pip install python-pkcs11"
            )

        uri_attrs = parse_pkcs11_uri(uri) if uri is not None else {}

        self._module_path = _resolve_module_path(
            module_path=module_path or uri_attrs.get("module_path"),
            module_name=uri_attrs.get("module_name") if not module_path else None,
        )
        self._token_label = (
            token_label if token_label is not None else uri_attrs.get("token_label")
        )
        self._token_serial = (
            token_serial
            if token_serial is not None
            else uri_attrs.get("token_serial")
        )
        self._manufacturer = uri_attrs.get("manufacturer")
        self._model = uri_attrs.get("model")
        self._slot_id = slot_id if slot_id is not None else uri_attrs.get("slot_id")
        self._key_label = (
            key_label if key_label is not None else uri_attrs.get("key_label")
        )
        self._cka_id = _normalize_cka_id(
            cka_id if cka_id is not None else uri_attrs.get("cka_id")
        )
        self._custom_key_id = key_id

        if pin is not None:
            self._pin_or_factory = pin
            self._pin_source = None
        elif "pin" in uri_attrs:
            self._pin_or_factory = uri_attrs["pin"]
            self._pin_source = None
        else:
            self._pin_or_factory = None
            self._pin_source = uri_attrs.get("pin_source")

        if self._key_label is None and self._cka_id is None:
            raise PKCS11ConfigError(
                "Specify key_label/object or cka_id/id to select a PKCS#11 key."
            )

        self._lock = threading.Lock()
        self._resolved_pin = None
        self._pin_resolved = False
        self._session = None

        self._lib = _p11.lib(self._module_path)
        self._token = _find_matching_token(
            self._lib,
            slot_id=self._slot_id,
            token_label=self._token_label,
            token_serial=self._token_serial,
            manufacturer=self._manufacturer,
            model=self._model,
        )

        # Read public key metadata once at initialization to validate config & key.
        session = self._get_or_open_session()
        self._private_key_exists_check(session)
        (
            self._algorithm,
            self._public_jwk,
            self._crv_size,
            self._hash_name,
        ) = self._load_public_key_info(session)

        logger.info(
            "PKCS#11 DPoP signer initialized: token=%s, algorithm=%s, thumbprint=%s...",
            _norm_attr(self._token.label),
            self._algorithm,
            self.thumbprint[:16],
        )

    def _get_pin(self):
        """Resolves the PIN once (if literal, callable, or pin-source)."""
        if not self._pin_resolved:
            if callable(self._pin_or_factory):
                self._resolved_pin = self._pin_or_factory()
            elif self._pin_or_factory is not None:
                self._resolved_pin = self._pin_or_factory
            elif self._pin_source is not None:
                self._resolved_pin = _read_pin_source(self._pin_source)
            self._pin_resolved = True
        return self._resolved_pin

    def _get_or_open_session(self):
        """Returns the cached PKCS#11 session, opening one if needed."""
        if self._session is None:
            pin = self._get_pin()
            try:
                self._session = (
                    self._token.open(user_pin=pin)
                    if pin is not None
                    else self._token.open()
                )
            except Exception as exc:
                if _is_pkcs11_pin_error(exc):
                    self._resolved_pin = None
                    self._pin_resolved = False
                    raise PKCS11PINRequiredError(
                        f"PKCS#11 PIN required or invalid: {exc}"
                    ) from exc
                raise
        return self._session

    def _object_filter(self, obj_class):
        """Builds a PKCS#11 search template dictionary."""
        template = {_p11.Attribute.CLASS: obj_class}
        if self._key_label is not None:
            template[_p11.Attribute.LABEL] = self._key_label
        if self._cka_id is not None:
            template[_p11.Attribute.ID] = self._cka_id
        return template

    def _find_single_object(self, session, obj_class):
        """Finds zero or one object for ``obj_class`` matching label/id."""
        objs = list(session.get_objects(self._object_filter(obj_class)))
        if len(objs) > 1:
            raise PKCS11ConfigError(
                f"Multiple PKCS#11 {obj_class.name} objects matched. "
                "Specify both object/key_label and id/cka_id to disambiguate."
            )
        return objs[0] if objs else None

    def _private_key_exists_check(self, session):
        """Verifies the target private key object exists in the token."""
        priv = self._find_single_object(session, _p11.ObjectClass.PRIVATE_KEY)
        if priv is None:
            raise PKCS11ConfigError(
                "No matching private key found on PKCS#11 token "
                f"(object={self._key_label!r}, id={self._cka_id!r})."
            )
        return priv

    def _load_public_key_info(self, session):
        """Extracts public key and builds JWK via CKO_PUBLIC_KEY or CKO_CERTIFICATE."""
        pub_obj = self._find_single_object(session, _p11.ObjectClass.PUBLIC_KEY)
        if pub_obj is not None:
            return _jwk_from_pkcs11_public_key(pub_obj)

        cert_obj = self._find_single_object(session, _p11.ObjectClass.CERTIFICATE)
        if cert_obj is not None:
            cert = x509.load_der_x509_certificate(
                bytes(cert_obj[_p11.Attribute.VALUE])
            )
            return _jwk_from_cryptography_public_key(cert.public_key())

        raise PKCS11ConfigError(
            "Found PKCS#11 private key, but no matching PUBLIC_KEY or "
            "CERTIFICATE object was found to extract the public JWK."
        )

    @property
    def algorithm(self):
        """str: ``'ES256'``, ``'ES384'``, or ``'RS256'``."""
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
        token_name = _norm_attr(self._token.label) or "token"
        if self._key_label:
            return f"pkcs11:{token_name}:{self._key_label}"
        return f"pkcs11:{token_name}:{self._cka_id.hex()}"

    def sign(self, data):
        """Signs ``data`` using the PKCS#11 token's private key.

        For ECDSA (``ES256``/``ES384``), signs the SHA-256/SHA-384 digest using
        ``CKM_ECDSA`` (returning raw ``R || S`` bytes per JWS), falling back to
        on-token ``CKM_ECDSA_SHA256``/``CKM_ECDSA_SHA384`` if the token rejects
        raw ``CKM_ECDSA``. For RSA (``RS256``), uses ``CKM_SHA256_RSA_PKCS``.

        Args:
            data (bytes): The ASCII signing input.

        Returns:
            bytes: The raw signature bytes.

        Raises:
            PKCS11DPoPError: If signing fails.
        """
        with self._lock:
            session = self._get_or_open_session()
            priv_key = self._private_key_exists_check(session)
            try:
                if self._algorithm.startswith("ES"):
                    digest = getattr(hashlib, self._hash_name)(data).digest()
                    try:
                        sig = bytes(
                            priv_key.sign(digest, mechanism=_p11.Mechanism.ECDSA)
                        )
                    except _p11.MechanismInvalid:
                        mech = (
                            _p11.Mechanism.ECDSA_SHA256
                            if self._algorithm == "ES256"
                            else _p11.Mechanism.ECDSA_SHA384
                        )
                        sig = bytes(priv_key.sign(data, mechanism=mech))
                    expected_len = 2 * self._crv_size
                    if len(sig) != expected_len:
                        raise PKCS11DPoPError(
                            f"Unexpected ECDSA signature length {len(sig)} "
                            f"(expected {expected_len} raw R||S bytes)."
                        )
                    return sig

                return bytes(
                    priv_key.sign(data, mechanism=_p11.Mechanism.SHA256_RSA_PKCS)
                )
            except PKCS11DPoPError:
                raise
            except Exception as exc:
                if _is_pkcs11_pin_error(exc):
                    self.close()
                    self._resolved_pin = None
                    self._pin_resolved = False
                    raise PKCS11PINRequiredError(
                        f"PKCS#11 PIN required or invalid: {exc}"
                    ) from exc
                raise PKCS11DPoPError(f"PKCS#11 signing failed: {exc}") from exc

    def close(self):
        """Closes any cached PKCS#11 session cleanly."""
        session = getattr(self, "_session", None)
        self._session = None
        if session is not None:
            try:
                session.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        self.close()
