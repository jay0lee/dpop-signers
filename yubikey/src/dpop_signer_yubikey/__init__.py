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

"""YubiKey Hardware-backed DPoP Signer (RFC 9449).

This module implements :class:`google.auth.dpop.DPoPSigner` using the
YubiKey Personal Identity Verification (PIV) application via ``yubikey-manager``.

Private key material is generated or stored entirely inside the YubiKey's secure
element and never leaves the hardware. Signing operations take place on-chip,
providing sender-constrained protection resistant to extraction or malware theft.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Callable, Mapping, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from google.auth.dpop import DPoPSigner, der_to_raw_ecdsa_signature

try:
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.piv import (
        KEY_TYPE,
        SLOT,
        ApduError,
        InvalidPinError,
        NotSupportedError,
        PivSession,
        SW,
    )
    _YKMAN_AVAILABLE = True
except ImportError as _import_err:  # pragma: no cover
    _YKMAN_AVAILABLE = False
    _IMPORT_ERROR = _import_err

logger = logging.getLogger(__name__)


def _b64url_encode(data):
    """Encodes bytes as unpadded URL-safe base64 ASCII text."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class YubiKeyDPoPError(Exception):
    """Base error for YubiKey DPoP operations."""
    pass


class YubiKeyNotFoundError(YubiKeyDPoPError):
    """Raised when no compatible YubiKey is detected."""
    pass


class YubiKeySlotEmptyError(YubiKeyDPoPError):
    """Raised when the specified PIV slot does not contain a usable key."""
    pass


class YubiKeyPINRequiredError(YubiKeyDPoPError):
    """Raised when a PIN is required for the requested operation."""
    pass


def parse_slot(slot: Union[str, int, SLOT]) -> SLOT:
    """Parses various slot representations into a :class:`yubikit.piv.SLOT`.

    Supports:
        - Enum instances: ``SLOT.SIGNATURE``, ``SLOT.AUTHENTICATION``
        - Hex strings: ``"9c"``, ``"9C"``, ``"0x9c"``, ``"9a"``, ``"9d"``, ``"9e"``
        - Integers: ``0x9c``, ``156``
        - Names: ``"SIGNATURE"``, ``"AUTHENTICATION"``, ``"KEY_MANAGEMENT"``, ``"CARD_AUTH"``

    Args:
        slot (Union[str, int, SLOT]): Slot specification.

    Returns:
        SLOT: The matching PIV slot enum.

    Raises:
        ValueError: If the slot string or integer cannot be resolved.
    """
    if isinstance(slot, SLOT):
        return slot

    if isinstance(slot, int):
        return SLOT(slot)

    if isinstance(slot, str):
        clean = slot.strip().upper()
        # Check by enum attribute name (e.g., 'SIGNATURE', 'AUTHENTICATION')
        if hasattr(SLOT, clean):
            return getattr(SLOT, clean)

        # Remove optional '0X' prefix
        if clean.startswith("0X"):
            clean = clean[2:]

        try:
            int_val = int(clean, 16)
            return SLOT(int_val)
        except (ValueError, KeyError):
            pass

    raise ValueError(
        f"Invalid PIV slot '{slot}'. Valid examples: '9c' (signature), '9a' (authentication), '9d', '9e'."
    )


def public_key_to_jwk(public_key: Any) -> Tuple[str, Mapping[str, Any], int]:
    """Converts a cryptography public key to JWS algorithm, RFC 7517 JWK, and curve byte size.

    Args:
        public_key: An :class:`ec.EllipticCurvePublicKey` or :class:`rsa.RSAPublicKey`.

    Returns:
        Tuple[str, Mapping[str, Any], int]: (algorithm_name, public_jwk_dict, coordinate_byte_size)
    """
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve
        if isinstance(curve, ec.SECP256R1):
            alg = "ES256"
            crv_size = 32
            crv_name = "P-256"
        elif isinstance(curve, ec.SECP384R1):
            alg = "ES384"
            crv_size = 48
            crv_name = "P-384"
        else:
            raise ValueError(f"Unsupported elliptic curve for DPoP: {curve.name}")

        pub_numbers = public_key.public_numbers()
        x_bytes = pub_numbers.x.to_bytes(crv_size, byteorder="big")
        y_bytes = pub_numbers.y.to_bytes(crv_size, byteorder="big")

        jwk = {
            "kty": "EC",
            "crv": crv_name,
            "x": _b64url_encode(x_bytes),
            "y": _b64url_encode(y_bytes),
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
            "n": _b64url_encode(n_bytes),
            "e": _b64url_encode(e_bytes),
        }
        return alg, jwk, 0

    raise ValueError(f"Unsupported public key type: {type(public_key)}")


class YubiKeyDPoPSigner(DPoPSigner):
    """Hardware-backed DPoP Signer using YubiKey PIV (RFC 9449).

    Args:
        slot (Union[str, int, SLOT]): The PIV slot holding the private key.
            Defaults to ``SLOT.SIGNATURE`` (slot 0x9c).
        serial (Optional[int]): Optional serial number of the YubiKey to target
            if multiple YubiKeys are attached.
        pin (Optional[Union[str, Callable[[], str]]]): PIV PIN string or
            zero-argument callable returning the PIN (invoked lazily and
            cached). Omit to raise :class:`YubiKeyPINRequiredError` if the
            slot requires PIN verification.
        key_id (Optional[str]): Optional custom key ID. Defaults to
            ``f"yubikey:{serial}:{slot.name.lower()}"``.
        device (Optional[YkmanDevice]): Optional pre-resolved device instance
            (useful for tests or dependency injection).
    """

    def __init__(
        self,
        slot: Union[str, int, SLOT] = SLOT.SIGNATURE,
        serial: Optional[int] = None,
        pin: Optional[Union[str, Callable[[], str]]] = None,
        key_id: Optional[str] = None,
        device: Optional[Any] = None,
    ):
        if not _YKMAN_AVAILABLE:
            raise YubiKeyDPoPError(
                f"yubikey-manager library is not installed: {_IMPORT_ERROR}. "
                "Install with 'pip install yubikey-manager'."
            )

        self._slot = parse_slot(slot)
        self._target_serial = serial
        self._pin_or_factory = pin
        self._resolved_pin = None
        self._pin_resolved = False
        self._custom_key_id = key_id

        # Resolve device
        self._device, self._serial = self._resolve_device(device, serial)

        # Inspect slot and cache public key / algorithm
        self._init_slot_metadata()

    def _resolve_device(
        self, device: Optional[Any], target_serial: Optional[int]
    ) -> Tuple[Any, Optional[int]]:
        """Finds and verifies the target YubiKey device."""
        if device is not None:
            return device, target_serial

        devices = list_all_devices(connection_types=[SmartCardConnection])
        if not devices:
            raise YubiKeyNotFoundError(
                "No YubiKey detected with SmartCard/CCID interface enabled. "
                "Please insert your YubiKey."
            )

        if target_serial is not None:
            for dev, info in devices:
                if info.serial == target_serial:
                    return dev, info.serial
            raise YubiKeyNotFoundError(
                f"YubiKey with serial {target_serial} not found. "
                f"Available serials: {[info.serial for _, info in devices]}"
            )

        if len(devices) > 1:
            serials = [info.serial for _, info in devices]
            logger.warning(
                f"Multiple YubiKeys found ({serials}). Using first device ({serials[0]}). "
                "Specify 'serial' to select a specific YubiKey."
            )

        selected_dev, selected_info = devices[0]
        return selected_dev, selected_info.serial

    def _init_slot_metadata(self) -> None:
        """Inspects the slot via PIV and extracts public key, key type, and JWK."""
        with self._device.open_connection(SmartCardConnection) as conn:
            session = PivSession(conn)
            pub_key = None
            key_type = None

            # 1. Try reading slot metadata (supported on YK 5.3.0+)
            try:
                meta = session.get_slot_metadata(self._slot)
                pub_key = meta.public_key
                key_type = meta.key_type
            except (NotSupportedError, ApduError, Exception):
                pass

            # 2. If metadata not present or older firmware, read certificate from slot
            if pub_key is None:
                try:
                    cert = session.get_certificate(self._slot)
                    pub_key = cert.public_key()
                    key_type = KEY_TYPE.from_public_key(pub_key)
                except Exception as exc:
                    raise YubiKeySlotEmptyError(
                        f"No usable key or certificate found in PIV slot {self._slot.name} "
                        f"(0x{self._slot.value:02X}) on YubiKey {self._serial}. "
                        "Provision the slot first (e.g. via 'ykman piv keys generate' "
                        "and 'ykman piv certificates generate')."
                    ) from exc

            self._key_type = key_type
            self._public_key = pub_key
            alg, jwk, crv_size = public_key_to_jwk(pub_key)
            self._algorithm = alg
            self._public_jwk = jwk
            self._crv_size = crv_size

    @property
    def algorithm(self) -> str:
        """The JWS signing algorithm name ('ES256', 'ES384', or 'RS256')."""
        return self._algorithm

    @property
    def public_jwk(self) -> Mapping[str, Any]:
        """The RFC 7517 public JSON Web Key (JWK) dictionary."""
        return self._public_jwk

    @property
    def key_id(self) -> Optional[str]:
        """Identifier for this YubiKey slot."""
        if self._custom_key_id:
            return self._custom_key_id
        ser = self._serial if self._serial is not None else "unknown"
        return f"yubikey:{ser}:{self._slot.name.lower()}"

    @property
    def slot(self) -> SLOT:
        """The PIV slot in use."""
        return self._slot

    @property
    def serial(self) -> Optional[int]:
        """The serial number of the YubiKey."""
        return self._serial

    def _get_pin(self) -> Optional[str]:
        """Resolves and caches the PIN from a literal value or callable."""
        if not self._pin_resolved:
            if callable(self._pin_or_factory):
                val = self._pin_or_factory()
                self._resolved_pin = val.strip() if isinstance(val, str) else val
            elif self._pin_or_factory is not None:
                self._resolved_pin = (
                    self._pin_or_factory.strip()
                    if isinstance(self._pin_or_factory, str)
                    else self._pin_or_factory
                )
            self._pin_resolved = True
        return self._resolved_pin or None

    def sign(self, data: bytes) -> bytes:
        """Signs the input bytes using the on-chip private key in the PIV slot.

        For ECDSA algorithms (ES256, ES384), converts the ASN.1 DER signature
        returned by the smart card chip to raw (R || S) format per RFC 7515 §3.4.

        Args:
            data (bytes): The ASCII data to sign (e.g. b'<header_b64>.<payload_b64>').

        Returns:
            bytes: The raw signature bytes.
        """
        with self._device.open_connection(SmartCardConnection) as conn:
            session = PivSession(conn)

            # Handle PIN verification if required or available
            pin = self._get_pin()
            if pin:
                try:
                    session.verify_pin(pin)
                except InvalidPinError as exc:
                    self._resolved_pin = None
                    self._pin_resolved = False
                    attempts = getattr(exc, "attempts_remaining", None)
                    msg = (
                        f"Invalid YubiKey PIV PIN. Attempts remaining: {attempts}"
                        if attempts is not None
                        else "Invalid YubiKey PIV PIN."
                    )
                    raise YubiKeyPINRequiredError(msg) from exc

            # Determine hash and padding
            if self._algorithm == "ES256":
                hash_alg = hashes.SHA256()
                asym_pad = None
            elif self._algorithm == "ES384":
                hash_alg = hashes.SHA384()
                asym_pad = None
            elif self._algorithm == "RS256":
                hash_alg = hashes.SHA256()
                asym_pad = padding.PKCS1v15()
            else:
                raise ValueError(f"Unsupported algorithm: {self._algorithm}")

            try:
                raw_or_der_sig = session.sign(
                    self._slot,
                    self._key_type,
                    data,
                    hash_algorithm=hash_alg,
                    padding=asym_pad,
                )
            except ApduError as exc:
                if exc.sw == SW.SECURITY_CONDITION_NOT_SATISFIED:
                    self._resolved_pin = None
                    self._pin_resolved = False
                    raise YubiKeyPINRequiredError(
                        f"PIV slot {self._slot.name} requires PIN verification. "
                        "Provide a PIN via 'pin' (string or callable)."
                    ) from exc
                raise

            # For ECDSA, convert PIV ASN.1 DER to raw (R || S) bytes
            if self._algorithm.startswith("ES"):
                return der_to_raw_ecdsa_signature(raw_or_der_sig, self._crv_size)

            return raw_or_der_sig
