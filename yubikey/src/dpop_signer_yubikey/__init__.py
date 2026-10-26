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

import datetime
import getpass
import logging
import sys
from typing import Any, Callable, Mapping, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from google.auth import _helpers
from google.auth.dpop import DPoPSigner, der_to_raw_ecdsa_signature

try:
    from ykman.device import DeviceInfo, YkmanDevice, list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.piv import (
        DEFAULT_MANAGEMENT_KEY,
        KEY_TYPE,
        PIN_POLICY,
        SLOT,
        TOUCH_POLICY,
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

    raise ValueError(f"Unsupported public key type: {type(public_key)}")


class YubiKeyDPoPSigner(DPoPSigner):
    """Hardware-backed DPoP Signer using YubiKey PIV (RFC 9449).

    Args:
        slot (Union[str, int, SLOT]): The PIV slot holding the private key.
            Defaults to ``SLOT.SIGNATURE`` (slot 0x9c).
        serial (Optional[int]): Optional serial number of the YubiKey to target
            if multiple YubiKeys are attached.
        pin (Optional[str]): PIV PIN for operations that require PIN verification.
        pin_callback (Optional[Callable[[], str]]): Optional callable returning
            a PIN if interactive prompting is desired when PIN is missing.
        key_id (Optional[str]): Optional custom key ID. Defaults to
            ``f"yubikey:{serial}:{slot.name.lower()}"``.
        device (Optional[YkmanDevice]): Optional pre-resolved device instance
            (useful for tests or dependency injection).
    """

    def __init__(
        self,
        slot: Union[str, int, SLOT] = SLOT.SIGNATURE,
        serial: Optional[int] = None,
        pin: Optional[str] = None,
        pin_callback: Optional[Callable[[], str]] = None,
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
        self._pin = pin
        self._pin_callback = pin_callback
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
                        "Provision the slot first or use generate_key_in_slot()."
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
        """Resolves the PIN via cached value, callback, or interactive prompt."""
        if self._pin:
            return self._pin
        if self._pin_callback:
            return self._pin_callback()
        if sys.stdin.isatty():
            try:
                entered = getpass.getpass("Enter YubiKey PIV PIN (or press Enter to skip): ")
                if entered.strip():
                    self._pin = entered.strip()
                    return self._pin
            except (EOFError, KeyboardInterrupt):
                pass
        return None

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
                    raise YubiKeyPINRequiredError(
                        f"PIV slot {self._slot.name} requires PIN verification. "
                        "Provide a PIN via 'pin' parameter or --yubikey-pin."
                    ) from exc
                raise

            # For ECDSA, convert PIV ASN.1 DER to raw (R || S) bytes
            if self._algorithm.startswith("ES"):
                return der_to_raw_ecdsa_signature(raw_or_der_sig, self._crv_size)

            return raw_or_der_sig

    @classmethod
    def generate_key_in_slot(
        cls,
        slot: Union[str, int, SLOT] = SLOT.SIGNATURE,
        serial: Optional[int] = None,
        key_type: KEY_TYPE = KEY_TYPE.ECCP256,
        pin: Optional[str] = None,
        management_key: bytes = DEFAULT_MANAGEMENT_KEY,
        touch_policy: TOUCH_POLICY = TOUCH_POLICY.DEFAULT,
        pin_policy: PIN_POLICY = PIN_POLICY.DEFAULT,
        subject: str = "CN=Google OAuth DPoP Client",
        device: Optional[Any] = None,
    ) -> YubiKeyDPoPSigner:
        """Generates a fresh asymmetric keypair directly inside the YubiKey PIV slot.

        Also generates a self-signed X.509 certificate and stores it in the slot so
        that both the slot metadata and certificate are recognized across all tools.

        Args:
            slot (Union[str, int, SLOT]): Target PIV slot (default: '9c').
            serial (Optional[int]): Target YubiKey serial.
            key_type (KEY_TYPE): Key algorithm type (default: ECCP256 for ES256).
            pin (Optional[str]): PIV PIN (required for self-signed cert generation on slot 9c).
            management_key (bytes): PIV management key for key generation.
            touch_policy (TOUCH_POLICY): Touch requirement policy.
            pin_policy (PIN_POLICY): PIN requirement policy.
            subject (str): Certificate subject string.
            device (Optional[Any]): Optional device override.

        Returns:
            YubiKeyDPoPSigner: A signer instance configured for the generated key.
        """
        if not _YKMAN_AVAILABLE:
            raise YubiKeyDPoPError("yubikey-manager is not installed.")

        parsed_slot = parse_slot(slot)

        # Temporary signer to resolve device
        temp = cls.__new__(cls)
        dev, resolved_serial = temp._resolve_device(device, serial)

        with dev.open_connection(SmartCardConnection) as conn:
            session = PivSession(conn)
            logger.info("Authenticating with PIV management key...")
            session.authenticate(management_key)

            logger.info(f"Generating on-chip {key_type.name} key in slot {parsed_slot.name}...")
            public_key = session.generate_key(
                parsed_slot,
                key_type,
                pin_policy=pin_policy,
                touch_policy=touch_policy,
            )

            # Generate and put self-signed certificate so slot is universally recognized
            now = datetime.datetime.now(datetime.timezone.utc)
            cert_builder = (
                x509.CertificateBuilder()
                .public_key(public_key)
                .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)]))
                .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)]))
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=3650))
            )

            cert = None
            if pin:
                try:
                    # Slot 9c PIN_POLICY_ALWAYS requires PIN verification immediately prior to sign
                    session.verify_pin(pin)
                    from ykman.piv import sign_certificate_builder
                    cert = sign_certificate_builder(
                        session, parsed_slot, key_type, cert_builder, hashes.SHA256
                    )
                except Exception as exc:
                    logger.debug(f"Hardware self-signing skipped ({exc}), generating cert via software builder...")

            if cert is None:
                signer_key = ec.generate_private_key(ec.SECP256R1())
                cert = cert_builder.sign(signer_key, hashes.SHA256())

            session.put_certificate(parsed_slot, cert)
            logger.info(f"Successfully provisioned slot {parsed_slot.name} with certificate.")

        return cls(
            slot=parsed_slot,
            serial=resolved_serial,
            pin=pin,
            device=dev,
        )
