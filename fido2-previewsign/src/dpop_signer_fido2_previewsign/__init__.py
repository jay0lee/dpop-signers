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

"""FIDO2 CTAP 2.3 previewSign DPoP Signer (RFC 9449).

This module implements :class:`google.auth.dpop.DPoPSigner` using the
experimental CTAP 2.3 ``previewSign`` extension supported by security
keys with firmware implementing the WebAuthn sign extension (e.g.
YubiKey 5 Series with firmware 5.8+, Yubico Security Key).

Unlike the PIV-based :mod:`dpop_signer_yubikey`, this signer uses the
FIDO2/CTAP2 protocol directly.  The private key is generated inside the
authenticator and **never leaves the hardware**.  Signing is performed
on-chip via an assertion request carrying the raw to-be-signed data in
the ``previewSign`` extension payload.

**IMPORTANT**: The ``previewSign`` extension is an experimental preview
specification.  It is not standardized and is subject to change.
Only ES256 (ECDSA P-256) is supported.

Lifecycle
---------
1. **Key generation** -- Call :func:`generate_signing_credential`
   to create a new FIDO2 credential with the ``previewSign`` extension
   on the security key (one touch required for key creation).  By
   default keys are created with ``Unattended = 0`` flags (no touch
   needed per signature) and as non-resident credentials; pass
   ``require_up=True``, ``require_uv=True``, or ``resident_key=True``
   to override.
2. **Signing** -- Call :meth:`sign` or :meth:`create_proof` to produce
   DPoP proof JWTs.  With the default ``require_up=False``, signing runs
   silently via CTAP2 ``options={'up': False}``.
3. **Persistence** -- Save the dictionary returned by :meth:`to_dict`
   and restore later via :meth:`Fido2PreviewSignDPoPSigner.from_dict`.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import logging
import os
import sys
from typing import Any, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from google.auth.dpop import DPoPSigner, der_to_raw_ecdsa_signature

try:
    from fido2.client import (
        DefaultClientDataCollector,
        Fido2Client,
        UserInteraction,
    )
    from fido2.ctap2.extensions import (
        PreviewSignExtension,
        _SignGenerateKeyInputs,
        _SignInputs,
        _SignSignInputs,
    )
    from fido2.hid import CtapHidDevice
    from fido2.utils import websafe_encode
    from fido2.webauthn import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters,
        PublicKeyCredentialRequestOptions,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialType,
        PublicKeyCredentialUserEntity,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    _FIDO2_AVAILABLE = True
except ImportError as _import_err:
    _FIDO2_AVAILABLE = False
    _IMPORT_ERROR = _import_err

logger = logging.getLogger(__name__)

# COSE algorithm identifier for ES256 (ECDSA w/ SHA-256 on P-256)
_COSE_ES256 = -7
# COSE algorithm identifier for ESP256 (ECDSA w/ SHA-256 on P-256, fully specified)
_COSE_ESP256 = -9
# Draft ARKG P-256 / ESP256-split identifier used by YubiKey 5.8 previewSign
_COSE_ESP256_SPLIT_ARKG = -65539

# Default relying party for DPoP signing credentials.
# This RP ID is used only to scope the FIDO2 credential on the
# authenticator -- it is not validated by any server.
_DEFAULT_RP_ID = "dpop.local"
_DEFAULT_RP_NAME = "DPoP Signing"


class Fido2PreviewSignError(Exception):
    """Base error for FIDO2 previewSign DPoP operations."""

    pass


class Fido2DeviceNotFoundError(Fido2PreviewSignError):
    """Raised when no compatible FIDO2 device is detected."""

    pass


class Fido2ExtensionNotSupportedError(Fido2PreviewSignError):
    """Raised when the device does not support the previewSign extension."""

    pass


class _CliInteraction(UserInteraction):
    """Simple CLI-based user interaction for FIDO2 operations."""

    def __init__(self, pin: Optional[str] = None):
        self._pin = pin

    def prompt_up(self):
        print("\nTouch your security key...", file=sys.stderr, flush=True)

    def request_pin(self, permissions, rp_id):
        if self._pin is not None:
            return self._pin
        try:
            return getpass.getpass("Enter FIDO2 PIN: ")
        except (EOFError, KeyboardInterrupt):
            return None

    def request_uv(self, permissions, rp_id):
        return True


def _find_device():
    """Finds the first CTAP HID device that supports previewSign.

    Returns:
        CtapHidDevice: The first compatible device.

    Raises:
        Fido2DeviceNotFoundError: If no FIDO2 device is found.
        Fido2ExtensionNotSupportedError: If no device supports previewSign.
    """
    from fido2.ctap2 import Ctap2

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        raise Fido2DeviceNotFoundError(
            "No FIDO2 HID device found. Insert a security key."
        )
    for dev in devices:
        try:
            info = Ctap2(dev).get_info()
            if PreviewSignExtension.NAME in (info.extensions or []):
                return dev
        except Exception:
            continue
    raise Fido2ExtensionNotSupportedError(
        "No connected FIDO2 device supports the 'previewSign' extension. "
        "Ensure firmware is 5.8+ and the extension is enabled."
    )


def _resolve_uv_requirement(client, require_uv: bool = False):
    """Returns REQUIRED if require_uv, else PREFERRED/DISCOURAGED by device."""
    if require_uv:
        return UserVerificationRequirement.REQUIRED
    info = getattr(client, "info", None)
    options = getattr(info, "options", None) or {}
    if any(options.get(k) for k in ("uv", "clientPin", "bioEnroll")):
        return UserVerificationRequirement.PREFERRED
    return UserVerificationRequirement.DISCOURAGED


def _make_client(
    device,
    rp_id=_DEFAULT_RP_ID,
    user_interaction=None,
    extensions=None,
):
    """Creates a Fido2Client configured for the previewSign extension.

    Args:
        device: A CtapHidDevice instance.
        rp_id: The relying party ID.
        user_interaction: Optional UserInteraction instance.
        extensions: Optional list of Ctap2Extension instances.

    Returns:
        Fido2Client: The configured client.
    """
    origin = f"https://{rp_id}"
    return Fido2Client(
        device,
        client_data_collector=DefaultClientDataCollector(origin),
        user_interaction=user_interaction or _CliInteraction(),
        extensions=(
            extensions if extensions is not None else [PreviewSignExtension()]
        ),
    )


def _make_unattended_preview_sign_extension():
    """Returns a PreviewSignExtension requesting flags=0 (Unattended)."""
    ext = PreviewSignExtension()
    orig_make_cred = ext.make_credential

    def _make_cred(ctap, options, pin_protocol):
        proc = orig_make_cred(ctap, options, pin_protocol)
        if proc is None:
            return None
        orig_prepare = proc.prepare_inputs

        def _prepare(pin_token):
            out = orig_prepare(pin_token)
            if out and PreviewSignExtension.NAME in out:
                # Yubico PreviewSignOptions.Unattended = 0 (no UP/UV per sign).
                out[PreviewSignExtension.NAME][4] = 0
            return out

        proc.prepare_inputs = _prepare
        return proc

    ext.make_credential = _make_cred
    return ext


def _prepare_tbs(data: bytes, additional_args: Optional[bytes]) -> bytes:
    """Returns tbs bytes, hashing with SHA-256 for ESP256-split ARKG keys."""
    if additional_args is None:
        return data
    from fido2 import cbor

    args_map = cbor.decode(additional_args)
    if (
        isinstance(args_map, dict)
        and args_map.get(3) == _COSE_ESP256_SPLIT_ARKG
    ):
        return hashlib.sha256(data).digest()
    return data


def _parse_cose_public_key(public_key_cbor_bytes):
    """Parses a COSE-encoded public key into EC public key + JWK.

    Args:
        public_key_cbor_bytes: CBOR-encoded COSE public key bytes.

    Returns:
        Tuple of (ec.EllipticCurvePublicKey, dict JWK, str algorithm).
    """
    from fido2 import cbor

    cose_key = cbor.decode(public_key_cbor_bytes)

    # COSE key parameter indices:
    # 1 = kty (2 = EC2), 3 = alg (-7 = ES256), -1 = crv (1 = P-256)
    # -2 = x, -3 = y
    kty = cose_key.get(1)
    if kty != 2:
        raise ValueError(f"Expected COSE EC2 key type (2), got {kty}")

    alg = cose_key.get(3)
    if alg not in (_COSE_ES256, _COSE_ESP256):
        raise ValueError(
            f"Expected COSE ES256 (-7) or ESP256 (-9) algorithm, got {alg}"
        )

    crv = cose_key.get(-1)
    if crv != 1:
        raise ValueError(f"Expected COSE P-256 curve (1), got {crv}")

    x_bytes = cose_key.get(-2)
    y_bytes = cose_key.get(-3)
    if not x_bytes or not y_bytes:
        raise ValueError("Missing x or y coordinate in COSE key")

    # Pad/trim to exactly 32 bytes
    x_bytes = x_bytes[-32:].rjust(32, b"\x00")
    y_bytes = y_bytes[-32:].rjust(32, b"\x00")

    # Reconstruct the cryptography public key
    pub_numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x_bytes, "big"),
        y=int.from_bytes(y_bytes, "big"),
        curve=ec.SECP256R1(),
    )
    public_key = pub_numbers.public_key()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(x_bytes).rstrip(b"=").decode("ascii"),
        "y": base64.urlsafe_b64encode(y_bytes).rstrip(b"=").decode("ascii"),
    }

    return public_key, jwk, "ES256"


class Fido2PreviewSignDPoPSigner(DPoPSigner):
    """Hardware-backed DPoP Signer using FIDO2 CTAP 2.3 previewSign.

    This signer uses the experimental ``previewSign`` CTAP2 extension to
    perform raw ECDSA P-256 (ES256) signing on a FIDO2 security key.
    The private key never leaves the hardware.

    **WARNING**: The ``previewSign`` extension is experimental and subject
    to change.  It requires a compatible authenticator (e.g. YubiKey 5
    Series with firmware 5.8+).

    Args:
        credential_id (bytes): The FIDO2 credential ID from registration.
        key_handle (bytes): The ARKG key handle returned by the
            previewSign extension during credential creation.
        public_key_bytes (bytes): CBOR-encoded COSE public key from
            the previewSign extension output.
        rp_id (str): The relying party ID used during registration.
            Must match at assertion time.
        key_id (Optional[str]): Optional custom key identifier.
        device: Optional pre-resolved CtapHidDevice.
        user_interaction: Optional UserInteraction for PIN/touch prompts.
        additional_args (Optional[bytes]): Optional CBOR-encoded ARKG
            signing arguments.
        require_up (bool): Whether user presence (physical touch) is
            required for each signature. Defaults to ``False``.
        require_uv (bool): Whether user verification (PIN/biometric) is
            required for each signature. Defaults to ``False``. Implies
            user presence when enabled.
        pin (Optional[str]): Optional FIDO2 PIN for non-interactive PIN
            prompts when ``user_interaction`` is not provided.
    """

    def __init__(
        self,
        credential_id: bytes,
        key_handle: bytes,
        public_key_bytes: bytes,
        rp_id: str = _DEFAULT_RP_ID,
        key_id: Optional[str] = None,
        device=None,
        user_interaction=None,
        additional_args: Optional[bytes] = None,
        require_up: bool = False,
        require_uv: bool = False,
        pin: Optional[str] = None,
    ):
        if not _FIDO2_AVAILABLE:
            raise Fido2PreviewSignError(
                f"fido2 library is not installed: {_IMPORT_ERROR}. "
                "Install with 'pip install fido2'."
            )

        self._credential_id = credential_id
        self._key_handle = key_handle
        self._public_key_bytes = public_key_bytes
        self._rp_id = rp_id
        self._custom_key_id = key_id
        self._user_interaction = user_interaction
        self._additional_args = additional_args
        self._require_uv = bool(require_uv)
        self._require_up = bool(require_up or require_uv)
        self._pin = pin

        # Parse the COSE public key
        self._public_key, self._public_jwk, self._algorithm = (
            _parse_cose_public_key(public_key_bytes)
        )

        # Resolve device (lazy -- will find on first sign if not provided)
        self._device = device

    def _get_device(self):
        """Returns the FIDO2 device, finding one if necessary."""
        if self._device is None:
            self._device = _find_device()
        return self._device

    @property
    def algorithm(self) -> str:
        """The JWS signing algorithm name (always 'ES256')."""
        return self._algorithm

    @property
    def public_jwk(self) -> Mapping[str, Any]:
        """The RFC 7517 public JSON Web Key (JWK) dictionary."""
        return self._public_jwk

    @property
    def key_id(self) -> Optional[str]:
        """Identifier for this FIDO2 signing credential."""
        if self._custom_key_id:
            return self._custom_key_id
        return f"fido2:{websafe_encode(self._credential_id[:8])}"

    @property
    def credential_id(self) -> bytes:
        """The FIDO2 credential ID."""
        return self._credential_id

    @property
    def key_handle(self) -> bytes:
        """The ARKG key handle from previewSign."""
        return self._key_handle

    @property
    def public_key_bytes(self) -> bytes:
        """The CBOR-encoded COSE public key."""
        return self._public_key_bytes

    @property
    def rp_id(self) -> str:
        """The relying party ID."""
        return self._rp_id

    @property
    def require_up(self) -> bool:
        """Whether user presence (touch) is required per signature."""
        return self._require_up

    @property
    def require_uv(self) -> bool:
        """Whether user verification (PIN/biometric) is required per sign."""
        return self._require_uv

    def sign(self, data: bytes) -> bytes:
        """Signs the input bytes on the security key via previewSign.

        Sends ``data`` (or its SHA-256 digest for ESP256-split ARKG keys)
        to the authenticator in the ``previewSign`` extension's ``tbs``
        (to-be-signed) field and returns the raw ECDSA P-256 signature.

        By default (``require_up=False``), signs silently via CTAP2
        ``options={'up': False}``. When ``require_up=True`` or
        ``require_uv=True``, prompts for touch and/or PIN verification.

        Args:
            data (bytes): The data to sign (typically the JWS signing
                input ``b'<header_b64>.<payload_b64>'``).

        Returns:
            bytes: The raw (R || S) ECDSA signature (64 bytes for P-256).

        Raises:
            Fido2PreviewSignError: If the device is not found or the
                signing operation fails.
        """
        device = self._get_device()
        tbs = _prepare_tbs(data, self._additional_args)

        if not (self._require_up or self._require_uv):
            return self._sign_unattended(device, tbs)

        client = _make_client(
            device,
            rp_id=self._rp_id,
            user_interaction=self._user_interaction or _CliInteraction(pin=self._pin),
        )

        cred_descriptor = PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=self._credential_id,
        )

        cred_id_b64 = websafe_encode(self._credential_id)

        sign_kwargs: dict[str, Any] = {}
        if self._additional_args is not None:
            sign_kwargs["additional_args"] = self._additional_args

        # Build the previewSign extension input for get_assertion.
        # sign_by_credential maps credential ID (base64url) -> signing params
        sign_inputs = _SignInputs(
            sign_by_credential={
                cred_id_b64: _SignSignInputs(
                    key_handle=self._key_handle,
                    tbs=tbs,
                    **sign_kwargs,
                ),
            },
        )

        options = PublicKeyCredentialRequestOptions(
            challenge=os.urandom(32),
            rp_id=self._rp_id,
            allow_credentials=[cred_descriptor],
            user_verification=_resolve_uv_requirement(
                client, require_uv=self._require_uv
            ),
            extensions={PreviewSignExtension.NAME: sign_inputs},
        )

        try:
            result = client.get_assertion(options)
        except Exception as exc:
            raise Fido2PreviewSignError(
                f"FIDO2 previewSign assertion failed: {exc}"
            ) from exc

        # Extract the signature from the extension outputs.
        # AssertionSelection.get_response() returns AuthenticationResponse,
        # whose client_extension_results is an
        # AuthenticationExtensionsClientOutputs (a Mapping).
        #
        # Use attribute access (preview_sign) rather than dict-style
        # .get("previewSign") -- the Mapping.__getitem__ converts rich
        # objects to plain dicts and base64-encodes bytes, whereas
        # __getattr__ returns the raw _SignOutputs dataclass.
        response = result.get_response(0)
        sign_output = response.client_extension_results.preview_sign

        if sign_output is None:
            raise Fido2PreviewSignError(
                "previewSign extension output missing from assertion response. "
                "Check that the authenticator supports the previewSign extension."
            )

        signature = sign_output.signature
        if signature is None:
            raise Fido2PreviewSignError(
                "previewSign extension returned no signature."
            )

        # The previewSign extension returns a DER-encoded ECDSA signature.
        # JWS ES256 requires raw (R || S) format -- 64 bytes for P-256.
        return der_to_raw_ecdsa_signature(signature, 32)

    def _sign_unattended(self, device, tbs: bytes) -> bytes:
        """Signs via CTAP2 getAssertion with options={'up': False}."""
        from fido2.ctap2 import Ctap2

        ext_in: dict[int, Any] = {2: self._key_handle, 6: tbs}
        if self._additional_args is not None:
            ext_in[7] = self._additional_args

        try:
            response = Ctap2(device).get_assertion(
                self._rp_id,
                os.urandom(32),
                [{"type": "public-key", "id": self._credential_id}],
                {PreviewSignExtension.NAME: ext_in},
                {"up": False},
            )
        except Exception as exc:
            if getattr(exc, "code", None) == 0x3B:
                raise Fido2PreviewSignError(
                    "Credential requires User Presence (touch). Re-generate "
                    "with require_up=False for unattended signing, or pass "
                    "require_up=True."
                ) from exc
            raise Fido2PreviewSignError(
                f"FIDO2 unattended previewSign assertion failed: {exc}"
            ) from exc

        extensions = getattr(response.auth_data, "extensions", None) or {}
        ps_output = extensions.get(PreviewSignExtension.NAME)
        if not ps_output or 6 not in ps_output:
            raise Fido2PreviewSignError(
                "previewSign extension output missing from assertion response."
            )
        return der_to_raw_ecdsa_signature(ps_output[6], 32)

    def to_dict(self) -> dict:
        """Serializes the signer state to a dictionary.

        The dictionary contains only public metadata and credential
        references -- no private key material is included (the private
        key never leaves the hardware).

        Returns:
            dict: A dictionary suitable for JSON serialization (values
                are hex-encoded bytes).
        """
        out = {
            "credential_id": self._credential_id.hex(),
            "key_handle": self._key_handle.hex(),
            "public_key_bytes": self._public_key_bytes.hex(),
            "rp_id": self._rp_id,
            "key_id": self._custom_key_id,
            "require_up": self._require_up,
            "require_uv": self._require_uv,
        }
        if self._additional_args is not None:
            out["additional_args"] = self._additional_args.hex()
        return out

    @classmethod
    def from_dict(
        cls,
        data: dict,
        device=None,
        user_interaction=None,
        pin: Optional[str] = None,
    ) -> "Fido2PreviewSignDPoPSigner":
        """Restores a signer from a previously serialized dictionary.

        Args:
            data (dict): The dictionary from :meth:`to_dict`.
            device: Optional CtapHidDevice to use.
            user_interaction: Optional UserInteraction for PIN/touch.
            pin (Optional[str]): Optional FIDO2 PIN for non-interactive
                prompts when ``user_interaction`` is not provided.

        Returns:
            Fido2PreviewSignDPoPSigner: The restored signer instance.
        """
        additional_args = (
            bytes.fromhex(data["additional_args"])
            if data.get("additional_args")
            else None
        )
        return cls(
            credential_id=bytes.fromhex(data["credential_id"]),
            key_handle=bytes.fromhex(data["key_handle"]),
            public_key_bytes=bytes.fromhex(data["public_key_bytes"]),
            rp_id=data.get("rp_id", _DEFAULT_RP_ID),
            key_id=data.get("key_id"),
            device=device,
            user_interaction=user_interaction,
            additional_args=additional_args,
            require_up=data.get("require_up", True),
            require_uv=data.get("require_uv", False),
            pin=pin,
        )


def generate_signing_credential(
    rp_id=_DEFAULT_RP_ID,
    rp_name=_DEFAULT_RP_NAME,
    user_id=None,
    user_name="dpop-signer",
    key_id=None,
    device=None,
    user_interaction=None,
    require_up=False,
    require_uv=False,
    resident_key=False,
    pin=None,
):
    """Generates a new previewSign signing credential on a FIDO2 device.

    This is a standalone key-generation helper -- separate from the
    signer class because DPoP signers should only *reference* existing
    keys, not create them.

    Creates a FIDO2 credential with the ``previewSign`` extension,
    which provisions a hardware-backed ECDSA P-256 signing key via
    ARKG (Asynchronous Remote Key Generation).

    **User interaction is required** -- the authenticator will prompt
    for PIN entry and/or touch confirmation.

    Args:
        rp_id (str): The relying party ID. Defaults to ``'dpop.local'``.
        rp_name (str): The relying party display name.
        user_id (Optional[bytes]): The user ID (random 32 bytes if
            omitted).
        user_name (str): The user name for the credential.
        key_id (Optional[str]): Optional custom key identifier.
        device: Optional CtapHidDevice to use.
        user_interaction: Optional UserInteraction for PIN/touch.
        require_up (bool): Whether user presence (physical touch) is
            required on each signature. Defaults to ``False``
            (``PreviewSignOptions.Unattended = 0``), so only credential
            creation requires a touch.
        require_uv (bool): Whether user verification (PIN/biometric) is
            required on each signature. Defaults to ``False``; when
            ``True``, sets ``PreviewSignOptions.RequireUserVerification``
            (``5``) and implies ``require_up=True``.
        resident_key (bool): Whether to create a discoverable (resident)
            credential stored on-chip and visible in Yubico Authenticator.
            Defaults to ``False``.
        pin (Optional[str]): Optional FIDO2 PIN for non-interactive PIN
            prompts when ``user_interaction`` is not provided.

    Returns:
        Fido2PreviewSignDPoPSigner: A signer configured with the
            newly generated credential.

    Raises:
        Fido2PreviewSignError: If device not found or extension
            not supported.
        Fido2ExtensionNotSupportedError: If the device does not
            support previewSign.
    """
    if not _FIDO2_AVAILABLE:
        raise Fido2PreviewSignError(
            f"fido2 library is not installed: {_IMPORT_ERROR}. "
            "Install with 'pip install fido2'."
        )

    if device is None:
        device = _find_device()

    unattended = not (require_up or require_uv)
    client_kwargs = {
        "rp_id": rp_id,
        "user_interaction": user_interaction or _CliInteraction(pin=pin),
    }
    if unattended:
        client_kwargs["extensions"] = [
            _make_unattended_preview_sign_extension()
        ]
    client = _make_client(device, **client_kwargs)

    # Check that the authenticator supports previewSign
    if (
        not hasattr(client, "info")
        or client.info is None
        or PreviewSignExtension.NAME not in (client.info.extensions or [])
    ):
        raise Fido2ExtensionNotSupportedError(
            "The connected FIDO2 device does not support the "
            "'previewSign' extension. Ensure firmware is 5.8+ "
            "and the extension is enabled."
        )

    if user_id is None:
        user_id = os.urandom(32)

    rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
    user = PublicKeyCredentialUserEntity(
        id=user_id,
        name=user_name,
    )

    # Request ES256 (-7)
    pub_key_params = [
        PublicKeyCredentialParameters(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            alg=_COSE_ES256,
        )
    ]

    # Build the previewSign extension input for make_credential.
    # Offer ES256 (-7) as well as ESP256-split ARKG (-65539, used by YubiKey 5.8).
    generate_inputs = _SignInputs(
        generate_key=_SignGenerateKeyInputs(
            algorithms=[_COSE_ES256, _COSE_ESP256_SPLIT_ARKG]
        ),
    )

    rk_req = (
        ResidentKeyRequirement.REQUIRED
        if resident_key
        else ResidentKeyRequirement.DISCOURAGED
    )
    options = PublicKeyCredentialCreationOptions(
        rp=rp,
        user=user,
        challenge=os.urandom(32),
        pub_key_cred_params=pub_key_params,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=rk_req,
            user_verification=_resolve_uv_requirement(
                client, require_uv=require_uv
            ),
        ),
        extensions={PreviewSignExtension.NAME: generate_inputs},
    )

    try:
        result = client.make_credential(options)
    except Exception as exc:
        raise Fido2PreviewSignError(
            f"FIDO2 previewSign credential creation failed: {exc}"
        ) from exc

    # Extract the credential ID from the attestation.
    # RegistrationResponse.response is AuthenticatorAttestationResponse,
    # which holds the AttestationObject.
    auth_data = result.response.attestation_object.auth_data
    cred_data = auth_data.credential_data
    if cred_data is None:
        raise Fido2PreviewSignError(
            "Attestation response missing credential data."
        )
    credential_id = cred_data.credential_id

    # Extract the previewSign extension outputs.
    # RegistrationResponse.client_extension_results is an
    # AuthenticationExtensionsClientOutputs (a Mapping).
    #
    # Use attribute access (preview_sign) rather than dict-style
    # .get("previewSign") -- the Mapping.__getitem__ converts rich
    # objects to plain dicts and base64-encodes bytes, whereas
    # __getattr__ returns the raw _SignOutputs dataclass.
    sign_output = result.client_extension_results.preview_sign

    if sign_output is None or sign_output.generated_key is None:
        raise Fido2PreviewSignError(
            "previewSign extension output missing from registration "
            "response. The authenticator may not fully support "
            "previewSign key generation."
        )

    generated = sign_output.generated_key
    key_handle = generated.key_handle
    public_key_bytes = generated.public_key
    additional_args = None

    if generated.algorithm == _COSE_ESP256_SPLIT_ARKG:
        from fido2 import cbor
        from fido2.cose import CoseKey

        arkg_key = CoseKey.parse(cbor.decode(public_key_bytes))
        ikm = os.urandom(32)
        ctx = os.urandom(16)
        derived_pk, sign_args = arkg_key.derive_public_key(ikm, ctx)
        public_key_bytes = cbor.encode(dict(derived_pk))
        additional_args = cbor.encode(sign_args)

    logger.info(
        f"Generated FIDO2 previewSign credential: "
        f"credential_id={credential_id.hex()[:16]}..., "
        f"key_handle={key_handle.hex()[:16]}..."
    )

    return Fido2PreviewSignDPoPSigner(
        credential_id=credential_id,
        key_handle=key_handle,
        public_key_bytes=public_key_bytes,
        rp_id=rp_id,
        key_id=key_id,
        device=device,
        user_interaction=user_interaction,
        additional_args=additional_args,
        require_up=bool(require_up or require_uv),
        require_uv=bool(require_uv),
        pin=pin,
    )
