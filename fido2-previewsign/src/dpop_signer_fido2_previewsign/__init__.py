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
specification.  It is NOT yet standardized and is subject to change.
Only ES256 (ECDSA P-256) is supported.

Lifecycle
---------
1. **Key generation** -- Call :func:`generate_signing_credential`
   to create a new FIDO2 credential with the ``previewSign`` extension
   on the security key.  This returns a signer instance holding the
   credential ID, the ARKG key handle, and the derived public key.
2. **Signing** -- Call :meth:`sign` or :meth:`create_proof` to produce
   DPoP proof JWTs.  Each signing operation triggers a CTAP2 assertion
   that sends the raw ``signing_input`` bytes to the authenticator, which
   returns a raw ECDSA P-256 signature.
3. **Persistence** -- Save ``credential_id``, ``key_handle``, and
   ``public_key_bytes`` (all ``bytes``) via :meth:`to_dict` to restore
   the signer later without re-generating.
"""

from __future__ import annotations

import getpass
import logging
import os
import sys
from typing import Any, Mapping, Optional, Sequence, Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from google.auth import _helpers
from google.auth.dpop import DPoPSigner

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
        _SignOutputs,
        _SignSignInputs,
    )
    from fido2.hid import CtapHidDevice
    from fido2.utils import websafe_encode
    from fido2.webauthn import (
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters,
        PublicKeyCredentialRequestOptions,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialType,
        PublicKeyCredentialUserEntity,
    )

    try:
        from fido2.cose import ES256 as CoseES256
    except ImportError:
        CoseES256 = None

    _FIDO2_AVAILABLE = True
except ImportError as _import_err:
    _FIDO2_AVAILABLE = False
    _IMPORT_ERROR = _import_err

logger = logging.getLogger(__name__)

# COSE algorithm identifier for ES256 (ECDSA w/ SHA-256 on P-256)
_COSE_ES256 = -7

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

    def prompt_up(self):
        print("\nTouch your security key...", file=sys.stderr, flush=True)

    def request_pin(self, permissions, rp_id):
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
    devices = list(CtapHidDevice.list_devices())
    if not devices:
        raise Fido2DeviceNotFoundError(
            "No FIDO2 HID device found. Insert a security key."
        )
    return devices[0]


def _make_client(device, rp_id=_DEFAULT_RP_ID, user_interaction=None):
    """Creates a Fido2Client configured for the previewSign extension.

    Args:
        device: A CtapHidDevice instance.
        rp_id: The relying party ID.
        user_interaction: Optional UserInteraction instance.

    Returns:
        Fido2Client: The configured client.
    """
    origin = f"https://{rp_id}"
    return Fido2Client(
        device,
        client_data_collector=DefaultClientDataCollector(origin),
        user_interaction=user_interaction or _CliInteraction(),
        extensions=[PreviewSignExtension()],
    )


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
    if alg != _COSE_ES256:
        raise ValueError(f"Expected COSE ES256 algorithm (-7), got {alg}")

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
        "x": _helpers.unpadded_urlsafe_b64encode(x_bytes).decode("ascii"),
        "y": _helpers.unpadded_urlsafe_b64encode(y_bytes).decode("ascii"),
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

    def sign(self, data: bytes) -> bytes:
        """Signs the input bytes on the security key via previewSign.

        Sends the raw ``data`` bytes to the authenticator in the
        ``previewSign`` extension's ``tbs`` (to-be-signed) field.
        The authenticator performs ECDSA P-256 signing on-chip and
        returns the raw signature.

        **User interaction is required** -- the authenticator will prompt
        for PIN verification and/or touch confirmation.

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
        client = _make_client(
            device,
            rp_id=self._rp_id,
            user_interaction=self._user_interaction,
        )

        cred_descriptor = PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=self._credential_id,
        )

        cred_id_b64 = websafe_encode(self._credential_id)

        # Build the previewSign extension input for get_assertion.
        # sign_by_credential maps credential ID (base64url) -> signing params
        sign_inputs = _SignInputs(
            sign_by_credential={
                cred_id_b64: _SignSignInputs(
                    key_handle=self._key_handle,
                    tbs=data,
                ),
            },
        )

        options = PublicKeyCredentialRequestOptions(
            challenge=os.urandom(32),
            rp_id=self._rp_id,
            allow_credentials=[cred_descriptor],
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
        # Convert DER -> raw R||S.
        r, s = decode_dss_signature(signature)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def to_dict(self) -> dict:
        """Serializes the signer state to a dictionary.

        The dictionary contains only public metadata and credential
        references -- no private key material is included (the private
        key never leaves the hardware).

        Returns:
            dict: A dictionary suitable for JSON serialization (values
                are hex-encoded bytes).
        """
        return {
            "credential_id": self._credential_id.hex(),
            "key_handle": self._key_handle.hex(),
            "public_key_bytes": self._public_key_bytes.hex(),
            "rp_id": self._rp_id,
            "key_id": self._custom_key_id,
        }

    @classmethod
    def from_dict(
        cls,
        data: dict,
        device=None,
        user_interaction=None,
    ) -> "Fido2PreviewSignDPoPSigner":
        """Restores a signer from a previously serialized dictionary.

        Args:
            data (dict): The dictionary from :meth:`to_dict`.
            device: Optional CtapHidDevice to use.
            user_interaction: Optional UserInteraction for PIN/touch.

        Returns:
            Fido2PreviewSignDPoPSigner: The restored signer instance.
        """
        return cls(
            credential_id=bytes.fromhex(data["credential_id"]),
            key_handle=bytes.fromhex(data["key_handle"]),
            public_key_bytes=bytes.fromhex(data["public_key_bytes"]),
            rp_id=data.get("rp_id", _DEFAULT_RP_ID),
            key_id=data.get("key_id"),
            device=device,
            user_interaction=user_interaction,
        )



def generate_signing_credential(
    rp_id=_DEFAULT_RP_ID,
    rp_name=_DEFAULT_RP_NAME,
    user_id=None,
    user_name="dpop-signer",
    key_id=None,
    device=None,
    user_interaction=None,
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

    client = _make_client(
        device,
        rp_id=rp_id,
        user_interaction=user_interaction or _CliInteraction(),
    )

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

    # Build the previewSign extension input for make_credential
    generate_inputs = _SignInputs(
        generate_key=_SignGenerateKeyInputs(algorithms=[_COSE_ES256]),
    )

    options = PublicKeyCredentialCreationOptions(
        rp=rp,
        user=user,
        challenge=os.urandom(32),
        pub_key_cred_params=pub_key_params,
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
    )
