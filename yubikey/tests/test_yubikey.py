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

import importlib
import sys
import types
from unittest import mock

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def _install_fake_ykman():
    ykman_mod = types.ModuleType("ykman")
    ykman_dev_mod = types.ModuleType("ykman.device")
    yubikit_mod = types.ModuleType("yubikit")
    yubikit_core_mod = types.ModuleType("yubikit.core")
    yubikit_sc_mod = types.ModuleType("yubikit.core.smartcard")
    yubikit_piv_mod = types.ModuleType("yubikit.piv")

    class _ApduError(Exception):
        def __init__(self, sw):
            super().__init__(f"APDU error 0x{sw:04X}")
            self.sw = sw

    class _InvalidPinError(Exception):
        def __init__(self, attempts_remaining=2):
            super().__init__("Invalid PIN")
            self.attempts_remaining = attempts_remaining

    class _NotSupportedError(Exception):
        pass

    class _Slot:
        SIGNATURE = None
        AUTHENTICATION = None
        KEY_MANAGEMENT = None
        CARD_AUTH = None

        def __init__(self, name, value):
            self.name = name
            self.value = value

        def __call__(self, value):
            for s in (self.SIGNATURE, self.AUTHENTICATION, self.KEY_MANAGEMENT, self.CARD_AUTH):
                if s.value == value:
                    return s
            raise ValueError(value)

    sig = _Slot("SIGNATURE", 0x9C)
    auth = _Slot("AUTHENTICATION", 0x9A)
    km = _Slot("KEY_MANAGEMENT", 0x9D)
    ca = _Slot("CARD_AUTH", 0x9E)
    _Slot.SIGNATURE = sig
    _Slot.AUTHENTICATION = auth
    _Slot.KEY_MANAGEMENT = km
    _Slot.CARD_AUTH = ca

    yubikit_piv_mod.SLOT = _Slot
    yubikit_piv_mod.KEY_TYPE = types.SimpleNamespace(
        ECCP256="ECCP256", from_public_key=lambda k: "ECCP256"
    )
    yubikit_piv_mod.ApduError = _ApduError
    yubikit_piv_mod.InvalidPinError = _InvalidPinError
    yubikit_piv_mod.NotSupportedError = _NotSupportedError
    yubikit_piv_mod.SW = types.SimpleNamespace(SECURITY_CONDITION_NOT_SATISFIED=0x6982)
    yubikit_piv_mod.PivSession = mock.MagicMock()
    yubikit_sc_mod.SmartCardConnection = object()
    ykman_dev_mod.list_all_devices = mock.MagicMock(return_value=[])

    return {
        "ykman": ykman_mod,
        "ykman.device": ykman_dev_mod,
        "yubikit": yubikit_mod,
        "yubikit.core": yubikit_core_mod,
        "yubikit.core.smartcard": yubikit_sc_mod,
        "yubikit.piv": yubikit_piv_mod,
    }


def _fake_device(private_key, session_mock):
    meta = types.SimpleNamespace(public_key=private_key.public_key(), key_type="ECCP256")
    session_mock.get_slot_metadata.return_value = meta
    conn = mock.MagicMock()
    conn.__enter__ = mock.MagicMock(return_value=conn)
    conn.__exit__ = mock.MagicMock(return_value=False)
    dev = mock.MagicMock()
    dev.open_connection.return_value = conn
    return dev


def test_yubikey_pin_callable_cached_and_create_proof():
    private_key = ec.generate_private_key(ec.SECP256R1())
    fake_mods = _install_fake_ykman()
    session = mock.MagicMock()
    session.sign.side_effect = lambda slot, kt, data, hash_algorithm, padding: (
        private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    )
    fake_mods["yubikit.piv"].PivSession.return_value = session
    dev = _fake_device(private_key, session)

    pin_calls = 0

    def pin_provider():
        nonlocal pin_calls
        pin_calls += 1
        return " 123456 "

    sys.modules.pop("dpop_signer_yubikey", None)
    with mock.patch.dict(sys.modules, fake_mods):
        mod = importlib.import_module("dpop_signer_yubikey")
        signer = mod.YubiKeyDPoPSigner(pin=pin_provider, serial=111222, device=dev)
        assert pin_calls == 0

        proof = signer.create_proof("POST", "https://oauth2.googleapis.com/token")
        signer.create_proof("GET", "https://www.googleapis.com/drive/v3/files")

    assert pin_calls == 1
    session.verify_pin.assert_called_with("123456")
    assert session.verify_pin.call_count == 2
    header = pyjwt.get_unverified_header(proof)
    claims = pyjwt.decode(
        proof, pyjwt.PyJWK.from_dict(header["jwk"]).key, algorithms=["ES256"]
    )
    assert claims["htm"] == "POST"


def test_yubikey_missing_or_invalid_pin_raises_and_resets_cache():
    private_key = ec.generate_private_key(ec.SECP256R1())
    fake_mods = _install_fake_ykman()
    ApduError = fake_mods["yubikit.piv"].ApduError
    InvalidPinError = fake_mods["yubikit.piv"].InvalidPinError
    sec_err = fake_mods["yubikit.piv"].SW.SECURITY_CONDITION_NOT_SATISFIED

    session = mock.MagicMock()
    fake_mods["yubikit.piv"].PivSession.return_value = session
    dev = _fake_device(private_key, session)

    sys.modules.pop("dpop_signer_yubikey", None)
    with mock.patch.dict(sys.modules, fake_mods):
        mod = importlib.import_module("dpop_signer_yubikey")

        # 1. Omitted PIN on locked slot raises YubiKeyPINRequiredError (no getpass)
        session.sign.side_effect = ApduError(sec_err)
        signer_no_pin = mod.YubiKeyDPoPSigner(serial=1, device=dev)
        with pytest.raises(mod.YubiKeyPINRequiredError, match="requires PIN verification"):
            signer_no_pin.sign(b"hello")

        # 2. Invalid PIN resets cached value so retry re-invokes callable
        pins = iter(["000000", "123456"])
        session.sign.side_effect = lambda slot, kt, data, hash_algorithm, padding: (
            private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        )

        def fake_verify(p):
            if p != "123456":
                raise InvalidPinError(attempts_remaining=2)

        session.verify_pin.side_effect = fake_verify
        signer_retry = mod.YubiKeyDPoPSigner(pin=lambda: next(pins), serial=1, device=dev)
        with pytest.raises(mod.YubiKeyPINRequiredError, match="Attempts remaining: 2"):
            signer_retry.sign(b"hello")

        sig = signer_retry.sign(b"hello")
        assert len(sig) == 64
