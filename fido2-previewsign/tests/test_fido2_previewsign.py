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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def _install_fake_fido2(cose_key_dict):
    fido2_mod = types.ModuleType("fido2")
    client_mod = types.ModuleType("fido2.client")
    ctap2_mod = types.ModuleType("fido2.ctap2")
    ext_mod = types.ModuleType("fido2.ctap2.extensions")
    hid_mod = types.ModuleType("fido2.hid")
    utils_mod = types.ModuleType("fido2.utils")
    webauthn_mod = types.ModuleType("fido2.webauthn")
    cbor_mod = types.ModuleType("fido2.cbor")

    class _Dummy:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    client_mod.DefaultClientDataCollector = _Dummy
    client_mod.Fido2Client = mock.MagicMock()
    client_mod.UserInteraction = object

    class _PreviewSignExtension:
        NAME = "previewSign"

    ext_mod.PreviewSignExtension = _PreviewSignExtension
    ext_mod._SignGenerateKeyInputs = _Dummy
    ext_mod._SignInputs = _Dummy
    ext_mod._SignSignInputs = _Dummy

    hid_mod.CtapHidDevice = mock.MagicMock()
    utils_mod.websafe_encode = lambda b: b.hex()
    cbor_mod.decode = mock.MagicMock(return_value=cose_key_dict)

    for attr in (
        "PublicKeyCredentialCreationOptions",
        "PublicKeyCredentialDescriptor",
        "PublicKeyCredentialParameters",
        "PublicKeyCredentialRequestOptions",
        "PublicKeyCredentialRpEntity",
        "PublicKeyCredentialType",
        "PublicKeyCredentialUserEntity",
    ):
        setattr(webauthn_mod, attr, _Dummy)
    webauthn_mod.PublicKeyCredentialType = mock.MagicMock()

    fido2_mod.cbor = cbor_mod
    return {
        "fido2": fido2_mod,
        "fido2.client": client_mod,
        "fido2.ctap2": ctap2_mod,
        "fido2.ctap2.extensions": ext_mod,
        "fido2.hid": hid_mod,
        "fido2.utils": utils_mod,
        "fido2.webauthn": webauthn_mod,
        "fido2.cbor": cbor_mod,
    }


def test_fido2_previewsign_proof_and_roundtrip():
    private_key = ec.generate_private_key(ec.SECP256R1())
    nums = private_key.public_key().public_numbers()
    cose_dict = {
        1: 2,
        3: -7,
        -1: 1,
        -2: nums.x.to_bytes(32, "big"),
        -3: nums.y.to_bytes(32, "big"),
    }
    fake_mods = _install_fake_fido2(cose_dict)

    sys.modules.pop("dpop_signer_fido2_previewsign", None)
    with mock.patch.dict(sys.modules, fake_mods):
        mod = importlib.import_module("dpop_signer_fido2_previewsign")

        def fake_assertion(options):
            tbs = options.kwargs["extensions"]["previewSign"].kwargs[
                "sign_by_credential"
            ]["0102"].kwargs["tbs"]
            der_sig = private_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
            resp = mock.MagicMock()
            resp.client_extension_results.preview_sign.signature = der_sig
            result = mock.MagicMock()
            result.get_response.return_value = resp
            return result

        client_inst = mock.MagicMock()
        client_inst.get_assertion.side_effect = fake_assertion
        fake_mods["fido2.client"].Fido2Client.return_value = client_inst

        signer = mod.Fido2PreviewSignDPoPSigner(
            credential_id=b"\x01\x02",
            key_handle=b"\x03\x04",
            public_key_bytes=b"cbor-bytes",
            device=mock.MagicMock(),
        )
        proof = signer.create_proof("POST", "https://oauth2.googleapis.com/token")
        header = pyjwt.get_unverified_header(proof)
        claims = pyjwt.decode(
            proof, pyjwt.PyJWK.from_dict(header["jwk"]).key, algorithms=["ES256"]
        )
        assert claims["htm"] == "POST"

        restored = mod.Fido2PreviewSignDPoPSigner.from_dict(signer.to_dict())
        assert restored.thumbprint == signer.thumbprint
        assert restored.credential_id == b"\x01\x02"
        assert restored.key_handle == b"\x03\x04"
