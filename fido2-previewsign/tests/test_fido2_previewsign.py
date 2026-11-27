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
    ext_mod._SignInputs = _Dummy
    ext_mod._SignSignInputs = _Dummy

    hid_mod.CtapHidDevice = mock.MagicMock()
    utils_mod.websafe_encode = lambda b: b.hex()
    cbor_mod.decode = mock.MagicMock(return_value=cose_key_dict)

    for attr in (
        "PublicKeyCredentialDescriptor",
        "PublicKeyCredentialRequestOptions",
        "PublicKeyCredentialType",
    ):
        setattr(webauthn_mod, attr, _Dummy)
    webauthn_mod.UserVerificationRequirement = types.SimpleNamespace(
        PREFERRED="preferred", DISCOURAGED="discouraged", REQUIRED="required"
    )
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
            require_up=True,
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


def test_find_device_selects_previewsign_capable_device():
    fake_mods = _install_fake_fido2({})
    ctap2_cls = mock.MagicMock()
    dev_old = mock.MagicMock()
    dev_58 = mock.MagicMock()
    fake_mods["fido2.hid"].CtapHidDevice.list_devices.return_value = [dev_old, dev_58]

    info_old = types.SimpleNamespace(extensions=["hmac-secret"])
    info_58 = types.SimpleNamespace(extensions=["hmac-secret", "previewSign"])
    ctap2_cls.side_effect = lambda d: mock.MagicMock(
        get_info=lambda: info_old if d is dev_old else info_58
    )
    fake_mods["fido2.ctap2"].Ctap2 = ctap2_cls

    sys.modules.pop("dpop_signer_fido2_previewsign", None)
    with mock.patch.dict(sys.modules, fake_mods):
        mod = importlib.import_module("dpop_signer_fido2_previewsign")
        assert mod._find_device() is dev_58

        ctap2_cls.side_effect = lambda d: mock.MagicMock(get_info=lambda: info_old)
        try:
            mod._find_device()
            raise AssertionError("Expected Fido2ExtensionNotSupportedError")
        except mod.Fido2ExtensionNotSupportedError:
            pass


def test_resolve_uv_requirement():
    import importlib
    import sys
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch

    mod = sys.modules.get("dpop_signer_fido2_previewsign")
    if mod is None:
        fake_webauthn = MagicMock()
        fake_webauthn.UserVerificationRequirement.PREFERRED = "preferred"
        fake_webauthn.UserVerificationRequirement.DISCOURAGED = "discouraged"
        fake_fido2 = MagicMock()
        fake_fido2.webauthn = fake_webauthn
        stubs = {
            "fido2": fake_fido2,
            "fido2.client": fake_fido2.client,
            "fido2.cose": fake_fido2.cose,
            "fido2.ctap2": fake_fido2.ctap2,
            "fido2.ctap2.base": fake_fido2.ctap2.base,
            "fido2.ctap2.extensions": fake_fido2.ctap2.extensions,
            "fido2.hid": fake_fido2.hid,
            "fido2.server": fake_fido2.server,
            "fido2.utils": fake_fido2.utils,
            "fido2.webauthn": fake_webauthn,
        }
        with patch.dict(sys.modules, stubs):
            mod = importlib.import_module("dpop_signer_fido2_previewsign")

    preferred = mod.UserVerificationRequirement.PREFERRED
    discouraged = mod.UserVerificationRequirement.DISCOURAGED
    assert preferred != discouraged

    def _client(options):
        return SimpleNamespace(info=SimpleNamespace(options=options))

    assert mod._resolve_uv_requirement(_client({"clientPin": False})) == discouraged
    assert mod._resolve_uv_requirement(_client({})) == discouraged
    assert mod._resolve_uv_requirement(_client(None)) == discouraged
    assert mod._resolve_uv_requirement(_client({"clientPin": True})) == preferred
    assert mod._resolve_uv_requirement(_client({"uv": True})) == preferred
    assert mod._resolve_uv_requirement(_client({"bioEnroll": True})) == preferred
    assert (
        mod._resolve_uv_requirement(_client({"clientPin": False}), require_uv=True)
        == mod.UserVerificationRequirement.REQUIRED
    )


def test_arkg_roundtrip_and_prehash():
    import hashlib
    import importlib
    import sys
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch

    from cryptography.hazmat.primitives.asymmetric import ec

    pn = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    fake_cbor = MagicMock()
    pk_map = {
        1: 2,
        3: -9,
        -1: 1,
        -2: pn.x.to_bytes(32, "big"),
        -3: pn.y.to_bytes(32, "big"),
    }
    args_map = {3: -65539, -1: b"\xaa\xbb", -2: b"ctx"}
    fake_cbor.decode.side_effect = lambda b: {b"pk": pk_map, b"args": args_map}[b]

    mod = sys.modules.get("dpop_signer_fido2_previewsign")
    if mod is None:
        fake_fido2 = MagicMock()
        with patch.dict(
            sys.modules,
            {
                "fido2": fake_fido2,
                "fido2.cbor": fake_cbor,
                "fido2.client": fake_fido2.client,
                "fido2.cose": fake_fido2.cose,
                "fido2.ctap2": fake_fido2.ctap2,
                "fido2.ctap2.base": fake_fido2.ctap2.base,
                "fido2.ctap2.extensions": fake_fido2.ctap2.extensions,
                "fido2.hid": fake_fido2.hid,
                "fido2.server": fake_fido2.server,
                "fido2.utils": fake_fido2.utils,
                "fido2.webauthn": fake_fido2.webauthn,
            },
        ):
            mod = importlib.import_module("dpop_signer_fido2_previewsign")

    fido2_pkg = sys.modules.get("fido2", MagicMock())
    fido2_pkg.cbor = fake_cbor
    with patch.dict(sys.modules, {"fido2": fido2_pkg, "fido2.cbor": fake_cbor}):
        signer = mod.Fido2PreviewSignDPoPSigner(
            credential_id=b"\x11\x22",
            key_handle=b"\x33\x44",
            public_key_bytes=b"pk",
            device=MagicMock(),
            additional_args=b"args",
            require_up=True,
        )
        assert signer.algorithm == "ES256"
        assert signer.public_jwk["kty"] == "EC"
        assert signer.public_jwk["crv"] == "P-256"

        serialized = signer.to_dict()
        assert serialized["additional_args"] == b"args".hex()
        assert serialized["require_up"] is True
        restored = mod.Fido2PreviewSignDPoPSigner.from_dict(
            serialized, device=MagicMock()
        )
        assert restored.to_dict() == serialized

        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        der_sig = encode_dss_signature(123, 456)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.client_extension_results.preview_sign.signature = der_sig
        mock_client.get_assertion.return_value.get_response.return_value = mock_resp

        sign_sign_inputs_spy = MagicMock(return_value=SimpleNamespace(sentinel=True))
        with patch.object(mod, "_make_client", return_value=mock_client), patch.object(
            mod, "_SignSignInputs", sign_sign_inputs_spy
        ):
            raw_sig = restored.sign(b"hello-dpop")

        assert len(raw_sig) == 64
        sign_sign_inputs_spy.assert_called_once_with(
            key_handle=b"\x33\x44",
            tbs=hashlib.sha256(b"hello-dpop").digest(),
            additional_args=b"args",
        )


def test_unattended_sign_and_flags():
    import hashlib
    import importlib
    import sys
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    pn = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    pk_map = {
        1: 2,
        3: -9,
        -1: 1,
        -2: pn.x.to_bytes(32, "big"),
        -3: pn.y.to_bytes(32, "big"),
    }
    args_map = {3: -65539, -1: b"\xaa\xbb", -2: b"ctx"}
    fake_cbor = MagicMock()
    fake_cbor.decode.side_effect = lambda b: {b"pk": pk_map, b"args": args_map}[b]

    mod = sys.modules.get("dpop_signer_fido2_previewsign")
    if mod is None:
        fake_fido2 = MagicMock()
        with patch.dict(
            sys.modules,
            {
                "fido2": fake_fido2,
                "fido2.cbor": fake_cbor,
                "fido2.client": fake_fido2.client,
                "fido2.cose": fake_fido2.cose,
                "fido2.ctap2": fake_fido2.ctap2,
                "fido2.ctap2.base": fake_fido2.ctap2.base,
                "fido2.ctap2.extensions": fake_fido2.ctap2.extensions,
                "fido2.hid": fake_fido2.hid,
                "fido2.server": fake_fido2.server,
                "fido2.utils": fake_fido2.utils,
                "fido2.webauthn": fake_fido2.webauthn,
            },
        ):
            mod = importlib.import_module("dpop_signer_fido2_previewsign")

    fido2_pkg = sys.modules.get("fido2", MagicMock())
    fido2_pkg.cbor = fake_cbor
    fake_ctap2_cls = MagicMock()
    der_sig = encode_dss_signature(111, 222)
    fake_ctap2_cls.return_value.get_assertion.return_value = SimpleNamespace(
        auth_data=SimpleNamespace(
            extensions={mod.PreviewSignExtension.NAME: {6: der_sig}}
        )
    )
    fake_ctap2_mod = MagicMock()
    fake_ctap2_mod.Ctap2 = fake_ctap2_cls

    with patch.dict(
        sys.modules,
        {"fido2": fido2_pkg, "fido2.cbor": fake_cbor, "fido2.ctap2": fake_ctap2_mod},
    ):
        signer = mod.Fido2PreviewSignDPoPSigner(
            credential_id=b"\x11\x22",
            key_handle=b"\x33\x44",
            public_key_bytes=b"pk",
            device=MagicMock(),
            additional_args=b"args",
        )
        assert signer.to_dict()["require_up"] is False
        raw_sig = signer.sign(b"silent-dpop")
        assert len(raw_sig) == 64

        call_args = fake_ctap2_cls.return_value.get_assertion.call_args[0]
        assert call_args[0] == "dpop.local"
        assert call_args[2] == [{"type": "public-key", "id": b"\x11\x22"}]
        assert call_args[3] == {
            mod.PreviewSignExtension.NAME: {
                2: b"\x33\x44",
                6: hashlib.sha256(b"silent-dpop").digest(),
                7: b"args",
            }
        }
        assert call_args[4] == {"up": False}


def test_require_uv_pin_and_roundtrip():
    import json
    from unittest import mock

    from cryptography.hazmat.primitives.asymmetric import ec

    pn = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    cose_dict = {
        1: 2,
        3: -7,
        -1: 1,
        -2: pn.x.to_bytes(32, "big"),
        -3: pn.y.to_bytes(32, "big"),
    }
    fake_mods = _install_fake_fido2(cose_dict)

    sys.modules.pop("dpop_signer_fido2_previewsign", None)
    with mock.patch.dict(sys.modules, fake_mods):
        mod = importlib.import_module("dpop_signer_fido2_previewsign")

        signer = mod.Fido2PreviewSignDPoPSigner(
            credential_id=b"\xaa\xbb",
            key_handle=b"\xcc\xdd",
            public_key_bytes=b"pk",
            device=mock.MagicMock(),
            require_uv=True,
            pin="9988",
        )
        assert signer.require_up is True
        assert signer.require_uv is True

        dumped = json.dumps(signer.to_dict())
        assert "9988" not in dumped
        restored = mod.Fido2PreviewSignDPoPSigner.from_dict(
            json.loads(dumped), device=mock.MagicMock(), pin="9988"
        )
        assert restored.require_up is True
        assert restored.require_uv is True

        cli = mod._PinUserInteraction(pin="9988")
        assert cli.request_pin(0, "dpop.local") == "9988"

        fake_client = mock.MagicMock()
        resp = mock.MagicMock()
        resp.client_extension_results.preview_sign.signature = b"\x30\x06\x02\x01\x01\x02\x01\x01"
        fake_client.get_assertion.return_value.get_response.return_value = resp
        with mock.patch.object(mod, "_make_client", return_value=fake_client) as mk_cli:
            sig = restored.sign(b"hello")
        assert len(sig) == 64
        assert mk_cli.call_args.kwargs["user_interaction"].request_pin(0, "dpop.local") == "9988"
        req_opts = fake_client.get_assertion.call_args[0][0]
        assert req_opts.kwargs["user_verification"] == mod.UserVerificationRequirement.REQUIRED

        # Callable PIN is invoked lazily once and invalidated on PinRequiredError
        calls = iter(["bad-pin", "good-pin"])
        call_count = 0

        def next_pin():
            nonlocal call_count
            call_count += 1
            return next(calls)

        signer_cb = mod.Fido2PreviewSignDPoPSigner(
            credential_id=b"\xaa\xbb",
            key_handle=b"\xcc\xdd",
            public_key_bytes=b"pk",
            device=mock.MagicMock(),
            require_uv=True,
            pin=next_pin,
        )
        assert call_count == 0
        assert signer_cb._pin_interaction.request_pin(0, "dpop.local") == "bad-pin"
        assert signer_cb._pin_interaction.request_pin(0, "dpop.local") == "bad-pin"
        assert call_count == 1

        class PinRequiredError(Exception):
            pass

        fake_client.get_assertion.side_effect = PinRequiredError("PIN required")
        with mock.patch.object(mod, "_make_client", return_value=fake_client):
            try:
                signer_cb.sign(b"hello")
                raise AssertionError("Expected Fido2PINRequiredError")
            except mod.Fido2PINRequiredError:
                pass
        assert signer_cb._pin_interaction.request_pin(0, "dpop.local") == "good-pin"
        assert call_count == 2


def test_error_paths_and_up_required_message():
    from unittest import mock

    from cryptography.hazmat.primitives.asymmetric import ec

    pn = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    valid_cose = {
        1: 2,
        3: -7,
        -1: 1,
        -2: pn.x.to_bytes(32, "big"),
        -3: pn.y.to_bytes(32, "big"),
    }
    fake_mods = _install_fake_fido2(valid_cose)

    sys.modules.pop("dpop_signer_fido2_previewsign", None)
    with mock.patch.dict(sys.modules, fake_mods):
        mod = importlib.import_module("dpop_signer_fido2_previewsign")

        fake_mods["fido2"].cbor.decode.return_value = {1: 3}
        try:
            mod._parse_cose_public_key(b"bad")
            raise AssertionError("Expected ValueError for non-EC2 key")
        except ValueError:
            pass

        fake_mods["fido2"].cbor.decode.return_value = {1: 2, 3: -8}
        try:
            mod._parse_cose_public_key(b"bad-alg")
            raise AssertionError("Expected ValueError for unsupported alg")
        except ValueError:
            pass

        fake_mods["fido2"].cbor.decode.return_value = valid_cose
        signer = mod.Fido2PreviewSignDPoPSigner(
            credential_id=b"\x01",
            key_handle=b"\x02",
            public_key_bytes=b"pk",
            device=mock.MagicMock(),
            require_up=False,
        )
        err = Exception("UP_REQUIRED")
        err.code = 0x3B
        fake_mods["fido2.ctap2"].Ctap2 = mock.MagicMock()
        fake_mods["fido2.ctap2"].Ctap2.return_value.get_assertion.side_effect = err
        try:
            signer.sign(b"payload")
            raise AssertionError("Expected Fido2PreviewSignError")
        except mod.Fido2PreviewSignError as exc:
            assert "User Presence" in str(exc)
