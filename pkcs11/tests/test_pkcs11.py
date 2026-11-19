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

import datetime
import importlib
import sys
import types
from unittest import mock

import jwt as pyjwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import NameOID


class _FakeEnum:
    PRIVATE_KEY = "PRIVATE_KEY"
    PUBLIC_KEY = "PUBLIC_KEY"
    CERTIFICATE = "CERTIFICATE"
    CLASS = "CLASS"
    LABEL = "LABEL"
    ID = "ID"
    KEY_TYPE = "KEY_TYPE"
    EC_PARAMS = "EC_PARAMS"
    EC_POINT = "EC_POINT"
    MODULUS = "MODULUS"
    PUBLIC_EXPONENT = "PUBLIC_EXPONENT"
    VALUE = "VALUE"
    EC = "EC"
    RSA = "RSA"
    ECDSA = "ECDSA"
    ECDSA_SHA256 = "ECDSA_SHA256"
    ECDSA_SHA384 = "ECDSA_SHA384"
    SHA256_RSA_PKCS = "SHA256_RSA_PKCS"


class _FakeObjectClass:
    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return isinstance(other, _FakeObjectClass) and self.name == other.name

    def __hash__(self):
        return hash(self.name)


class _MechanismInvalid(Exception):
    pass


def _make_fake_pkcs11_module(slots):
    mod = types.ModuleType("pkcs11")
    mod.MechanismInvalid = _MechanismInvalid
    mod.Attribute = _FakeEnum
    mod.KeyType = _FakeEnum
    mod.Mechanism = _FakeEnum
    mod.ObjectClass = types.SimpleNamespace(
        PRIVATE_KEY=_FakeObjectClass("PRIVATE_KEY"),
        PUBLIC_KEY=_FakeObjectClass("PUBLIC_KEY"),
        CERTIFICATE=_FakeObjectClass("CERTIFICATE"),
    )

    fake_lib = mock.MagicMock()
    fake_lib.get_slots.return_value = slots
    mod.lib = mock.MagicMock(return_value=fake_lib)
    return mod, fake_lib


def _make_self_signed_der(key):
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "PKCS11 Test")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _load_mod(slots):
    fake_p11, fake_lib = _make_fake_pkcs11_module(slots)
    sys.modules.pop("dpop_signer_pkcs11", None)
    with mock.patch.dict(sys.modules, {"pkcs11": fake_p11}):
        mod = importlib.import_module("dpop_signer_pkcs11")
    return mod, fake_p11, fake_lib


def test_parse_pkcs11_uri_rfc7512_attributes():
    mod, _, _ = _load_mod([])
    parsed = mod.parse_pkcs11_uri(
        "pkcs11:token=YubiKey%20PIV;object=dpop-key;id=%01%ab;slot-id=2;"
        "serial=123456;manufacturer=Yubico;model=YubiKey;type=private"
        "?module-path=/opt/homebrew/lib/libykcs11.dylib&pin-value=123456"
    )
    assert parsed["token_label"] == "YubiKey PIV"
    assert parsed["key_label"] == "dpop-key"
    assert parsed["cka_id"] == b"\x01\xab"
    assert parsed["slot_id"] == 2
    assert parsed["token_serial"] == "123456"
    assert parsed["manufacturer"] == "Yubico"
    assert parsed["model"] == "YubiKey"
    assert parsed["object_type"] == "private"
    assert parsed["module_path"] == "/opt/homebrew/lib/libykcs11.dylib"
    assert parsed["pin"] == "123456"


@pytest.mark.parametrize(
    "bad_uri",
    [
        "http://example.com",
        "pkcs11:token_without_equals",
        "pkcs11:slot-id=notanint",
        "pkcs11:type=secret-key",
    ],
)
def test_parse_pkcs11_uri_invalid_raises(bad_uri):
    mod, _, _ = _load_mod([])
    with pytest.raises(ValueError):
        mod.parse_pkcs11_uri(bad_uri)


def test_ecdsa_public_key_object_and_der_octet_point_es256(tmp_path):
    lib_file = tmp_path / "libmock.so"
    lib_file.write_bytes(b"")
    pin_file = tmp_path / "pin.txt"
    pin_file.write_text("s3cr3t\n", encoding="utf-8")

    priv_key = ec.generate_private_key(ec.SECP256R1())
    raw_point = priv_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    # Cryptoki wraps EC_POINT in DER OCTET STRING (0x04 <len> <04||X||Y>)
    der_ec_point = bytes([0x04, len(raw_point)]) + raw_point
    p256_oid = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"

    fake_priv = mock.MagicMock()

    def fake_sign(digest, mechanism):
        der = priv_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    fake_priv.sign.side_effect = fake_sign
    fake_pub = {
        _FakeEnum.KEY_TYPE: _FakeEnum.EC,
        _FakeEnum.EC_PARAMS: p256_oid,
        _FakeEnum.EC_POINT: der_ec_point,
    }

    session = mock.MagicMock()
    session.get_objects.side_effect = lambda tmpl: (
        [fake_priv]
        if tmpl[_FakeEnum.CLASS].name == "PRIVATE_KEY"
        else [fake_pub]
        if tmpl[_FakeEnum.CLASS].name == "PUBLIC_KEY"
        else []
    )
    token = types.SimpleNamespace(
        label="tpm2          ",
        serial="SN01  ",
        manufacturer_id="TPM2",
        model="Soft",
        open=mock.MagicMock(return_value=session),
    )
    slot = types.SimpleNamespace(slot_id=1, get_token=lambda: token)
    mod, _, _ = _load_mod([slot])

    with mod.PKCS11DPoPSigner(
        f"pkcs11:token=tpm2;object=dpop;id=%01?module-path={lib_file}&pin-source=file:{pin_file}"
    ) as signer:
        token.open.assert_called_once_with(user_pin="s3cr3t")
        assert signer.algorithm == "ES256"
        assert "=" not in signer.public_jwk["x"]
        assert signer.key_id == "pkcs11:tpm2:dpop"

        proof = signer.create_proof("POST", "https://oauth2.googleapis.com/token")
        header = pyjwt.get_unverified_header(proof)
        claims = pyjwt.decode(
            proof, pyjwt.PyJWK.from_dict(header["jwk"]).key, algorithms=["ES256"]
        )
        assert claims["htm"] == "POST"
    session.close.assert_called_once()


def test_certificate_fallback_rsa_and_callback_pin(tmp_path):
    lib_file = tmp_path / "opensc.so"
    lib_file.write_bytes(b"")
    rsa_key = rsa.generate_private_key(65537, 2048)
    cert_der = _make_self_signed_der(rsa_key)

    fake_priv = mock.MagicMock()
    fake_priv.sign.side_effect = lambda data, mechanism: rsa_key.sign(
        data, padding.PKCS1v15(), hashes.SHA256()
    )
    fake_cert = {_FakeEnum.VALUE: cert_der}

    session = mock.MagicMock()
    session.get_objects.side_effect = lambda tmpl: (
        [fake_priv]
        if tmpl[_FakeEnum.CLASS].name == "PRIVATE_KEY"
        else [fake_cert]
        if tmpl[_FakeEnum.CLASS].name == "CERTIFICATE"
        else []
    )
    token = types.SimpleNamespace(
        label="PIV",
        serial="999",
        manufacturer_id="Yubico",
        model="YK",
        open=mock.MagicMock(return_value=session),
    )
    slot = types.SimpleNamespace(slot_id=0, get_token=lambda: token)
    mod, _, _ = _load_mod([slot])

    pin_factory = mock.Mock(return_value="654321")
    signer = mod.PKCS11DPoPSigner(
        module_path=str(lib_file),
        token_label="PIV",
        cka_id="02",
        pin=pin_factory,
    )
    assert signer.algorithm == "RS256"
    assert signer.key_id == "pkcs11:PIV:02"
    proof = signer.create_proof("POST", "https://oauth2.googleapis.com/token")
    header = pyjwt.get_unverified_header(proof)
    claims = pyjwt.decode(
        proof, pyjwt.PyJWK.from_dict(header["jwk"]).key, algorithms=["RS256"]
    )
    assert claims["htm"] == "POST"
    assert pin_factory.call_count == 1
    signer.close()


def test_ecdsa_sha256_fallback_when_raw_ckm_ecdsa_rejected(tmp_path):
    lib_file = tmp_path / "libmock.so"
    lib_file.write_bytes(b"")
    priv_key = ec.generate_private_key(ec.SECP256R1())
    cert_der = _make_self_signed_der(priv_key)

    fake_priv = mock.MagicMock()

    def sign_with_fallback(payload, mechanism):
        if mechanism == _FakeEnum.ECDSA:
            raise _MechanismInvalid("CKM_ECDSA disallowed")
        der = priv_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    fake_priv.sign.side_effect = sign_with_fallback
    session = mock.MagicMock()
    session.get_objects.side_effect = lambda tmpl: (
        [fake_priv]
        if tmpl[_FakeEnum.CLASS].name == "PRIVATE_KEY"
        else [{_FakeEnum.VALUE: cert_der}]
        if tmpl[_FakeEnum.CLASS].name == "CERTIFICATE"
        else []
    )
    token = types.SimpleNamespace(
        label="tok",
        serial="1",
        manufacturer_id="M",
        model="K",
        open=mock.MagicMock(return_value=session),
    )
    slot = types.SimpleNamespace(slot_id=0, get_token=lambda: token)
    mod, _, _ = _load_mod([slot])

    signer = mod.PKCS11DPoPSigner(
        module_path=str(lib_file), key_label="k", pin="1234"
    )
    proof = signer.create_proof("POST", "https://oauth2.googleapis.com/token")
    header = pyjwt.get_unverified_header(proof)
    pyjwt.decode(proof, pyjwt.PyJWK.from_dict(header["jwk"]).key, algorithms=["ES256"])
    signer.close()


def test_env_module_and_rsa_public_key_object(tmp_path, monkeypatch):
    lib_file = tmp_path / "envmock.so"
    lib_file.write_bytes(b"")
    monkeypatch.setenv("PKCS11_MODULE", str(lib_file))

    rsa_key = rsa.generate_private_key(65537, 2048)
    pub_nums = rsa_key.public_key().public_numbers()
    n_bytes = pub_nums.n.to_bytes((pub_nums.n.bit_length() + 7) // 8, "big")
    e_bytes = pub_nums.e.to_bytes((pub_nums.e.bit_length() + 7) // 8, "big")

    fake_priv = mock.MagicMock()
    fake_priv.sign.side_effect = lambda data, mechanism: rsa_key.sign(
        data, padding.PKCS1v15(), hashes.SHA256()
    )
    # Include a redundant leading 0x00 byte to test stripping.
    fake_pub = {
        _FakeEnum.KEY_TYPE: _FakeEnum.RSA,
        _FakeEnum.MODULUS: b"\x00" + n_bytes,
        _FakeEnum.PUBLIC_EXPONENT: e_bytes,
    }
    session = mock.MagicMock()
    session.get_objects.side_effect = lambda tmpl: (
        [fake_priv]
        if tmpl[_FakeEnum.CLASS].name == "PRIVATE_KEY"
        else [fake_pub]
        if tmpl[_FakeEnum.CLASS].name == "PUBLIC_KEY"
        else []
    )
    token = types.SimpleNamespace(
        label="hsm",
        serial="1",
        manufacturer_id="M",
        model="K",
        open=mock.MagicMock(return_value=session),
    )
    slot = types.SimpleNamespace(slot_id=0, get_token=lambda: token)
    mod, _, _ = _load_mod([slot])

    signer = mod.PKCS11DPoPSigner("pkcs11:object=rsa-k")
    assert signer.algorithm == "RS256"
    proof = signer.create_proof("POST", "https://oauth2.googleapis.com/token")
    header = pyjwt.get_unverified_header(proof)
    pyjwt.decode(proof, pyjwt.PyJWK.from_dict(header["jwk"]).key, algorithms=["RS256"])
    signer.close()


def test_p11_kit_module_name_and_config_errors(tmp_path):
    lib_file = tmp_path / "libykcs11.so"
    lib_file.write_bytes(b"")
    p11_dir = tmp_path / "modules"
    p11_dir.mkdir()
    (p11_dir / "yubikey.module").write_text(
        f"# sample\nmodule: {lib_file}\n", encoding="utf-8"
    )

    mod, _, _ = _load_mod([])
    with mock.patch.object(mod, "_P11_KIT_MODULE_DIRS", (str(p11_dir),)):
        assert mod._resolve_module_path(module_name="yubikey") == str(lib_file)

    with pytest.raises(mod.PKCS11ConfigError, match="Specify key_label/object"):
        mod.PKCS11DPoPSigner(module_path=str(lib_file))

    with pytest.raises(mod.PKCS11ConfigError, match="No matching PKCS#11 token"):
        mod.PKCS11DPoPSigner(module_path=str(lib_file), key_label="k")
