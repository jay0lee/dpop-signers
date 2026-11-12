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

import ctypes
import datetime
import importlib
import sys
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
import pytest


def _make_self_signed_der(key):
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "DPoP Client")]
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


def _load_windows_module(crypt32_mock, ncrypt_mock):
    def fake_windll(name, use_last_error=False):
        if name == "crypt32":
            return crypt32_mock
        if name == "ncrypt":
            return ncrypt_mock
        raise ValueError(f"Unexpected DLL: {name}")

    sys.modules.pop("dpop_signer_windows_tpm", None)
    with (
        mock.patch.object(sys, "platform", "win32"),
        mock.patch.object(ctypes, "WinDLL", side_effect=fake_windll, create=True),
    ):
        return importlib.import_module("dpop_signer_windows_tpm")


def _make_cert_ptr(mod, der_bytes):
    buf = (ctypes.c_byte * len(der_bytes)).from_buffer_copy(der_bytes)
    ctx = mod._CERT_CONTEXT()
    ctx.pbCertEncoded = buf
    ctx.cbCertEncoded = len(der_bytes)
    # Keep buffer alive on ctx for test lifetime.
    ctx._keepalive_buf = buf
    return ctypes.pointer(ctx)


def _configure_success_mocks(crypt32_mock, ncrypt_mock, cert_ptr_factory):
    crypt32_mock.CertOpenStore.return_value = 0x1001
    crypt32_mock.CertFindCertificateInStore.side_effect = (
        lambda *args, **kwargs: cert_ptr_factory()
    )

    def fake_acquire(cert_ctx, flags, pv_reserved, ph_key, p_key_spec, p_caller_free):
        ph_key._obj.value = 0x2002
        p_key_spec._obj.value = 0xFFFFFFFF
        p_caller_free._obj.value = 1
        return 1

    crypt32_mock.CryptAcquireCertificatePrivateKey.side_effect = fake_acquire
    crypt32_mock.CertFreeCertificateContext.return_value = 1
    crypt32_mock.CertCloseStore.return_value = 1

    fake_sig = b"\xAA" * 64

    def fake_sign(h_key, p_padding, pb_hash, cb_hash, pb_sig, cb_sig, pcb_result, flags):
        pcb_result._obj.value = len(fake_sig)
        if pb_sig is not None:
            ctypes.memmove(pb_sig, fake_sig, len(fake_sig))
        return 0

    ncrypt_mock.NCryptSignHash.side_effect = fake_sign
    ncrypt_mock.NCryptFreeObject.return_value = 0
    return fake_sig


def test_import_fails_on_non_windows():
    sys.modules.pop("dpop_signer_windows_tpm", None)
    with mock.patch.object(sys, "platform", "darwin"):
        with pytest.raises(ImportError, match="only supported on Windows"):
            importlib.import_module("dpop_signer_windows_tpm")


@pytest.mark.parametrize(
    "store_location,expected_flag",
    [
        (None, 0x00010000 | 0x00008000),
        ("current_user", 0x00010000 | 0x00008000),
        ("CurrentUser", 0x00010000 | 0x00008000),
        ("local_machine", 0x00020000 | 0x00008000),
        ("LocalMachine", 0x00020000 | 0x00008000),
        ("local-machine", 0x00020000 | 0x00008000),
    ],
)
def test_store_location_opens_expected_system_store(store_location, expected_flag):
    ec_key = ec.generate_private_key(ec.SECP256R1())
    der_bytes = _make_self_signed_der(ec_key)

    crypt32_mock = mock.MagicMock()
    ncrypt_mock = mock.MagicMock()
    mod = _load_windows_module(crypt32_mock, ncrypt_mock)
    expected_sig = _configure_success_mocks(
        crypt32_mock, ncrypt_mock, lambda: _make_cert_ptr(mod, der_bytes)
    )

    kwargs = {"subject": "DPoP Client"}
    if store_location is not None:
        kwargs["store_location"] = store_location

    signer = mod.WindowsCNGDPoPSigner(**kwargs)

    call_args = crypt32_mock.CertOpenStore.call_args[0]
    assert call_args[0] == mod._CERT_STORE_PROV_SYSTEM
    assert call_args[3] == expected_flag
    assert call_args[4].value == "MY"
    assert signer.algorithm == "ES256"
    assert signer.public_jwk["kty"] == "EC"
    assert signer.public_jwk["crv"] == "P-256"
    assert signer.sign(b"header.payload") == expected_sig


@pytest.mark.parametrize("bad_location", ["system", "user", "", 123])
def test_invalid_store_location_raises_value_error(bad_location):
    crypt32_mock = mock.MagicMock()
    ncrypt_mock = mock.MagicMock()
    mod = _load_windows_module(crypt32_mock, ncrypt_mock)

    with pytest.raises(ValueError, match="store_location"):
        mod.WindowsCNGDPoPSigner(subject="DPoP Client", store_location=bad_location)

    crypt32_mock.CertOpenStore.assert_not_called()


def test_missing_subject_and_thumbprint_raises_value_error():
    mod = _load_windows_module(mock.MagicMock(), mock.MagicMock())
    with pytest.raises(ValueError, match="subject.*thumbprint"):
        mod.WindowsCNGDPoPSigner()


def test_cert_not_found_error_mentions_selected_store():
    crypt32_mock = mock.MagicMock()
    crypt32_mock.CertOpenStore.return_value = 0x1001
    crypt32_mock.CertFindCertificateInStore.return_value = None
    mod = _load_windows_module(crypt32_mock, mock.MagicMock())

    with pytest.raises(mod.WindowsCNGDPoPError, match=r"Cert:\\LocalMachine\\My"):
        mod.WindowsCNGDPoPSigner(subject="Missing", store_location="local_machine")

    with pytest.raises(mod.WindowsCNGDPoPError, match=r"Cert:\\LocalMachine\\My"):
        mod.WindowsCNGDPoPSigner(thumbprint="AABBCCDD", store_location="local_machine")

    with pytest.raises(mod.WindowsCNGDPoPError, match=r"Cert:\\CurrentUser\\My"):
        mod.WindowsCNGDPoPSigner(subject="Missing")


def test_acquire_key_bad_keyset_over_ssh_includes_local_machine_hint():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    der_bytes = _make_self_signed_der(ec_key)

    crypt32_mock = mock.MagicMock()
    crypt32_mock.CertOpenStore.return_value = 0x1001
    mod = _load_windows_module(crypt32_mock, mock.MagicMock())
    crypt32_mock.CertFindCertificateInStore.return_value = _make_cert_ptr(mod, der_bytes)
    crypt32_mock.CryptAcquireCertificatePrivateKey.return_value = 0

    with mock.patch.object(ctypes, "get_last_error", return_value=-2146893802, create=True):
        with pytest.raises(mod.WindowsCNGDPoPError) as exc_info:
            mod.WindowsCNGDPoPSigner(subject="DPoP Client")

    assert "-2146893802" in str(exc_info.value)
    assert "store_location='local_machine'" in str(exc_info.value)


def test_acquire_key_failure_in_local_machine_mentions_read_permission():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    der_bytes = _make_self_signed_der(ec_key)

    crypt32_mock = mock.MagicMock()
    crypt32_mock.CertOpenStore.return_value = 0x1001
    mod = _load_windows_module(crypt32_mock, mock.MagicMock())
    crypt32_mock.CertFindCertificateInStore.return_value = _make_cert_ptr(mod, der_bytes)
    crypt32_mock.CryptAcquireCertificatePrivateKey.return_value = 0

    with mock.patch.object(ctypes, "get_last_error", return_value=5, create=True):
        with pytest.raises(mod.WindowsCNGDPoPError, match="Read permission"):
            mod.WindowsCNGDPoPSigner(
                subject="DPoP Client",
                store_location="local_machine",
            )


def test_rsa_thumbprint_signing_and_key_id():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der_bytes = _make_self_signed_der(rsa_key)

    crypt32_mock = mock.MagicMock()
    ncrypt_mock = mock.MagicMock()
    mod = _load_windows_module(crypt32_mock, ncrypt_mock)
    expected_sig = _configure_success_mocks(
        crypt32_mock, ncrypt_mock, lambda: _make_cert_ptr(mod, der_bytes)
    )

    signer = mod.WindowsCNGDPoPSigner(
        thumbprint="00112233445566778899AABBCCDDEEFF00112233",
        key_id="win-machine-rsa",
        store_location="local_machine",
    )

    assert signer.algorithm == "RS256"
    assert signer.public_jwk["kty"] == "RSA"
    assert signer.key_id == "win-machine-rsa"
    assert signer.sign(b"header.payload") == expected_sig
    # Verify PKCS#1 padding flag used for RS256
    assert ncrypt_mock.NCryptSignHash.call_args[0][7] == mod._BCRYPT_PAD_PKCS1
