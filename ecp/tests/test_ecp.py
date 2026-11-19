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
import json
from unittest import mock

import jwt as pyjwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from dpop_signer_ecp import ECPDPoPSigner, public_key_to_jwk


def _self_signed_pem(key):
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "ECP Test")]
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
    return cert.public_bytes(serialization.Encoding.PEM)


def test_public_key_to_jwk_ec_and_rsa():
    ec_pub = ec.generate_private_key(ec.SECP256R1()).public_key()
    alg, jwk, crv_size = public_key_to_jwk(ec_pub)
    assert alg == "ES256"
    assert crv_size == 32
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"
    assert "=" not in jwk["x"] and "=" not in jwk["y"]

    rsa_pub = rsa.generate_private_key(65537, 2048).public_key()
    alg_r, jwk_r, crv_r = public_key_to_jwk(rsa_pub)
    assert alg_r == "RS256"
    assert crv_r == 0
    assert jwk_r["kty"] == "RSA"
    assert "=" not in jwk_r["n"] and "=" not in jwk_r["e"]


def test_ecp_signer_creates_verifiable_es256_proof(tmp_path):
    private_key = ec.generate_private_key(ec.SECP256R1())
    cert_pem = _self_signed_pem(private_key)

    fake_lib_file = tmp_path / "libecp.so"
    fake_lib_file.write_bytes(b"")
    cfg_file = tmp_path / "certificate_config.json"
    cfg_file.write_text(json.dumps({"libs": {"ecp_client": str(fake_lib_file)}}))

    fake_lib = mock.MagicMock()

    def fake_get_cert(cfg_bytes, buf, buf_len):
        if buf is None:
            return len(cert_pem)
        ctypes.memmove(buf, cert_pem, len(cert_pem))
        return len(cert_pem)

    def fake_sign(cfg_bytes, digest_ptr, digest_len, sig_buf, sig_buf_len):
        digest = ctypes.string_at(digest_ptr, digest_len)
        # Re-sign prehashed? Sign directly with private key on raw data in sign test.
        from cryptography.hazmat.primitives.asymmetric import utils

        der_sig = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        ctypes.memmove(sig_buf, der_sig, len(der_sig))
        return len(der_sig)

    fake_lib.GetCertPemForPython.side_effect = fake_get_cert
    fake_lib.SignForPython.side_effect = fake_sign

    with mock.patch("dpop_signer_ecp._load_signer_lib", return_value=fake_lib):
        signer = ECPDPoPSigner(config_path=str(cfg_file))

    proof = signer.create_proof("POST", "https://oauth2.googleapis.com/token")
    header = pyjwt.get_unverified_header(proof)
    assert header["alg"] == "ES256"
    claims = pyjwt.decode(
        proof, pyjwt.PyJWK.from_dict(header["jwk"]).key, algorithms=["ES256"]
    )
    assert claims["htm"] == "POST"
    assert signer.key_id == f"ecp:{cfg_file.name}"


def test_ecp_unsupported_curve_raises():
    p384_pub = ec.generate_private_key(ec.SECP384R1()).public_key()
    with pytest.raises(ValueError, match="Unsupported curve"):
        public_key_to_jwk(p384_pub)
