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
from unittest import mock

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def test_import_fails_on_non_macos():
    sys.modules.pop("dpop_signer_macos_secureenclave", None)
    with mock.patch.object(sys, "platform", "linux"):
        with pytest.raises(
            ImportError, match="dpop_signer_macos_secureenclave is only supported on macOS"
        ):
            importlib.import_module("dpop_signer_macos_secureenclave")


def test_secure_enclave_signer_creates_verifiable_es256_proof():
    if sys.platform != "darwin":
        pytest.skip("ctypes CF/Security bridge test runs on macOS")

    sys.modules.pop("dpop_signer_macos_secureenclave", None)
    mod = importlib.import_module("dpop_signer_macos_secureenclave")

    private_key = ec.generate_private_key(ec.SECP256R1())
    raw_point = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )

    last_der = [b""]

    def fake_bytes_from_cf_data(ref):
        return raw_point if ref == 9001 else last_der[0]

    with (
        mock.patch.object(
            mod.SecureEnclaveDPoPSigner, "_find_identity_key", return_value=1001
        ),
        mock.patch.object(mod._Sec, "SecKeyCopyPublicKey", return_value=2001),
        mock.patch.object(
            mod._Sec, "SecKeyCopyExternalRepresentation", return_value=9001
        ),
        mock.patch.object(mod, "_CF") as cf_mock,
        mock.patch.object(mod, "_cf_data", side_effect=lambda b: b),
        mock.patch.object(mod, "_bytes_from_cf_data", side_effect=fake_bytes_from_cf_data),
        mock.patch.object(mod._Sec, "SecKeyCreateSignature") as sec_sign_mock,
    ):
        def do_sign(key_ref, alg, data, err_ptr):
            last_der[0] = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            return 3001

        sec_sign_mock.side_effect = do_sign
        cf_mock.CFRelease.return_value = None

        signer = mod.SecureEnclaveDPoPSigner(label="dpop-signing")
        assert signer.algorithm == "ES256"
        assert "=" not in signer.public_jwk["x"]
        assert signer.key_id == "se:dpop-signing"

        proof = signer.create_proof("POST", "https://oauth2.googleapis.com/token")
        header = pyjwt.get_unverified_header(proof)
        claims = pyjwt.decode(
            proof, pyjwt.PyJWK.from_dict(header["jwk"]).key, algorithms=["ES256"]
        )
        assert claims["htm"] == "POST"
        del signer
