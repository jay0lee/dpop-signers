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
from cryptography.hazmat.primitives.asymmetric import ec, utils


def _fake_tpm2_pytss():
    mod = types.ModuleType("tpm2_pytss")
    mod.TPM2_ALG = types.SimpleNamespace(
        ECC=0x0023, RSA=0x0001, ECDSA=0x0018, RSASSA=0x0014, SHA256=0x000B
    )
    mod.ESYS_TR = types.SimpleNamespace(PASSWORD=1)
    mod.TPM2_RH = types.SimpleNamespace(NULL=2)
    mod.TPM2_ST = types.SimpleNamespace(HASHCHECK=3)

    class _Scheme:
        def __init__(self, scheme=None):
            self.scheme = scheme
            self.details = types.SimpleNamespace(any=types.SimpleNamespace(hashAlg=None))

    mod.TPMT_SIG_SCHEME = _Scheme
    mod.TPMT_TK_HASHCHECK = lambda **kw: kw
    mod.TPM2B_DIGEST = lambda d: d
    mod.ESAPI = mock.MagicMock()
    return mod


def test_linux_tpm_es256_jwk_and_sign():
    private_key = ec.generate_private_key(ec.SECP256R1())
    nums = private_key.public_key().public_numbers()

    fake_tpm2 = _fake_tpm2_pytss()
    pub = types.SimpleNamespace(
        publicArea=types.SimpleNamespace(
            type=fake_tpm2.TPM2_ALG.ECC,
            parameters=types.SimpleNamespace(eccDetail=types.SimpleNamespace(curveID=0x0003)),
            unique=types.SimpleNamespace(
                ecc=types.SimpleNamespace(
                    x=nums.x.to_bytes(32, "big"),
                    y=nums.y.to_bytes(32, "big"),
                )
            ),
        )
    )

    ectx = mock.MagicMock()
    ectx.read_public.return_value = (pub, None, None)

    def fake_sign(key_handle, digest, in_scheme, validation, session1):
        der = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        return types.SimpleNamespace(
            sigAlg=fake_tpm2.TPM2_ALG.ECDSA,
            signature=types.SimpleNamespace(
                ecdsa=types.SimpleNamespace(
                    signatureR=r.to_bytes(32, "big"),
                    signatureS=s.to_bytes(32, "big"),
                )
            ),
        )

    ectx.sign.side_effect = fake_sign
    fake_tpm2.ESAPI.return_value = ectx

    sys.modules.pop("dpop_signer_linux_tpm", None)
    with mock.patch.dict(sys.modules, {"tpm2_pytss": fake_tpm2}):
        mod = importlib.import_module("dpop_signer_linux_tpm")
        signer = mod.LinuxTPMDPoPSigner(handle=0x81000001)
        assert signer.algorithm == "ES256"
        assert "=" not in signer.public_jwk["x"]
        assert signer.key_id == "tpm:0x81000001"

        proof = signer.create_proof("POST", "https://oauth2.googleapis.com/token")
        header = pyjwt.get_unverified_header(proof)
        claims = pyjwt.decode(
            proof, pyjwt.PyJWK.from_dict(header["jwk"]).key, algorithms=["ES256"]
        )
        assert claims["htm"] == "POST"
