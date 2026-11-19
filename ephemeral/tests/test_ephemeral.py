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

import json

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec

from dpop_signer_ephemeral import EphemeralDPoPSigner


def test_ephemeral_signer_generates_distinct_keys():
    s1 = EphemeralDPoPSigner()
    s2 = EphemeralDPoPSigner(key_id="eph-1")

    assert s1.algorithm == "ES256"
    assert s1.key_id is None
    assert s2.key_id == "eph-1"
    assert s1.thumbprint != s2.thumbprint


def test_ephemeral_signer_proof_verifies_against_embedded_jwk():
    signer = EphemeralDPoPSigner()
    proof = signer.create_proof("POST", "https://oauth2.googleapis.com/token")

    header = pyjwt.get_unverified_header(proof)
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    assert "kid" not in header

    jwk = pyjwt.PyJWK.from_dict(header["jwk"])
    claims = pyjwt.decode(proof, jwk.key, algorithms=["ES256"])
    assert claims["htm"] == "POST"
    assert claims["htu"] == "https://oauth2.googleapis.com/token"
    assert isinstance(jwk.key, ec.EllipticCurvePublicKey)
    assert json.loads(json.dumps(header["jwk"])) == signer.public_jwk
