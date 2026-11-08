"""Ephemeral (in-memory) DPoP signer for testing.

Generates a fresh ECDSA P-256 key in memory on every instantiation.
The private key is never written to disk and is different each time
the signer is created.

This backend is **expected to fail** when used against a DPoP-bound
refresh token.  It produces a valid DPoP proof signed by the wrong
key, which the server must reject.  If a refresh succeeds with this
backend, either:

1. The server is not enforcing DPoP for this refresh token (the token
   was never bound, or enforcement is disabled).
2. The server is accepting proofs from any valid key without checking
   the thumbprint -- a server-side bug.
3. The ephemeral key collided with the real key's thumbprint -- odds
   of 1 in 2^128, comparable to guessing a specific atom in the
   observable universe.

Usage::

    from dpop_signer_ephemeral import EphemeralDPoPSigner

    signer = EphemeralDPoPSigner()
    # signer.thumbprint is different every time
"""

from cryptography.hazmat.primitives.asymmetric import ec

from google.auth.dpop import SoftwareDPoPSigner


class EphemeralDPoPError(Exception):
    """Error from the ephemeral DPoP signer."""


class EphemeralDPoPSigner(SoftwareDPoPSigner):
    """A DPoP signer that generates a fresh P-256 key on every instantiation.

    The key exists only in memory for the lifetime of this object.  It is
    never persisted and will be different on every construction.

    This backend is **expected to fail** against DPoP-bound tokens.  A
    successful refresh means the server is not enforcing DPoP binding --
    unless you have beaten 1-in-2^128 odds on a key collision.
    """

    def __init__(self, key_id=None):
        """
        Args:
            key_id (Optional[str]): Optional key identifier.
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        super().__init__(private_key, key_id=key_id)
