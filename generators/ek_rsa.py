"""
Derived from Cr50 source code, converted for use
in Python on host machines.
"""

import hashlib
import hmac
import struct

from signer_types import *

from .helpers.rsa import *
from .helpers.shared import *

# This is the SHA-256 hash of the RSA template from the TCG
# EK Credential Profile spec.
CR50_RSA_EK_NAME = bytes.fromhex(
    "68d1a241fb272f0390bfd0428dadeeb0"
    "2bf4a1cd46ab6c391ba31f5187068e6a"
)

def derive_cr50_ek_rsa(eps: bytes) -> RSAKeyPair:
    if not isinstance(eps, bytes):
        raise TypeError("EPS not of type bytes")

    if len(eps) != 32:
        raise TypeError("EPS must be 32 bytes long")

    rsa_seed = hmac.new(eps, b"RSA\x00", hashlib.sha256).digest()
    label = b"RSA key by vendor"

    counter = 1
    primes = []
    for _ in range(2):
        # generate_prime
        for _ in range(3): # MAX_GENERATE_ATTEMPTS
            generated = kdfa_sha256(
                key=rsa_seed,
                label=label,
                context_u=CR50_RSA_EK_NAME,
                context_v=struct.pack(">I", counter),
                bits=2048 // 2,
            )

            counter += 1
            prime = cr50_prime(generated, 65537)

            if prime is not None:
                primes.append(prime)
                break
        else:
            raise RuntimeError("CRYPT_FAIL")

    p, q = primes
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(65537, -1, phi)

    return RSAKeyPair(n, 65537, d, p, q)
