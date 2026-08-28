"""
Derived from Cr50 source code.
Most of these are from ChatGPT.
"""

import struct
import hmac
import hashlib

from signer_types import *

# Implement TPM2 library __cpri__KDF function.
def kdfa_sha256(
    key: bytes,
    label: bytes,
    context_u: bytes,
    context_v: bytes,
    bits: int,
) -> bytes:
    wanted = (bits + 7) // 8
    output = bytearray()
    iteration = 1

    while len(output) < wanted:
        message = (
            struct.pack(">I", iteration)
            + label + b"\x00"
            + context_u + context_v
            + struct.pack(">I", bits)
        )

        output += hmac.new(key, message, hashlib.sha256).digest()

        iteration += 1

    return bytes(output[:wanted])