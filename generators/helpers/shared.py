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

def kdfe_sha256(
    z: bytes,
    label: bytes,
    party_u_info: bytes,
    party_v_info: bytes,
    bits: int,
) -> bytes:
    wanted = (bits + 7) // 8
    output = bytearray()
    counter = 1

    while len(output) < wanted:
        message = (
            struct.pack(">I", counter)
            + z
            + label + b"\x00"
            + party_u_info
            + party_v_info
        )

        output += hashlib.sha256(message).digest()
        counter += 1

    return bytes(output[:wanted])

def read_tpm2b(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("missing len")

    size = struct.unpack_from(">H", data, offset)[0]
    start = offset + 2
    end = start + size

    if end > len(data):
        raise ValueError("trunc data")

    return data[start:end], end

def write_tpm2b(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data

def create_fake_qualified_signer(name: bytes) -> bytes:
    # The SRK is never sent to the PCA, so this is useless to the PCA.
    # Generate a fake qualifiedsigner.
    synthetic_srk_qn = (
        b"\x00\x0b"
        + hashlib.sha256(b"software-test-srk").digest()
    )

    return (
        b"\x00\x0b"
        + hashlib.sha256(
            synthetic_srk_qn + name
        ).digest()
    )
