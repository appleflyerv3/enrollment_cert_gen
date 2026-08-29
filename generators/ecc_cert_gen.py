"""
Derived from Cr50 source code, converted for use
in Python on host machines.
"""

import hashlib
import hmac
import secrets

from signer_types import *

from .helpers.ecc import *
from .helpers.shared import *

# Canonically marshalled TPMT_PUBLIC template used before key generation:
#   type             = TPM_ALG_ECC
#   nameAlg          = TPM_ALG_SHA256
#   attributes       = fixedTPM | fixedParent | sensitiveDataOrigin |
#                      userWithAuth | noDA | restricted | sign
#   symmetric        = TPM_ALG_NULL
#   scheme           = ECDSA-SHA256
#   curve            = NIST P-256
#   KDF              = TPM_ALG_NULL
#   unique.x/y       = empty
AIK_TEMPLATE = bytes.fromhex(
    "0023000b00050472000000100018000b0003001000000000"
)

ENROLLMENT_KEY_TEMPLATE = bytes.fromhex(
    "0023000b000404720000001000100003001000000000"
)

def create_cr50_ecc_signing_key(template: bytes):
    # Cr50 uses CryptGenerateRandom(PRIMARY_SEED_SIZE).
    local_creation_seed = secrets.token_bytes(32)

    # Cr50 separates the ECC derivation tree from RSA.
    ecc_seed = hmac.new(local_creation_seed, b"ECC\x00", hashlib.sha256).digest()

    # Signing keys start with counter 1.
    counter = 1

    while counter != 0:
        candidate_bytes = kdfa_sha256(
            key=ecc_seed,
            label=b"ECC key by vendor",
            # TPM Name = nameAlg || hash(TPMT_PUBLIC)
            context_u=b"\x00\x0b" + hashlib.sha256(template).digest(),

            # Important Cr50 quirk: ecc.c uses memcpy() from uint32_t,
            # so this counter is little-endian on Cr50.
            context_v=counter.to_bytes(4, "little"),

            bits=256,
        )

        candidate = int.from_bytes(candidate_bytes, "big")

        # Mirrors DCRYPTO_p256_key_from_bytes():
        # accept candidate < curve_order - 2, then add one.
        if candidate < N - 2:
            private_scalar = candidate + 1
            public_x, public_y = ecc_scalar_multiply(private_scalar, G)

            final_public_area = (
                AIK_TEMPLATE[:-4]
                + (32).to_bytes(2, "big")
                + public_x.to_bytes(32, "big")
                + (32).to_bytes(2, "big")
                + public_y.to_bytes(32, "big")
            )

            final_name = (
                b"\x00\x0b"
                + hashlib.sha256(final_public_area).digest()
            )

            return {
                "key_pair": ECCKeyPair(
                    d=private_scalar,
                    x=public_x,
                    y=public_y,
                ),
                "template_name": b"\x00\x0b" + hashlib.sha256(template).digest(),
                "tpmt_public": final_public_area,
                "key_name": final_name,
            }

        counter = (counter + 1) & 0xFFFFFFFF

    raise RuntimeError("ECC ctr wrap 32bit")

def create_cr50_aik() -> dict:
    result = create_cr50_ecc_signing_key(AIK_TEMPLATE)
    result["aik_name"] = result["key_name"]
    return result


def create_cr50_enrollment_key() -> dict:
    result = create_cr50_ecc_signing_key(ENROLLMENT_KEY_TEMPLATE)
    result["enrollment_key_name"] = result["key_name"]
    return result