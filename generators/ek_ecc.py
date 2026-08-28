import hashlib
import hmac

from signer_types import *

from .helpers.ecc import *
from .helpers.shared import *

CR50_ECC_EK_CONTEXT = bytes.fromhex("c2e03193")

def derive_cr50_ek_ecc(eps: bytes) -> ECCKeyPair:
    if not isinstance(eps, bytes) or len(eps) != 32:
        raise ValueError("EPS must be exactly 32 bytes")

    # Cr50 separates ECC derivation from RSA derivation.
    ecc_seed = hmac.new(eps, b"ECC\x00", hashlib.sha256).digest()

    counter = 1

    while counter != 0:
        candidate_bytes = kdfa_sha256(
            key=ecc_seed,
            label=b"ECC key by vendor",
            context_u=CR50_ECC_EK_CONTEXT,

            # Important Cr50 quirk: ecc.c uses memcpy() from uint32_t,
            # so this counter is little-endian on Cr50.
            context_v=counter.to_bytes(4, "little"),

            bits=256,
        )

        # p256_from_bin() interprets this as big-endian.
        candidate = int.from_bytes(candidate_bytes, "big")

        # Mirrors DCRYPTO_p256_key_from_bytes():
        # accept candidate < curve_order - 2, then add one.
        if candidate < N - 2:
            private_scalar = candidate + 1
            public_point = ecc_scalar_multiply(
                private_scalar,
                (GX, GY),
            )

            if public_point is None:
                raise RuntimeError("ECC point inf")

            x, y = public_point

            assert (y * y - (x * x * x + A * x + B)) % P == 0

            return ECCKeyPair(
                d=private_scalar,
                x=x,
                y=y,
                counter=counter,
            )

        counter = (counter + 1) & 0xFFFFFFFF

    raise RuntimeError("ECC ctr wrap 32bit")