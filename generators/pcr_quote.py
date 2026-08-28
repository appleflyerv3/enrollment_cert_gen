import hashlib
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018
TPM_ALG_SHA256 = 0x000B


def tpm2b(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def create_fake_qualified_signer(aik_name: bytes) -> bytes:
    # The SRK is never sent to the PCA, so this is useless to the PCA.
    # Generate a fake qualifiedsigner.
    synthetic_srk_qn = (
        b"\x00\x0b"
        + hashlib.sha256(b"software-test-srk").digest()
    )

    return (
        b"\x00\x0b"
        + hashlib.sha256(
            synthetic_srk_qn + aik_name
        ).digest()
    )


def tpm2_pcr_quote(
    aik_info: dict,
    pcr_index: int,
    pcr_value: bytes,
    source_hint: bytes | None = None,
) -> dict[str, bytes]:
    if len(pcr_value) != 32:
        raise ValueError("PCR value must be 32 bytes")

    if not 0 <= pcr_index < 24:
        raise ValueError("PCR index must be 0-23")

    aik = aik_info["key_pair"]

    # SHA-256 PCR bank selection.
    selection = bytearray(3)
    selection[pcr_index // 8] |= 1 << (pcr_index % 8)

    # For one selected PCR.
    pcr_digest = hashlib.sha256(pcr_value).digest()

    # TPML_PCR_SELECTION followed by TPM2B_DIGEST.
    quote_info = (
        struct.pack(">I", 1)                 # selection count
        + struct.pack(">H", TPM_ALG_SHA256)
        + bytes([3])                         # sizeofSelect
        + bytes(selection)
        + tpm2b(pcr_digest)
    )

    qualified_signer = create_fake_qualified_signer(
        aik_info["aik_name"]
    )

    # Serialized TPMS_ATTEST. ChromeOS stores this without the outer
    # TPM2B_ATTEST size prefix.
    quoted_data = (
        struct.pack(">I", TPM_GENERATED_VALUE)
        + struct.pack(">H", TPM_ST_ATTEST_QUOTE)
        + tpm2b(qualified_signer)
        + tpm2b(b"") # ChromeOS provides an empty qualifyingData
        + struct.pack(
            ">QIIB",
            0, # clock (no obf)
            0, # resetCount | shProof
            0, # restartCount | shProof
            1, # safe (no obf)
        )
        + struct.pack(">Q", 0) # firmwareVersion | shProof
        + quote_info
    )

    private_key = ec.derive_private_key(
        aik.d,
        ec.SECP256R1(),
    )

    public_numbers = private_key.public_key().public_numbers()
    if (public_numbers.x, public_numbers.y) != (aik.x, aik.y):
        raise ValueError("AIK private/public keys do not match")

    # DER-encoded ECDSA signature, matching Quote.quote.
    signature = private_key.sign(
        quoted_data,
        ec.ECDSA(hashes.SHA256()),
    )

    quote = {
        "quote": signature,
        "quoted_data": quoted_data,
        "quoted_pcr_value": pcr_value,
    }

    if source_hint:
        quote["pcr_source_hint"] = source_hint

    return quote