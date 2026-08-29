import secrets
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from .helpers.shared import write_tpm2b, create_fake_qualified_signer

TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_CERTIFY = 0x8017

def tpm2_certify(
    aik_info: dict,
    enrollment_key_info: dict,
) -> dict:
    qualifying_data = secrets.token_bytes(20)

    aik = aik_info["key_pair"]
    aik_name = aik_info["aik_name"]
    enrollment_name = enrollment_key_info["enrollment_key_name"]

    aik_qualified_name = create_fake_qualified_signer(
        aik_name,
    )
    enrollment_qualified_name = create_fake_qualified_signer(
        enrollment_name,
    )

    certified_key_info = (
        struct.pack(
            ">IH",
            TPM_GENERATED_VALUE,
            TPM_ST_ATTEST_CERTIFY,
        )
        + write_tpm2b(aik_qualified_name)
        + write_tpm2b(qualifying_data) # garbage qualifyingData
        + struct.pack(">Q", 0) # clock (no obf)
        + struct.pack(">I", 0) # resetCount | shProof
        + struct.pack(">I", 0) # restartCount | shProof
        + struct.pack(">B", 1) # safe (no obf)
        + struct.pack(">Q", 0) # firmwareVersion | shProof
        + write_tpm2b(enrollment_name) # TPMS_CERTIFY_INFO.name
        + write_tpm2b(enrollment_qualified_name)
    )

    aik_private_key = ec.derive_private_key(
        aik.d,
        ec.SECP256R1(),
    )

    certified_key_proof = aik_private_key.sign(
        certified_key_info,
        ec.ECDSA(hashes.SHA256()),
    )

    return {
        "certified_public_key": enrollment_key_info["tpmt_public"],
        "certified_key_info": certified_key_info,
        "certified_key_proof": certified_key_proof,
        "qualifying_data": qualifying_data,
        "enrollment_key_name": enrollment_name,
        "enrollment_key_qualified_name": enrollment_qualified_name,
    }