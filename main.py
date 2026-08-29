import sys
import hashlib
import hmac
import uuid
from ek_certs import PROD_RO_CERT_REGION, PROD_ENDORSEMENT_SEED
from cert_broker import derive_ek_info, derive_aik_info, derive_enrollment_key_info

from dmserver_utils import dmserver_device_register_certificate_based

SAVE_ENROLLMENT_CERT = True

PCR0_VALUES = {
    "verified": "89eaf35134b4b3c649f44c0c765b96aeab8bb34ee83cc7a683c4e53d1581c8c7",
    "developer": "23e14dd9bb51a50e16911f7e11df1e1aaf0b17134dc739c5653607a1ec8dd37a"
}

def derive_aik_info_wrapper(
    ek_ecc_keypair: dict, 
    ek_ecc_cert: bytes, 
    bootmode: str, 
    hwid: str, 
    stable_device_secret: str
):
    # PCR0 value(we already know it directly, no need to calculate anything)
    pcr0_value = bytes.fromhex(PCR0_VALUES[bootmode])

    # PCR1 value derivation
    hwid_bytes = hwid.encode("ascii")
    hwid_digest = hashlib.sha256(hwid_bytes).digest()
    # Extend operation of HWID digest over PCR1 empty value
    pcr1_value = hashlib.sha256(b'\x00' * 32 + hwid_digest).digest()

    # enterprise_enrollment_nonce derivation
    stable_device_secret_bytes = bytes.fromhex(stable_device_secret)
    den = hmac.new(
        b"attestation_based_enrollment",
        stable_device_secret_bytes,
        hashlib.sha256
    ).digest()

    aik_keypair_info, aik_certificate = derive_aik_info(
        ek_ecc_keypair=ek_ecc_keypair, 
        ek_ecc_certificate=ek_ecc_cert, 
        pcr0_value=pcr0_value, 
        pcr1_value=pcr1_value, 
        pcr1_source_hint=hwid_bytes,
        enterprise_enrollment_nonce=den
    )

    return aik_keypair_info, aik_certificate

def main() -> int:
    ek_rsa_keypair, ek_rsa_cert, ek_ecc_keypair, ek_ecc_cert = derive_ek_info(PROD_RO_CERT_REGION, PROD_ENDORSEMENT_SEED)

    aik_keypair_info, aik_certificate = derive_aik_info_wrapper(
        ek_ecc_keypair,
        ek_ecc_cert,
        bootmode="verified", # "verified" or "developer"
        hwid="CRAASKANA-QRII B2B-B3B-B3A-C3C-63A",
        stable_device_secret="e9c429208a505939bb3b2c7774c4e57e27114dc78276a5eddb3643ea5eda8e13",
    )

    enrollment_key_keypair_info, enrollment_key_certificate, enrollment_key_intermediate_ca = derive_enrollment_key_info(aik_keypair_info, aik_certificate)

    if SAVE_ENROLLMENT_CERT:
        with open("enrollment_certificate.der", "wb") as file:
            file.write(enrollment_key_certificate)

    # Send the request to get DMToken based on certificate
    print("Registering device with PCA enrollment certificate")
    dmserver_device_register_certificate_based(
        enrollment_key_keypair_info,
        enrollment_key_certificate,
        enrollment_key_intermediate_ca,
        "e9c429208a505939bb3b2c7774c4e57e27114dc78276a5eddb3643ea5eda8e13",
        "FUCKULXRD",
        "CRAASKANA-QRII B2B-B3B-B3A-C3C-63A",
        "GSKT",
        str(uuid.uuid4())
    )
    print(str(uuid.uuid4()))
    
sys.exit(main())