import sys

from ek_certs import PROD_RO_CERT_REGION, PROD_ENDORSEMENT_SEED
from broker import derive_ek_info, derive_aik_info, derive_enrollment_key_info

def main() -> int:
    ek_rsa_keypair, ek_rsa_cert, ek_ecc_keypair, ek_ecc_cert = derive_ek_info(PROD_RO_CERT_REGION, PROD_ENDORSEMENT_SEED)

    aik_keypair_info, aik_certificate = derive_aik_info(ek_ecc_keypair, ek_ecc_cert)

    enrollment_key_keypair_info, enrollment_key_certificate, enrollment_key_intermediate_ca = derive_enrollment_key_info(aik_keypair_info, aik_certificate)

    with open("enrollment_certificate.der", "wb") as file:
        file.write(enrollment_key_certificate)
    
sys.exit(main())