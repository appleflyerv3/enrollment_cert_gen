import sys

from ek_certs import *
from generators.ek_cert import verify_eps_matches_ro_certs, extract_ek_cert
from generators.ek_rsa import derive_cr50_ek_rsa
from generators.ek_ecc import derive_cr50_ek_ecc
from signer_types import RSAKeyPair, ECCKeyPair


KEY_MATERIAL_PRINTS = True

def main() -> int:
    # Ensure the HMAC in the PROD_RO_CERT_REGION verifies the above certificate region,
    # with the EPS as a key.
    eps_match_ro_certs = verify_eps_matches_ro_certs(PROD_RO_CERT_REGION, PROD_ENDORSEMENT_SEED)
    if not eps_match_ro_certs:
        print("PROD_RO_CERT_REGION does not correspond to PROD_ENDORSEMENT_SEED.")
        return 1

    print("PROD_RO_CERT_REGION corresponds to PROD_ENDORSEMENT_SEED.")

    # From the EPS, generate EK RSA keypair
    ek_rsa_keypair: RSAKeyPair = derive_cr50_ek_rsa(PROD_ENDORSEMENT_SEED)
    print("Derived EK RSA keypair")

    if KEY_MATERIAL_PRINTS:
        ek_rsa_public_modulus = ek_rsa_keypair.n.to_bytes(2048 // 8, "big")
        print(ek_rsa_public_modulus)

    # Extract the EK RSA certificate from the RO_CERT_REGION
    ek_rsa_cert = extract_ek_cert(129, PROD_RO_CERT_REGION)
    if not ek_rsa_cert:
        print("Failed to extract EK RSA certificate")
        return 1

    print("Extracted EK RSA certificate")

    # From the EPS, generate EK ECC keypair
    ek_ecc_keypair: ECCKeyPair = derive_cr50_ek_ecc(PROD_ENDORSEMENT_SEED)
    print("Derived EK ECC keypair")

    if KEY_MATERIAL_PRINTS:
        ek_sec1_p256_point = ek_ecc_keypair.public_bytes
        print(ek_sec1_p256_point)

    # Extract the EK RSA certificate from the RO_CERT_REGION
    ek_rsa_cert = extract_ek_cert(130, PROD_RO_CERT_REGION)
    if not ek_rsa_cert:
        print("Failed to extract EK RSA certificate")
        return 1

    print("Extracted EK RSA certificate")
                             
sys.exit(main())