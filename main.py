import sys
import hashlib
import hmac
import requests

import proto.attestation_ca_pb2 as ca

from ek_certs import *
from generators.ek_cert import verify_eps_matches_ro_certs, extract_ek_cert
from generators.ek_rsa import derive_cr50_ek_rsa
from generators.ek_ecc import derive_cr50_ek_ecc
from generators.aik_ecc import create_cr50_aik
from generators.encrypt_ek_cert_aca import encrypt_ek_certificate_for_pca
from generators.pcr_quote import tpm2_pcr_quote
from generators.extract_aik_cert import unwrap_pca_aik_certificate
from signer_types import RSAKeyPair, ECCKeyPair

from proto.aik_enroll import craft_aik_enrollment_protobuf_request

KEY_MATERIAL_PRINTS = False

def send_aik_enrollment_request(request_bytes: bytes):
    response = requests.post(
        "https://chromeos-ca.gstatic.com/enroll",
        data=request_bytes,
        headers={"Content-Type": "application/octet-stream"},
        timeout=30,
    )
    response.raise_for_status()

    reply = ca.AttestationEnrollmentResponse()
    reply.ParseFromString(response.content)

    return reply

def derive_ek_info(ro_certs: bytes, eps: bytes) -> tuple[RSAKeyPair, bytes, ECCKeyPair, bytes]:
    # Ensure the HMAC in the EPS verifies the given certificate region,
    # with the EPS as a key.
    eps_match_ro_certs = verify_eps_matches_ro_certs(ro_certs, eps)
    if not eps_match_ro_certs:
        print("ro_certs does not correspond to eps.")
        return 1

    print("ro_certs corresponds to eps.")

    # From the EPS, generate EK RSA keypair
    ek_rsa_keypair: RSAKeyPair = derive_cr50_ek_rsa(eps)
    print("Derived EK RSA keypair")

    if KEY_MATERIAL_PRINTS:
        ek_rsa_public_modulus = ek_rsa_keypair.n.to_bytes(2048 // 8, "big")
        print(ek_rsa_public_modulus)

    # Extract the EK RSA certificate from the RO_CERT_REGION
    ek_rsa_cert = extract_ek_cert(129, ro_certs)
    if not ek_rsa_cert:
        print("Failed to extract EK RSA certificate")
        return 1

    print("Extracted EK RSA certificate")

    # From the EPS, generate EK ECC keypair
    ek_ecc_keypair: ECCKeyPair = derive_cr50_ek_ecc(eps)
    print("Derived EK ECC keypair")

    if KEY_MATERIAL_PRINTS:
        ek_sec1_p256_point = ek_ecc_keypair.public_bytes
        print(ek_sec1_p256_point)

    # Extract the EK ECC certificate from the RO_CERT_REGION
    ek_ecc_cert = extract_ek_cert(130, ro_certs)
    if not ek_ecc_cert:
        print("Failed to extract EK ECC certificate")
        return 1

    print("Extracted EK ECC certificate")

    return ek_rsa_keypair, ek_rsa_cert, ek_ecc_keypair, ek_ecc_cert

def derive_aik_info(ek_ecc_keypair: ECCKeyPair, ek_ecc_certificate: bytes) -> None:
    # AttestationEnrollmentRequest = {
    #     "tpm_version": 2, # TPM version
    #     "encrypted_endorsement_credential": None, # DER EK cert, encrypted
    #     "identity_public_key": None, # AIK public space
    #     "pcr0_quote": None, # Signed PCR0
    #     "pcr1_quote": None, # Signed PCR1
    #     "enterprise_enrollment_nonce": None, # Chromebook DEN
    # }

    # First, let's create the AIK keypair
    aik_keypair_info = create_cr50_aik()

    # Next, encrypt the EK ECC certitificate
    encrypted_ek_cert = encrypt_ek_certificate_for_pca(ek_ecc_certificate)

    pcr0_value_verified = bytes.fromhex(
        "89eaf35134b4b3c649f44c0c765b96aeab8bb34ee83cc7a683c4e53d1581c8c7"
    )
    # Now, generate PCR0 and PCR1 quotes
    pcr0_quote = tpm2_pcr_quote(aik_keypair_info, 0, pcr0_value_verified, source_hint=None)

    hwid_bytes = "CRAASKANA-QRII B2B-B3B-B3A-C3C-63A".encode("ascii")
    hwid_digest = hashlib.sha256(hwid_bytes).digest()
    # Extend operation of HWID digest over PCR1 empty value
    pcr1_value = hashlib.sha256(b'\x00' * 32 + hwid_digest).digest()
    pcr1_quote = tpm2_pcr_quote(aik_keypair_info, 1, pcr1_value, source_hint=hwid_bytes)

    stable_device_secret = bytes.fromhex(
        "e82ea8ebdc73184410729e315adfa41b31add5b8d8f9e04521e9ffa90bc2ad1c"
    )
    den = hmac.new(
        b"attestation_based_enrollment",
        stable_device_secret,
        hashlib.sha256
    ).digest()

    # Finally, craft the AIK enrollment request
    protorq = craft_aik_enrollment_protobuf_request(
        2, # TPM_2_0
        aik_keypair_info["tpmt_public"],
        encrypted_ek_cert,
        pcr0_quote,
        pcr1_quote,
        den
    )

    # Send the AIK enrollment request to the PCA server.
    print("AIK keypair enrollment request sent to PCA")
    aik_encrypted_cert_reply = send_aik_enrollment_request(protorq)
    print("Recieved AIK certificate from PCA")

    # Lastly, unwrap the encrypted AIK certificate sent back by the PCA.
    aik_certificate = unwrap_pca_aik_certificate(
        aik_encrypted_cert_reply.encrypted_identity_credential,
        ek_ecc_certificate,
        ek_ecc_keypair,
        aik_keypair_info
    )
    print("Unwrapped AIK certificate with EK keypair and cert")

    return aik_keypair_info, aik_certificate

def main() -> int:
    ek_rsa_keypair, ek_rsa_cert, ek_ecc_keypair, ek_ecc_cert = derive_ek_info(PROD_RO_CERT_REGION, PROD_ENDORSEMENT_SEED)

    aik_keypair_info, aik_certificate = derive_aik_info(ek_ecc_keypair, ek_ecc_cert)
    
sys.exit(main())