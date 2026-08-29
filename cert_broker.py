"""
Main code to broker certificates based on the EK certificate.
Simplify interaction with the PCA server.
"""
from generators.ek_cert import verify_eps_matches_ro_certs, extract_ek_cert
from generators.ek_rsa import derive_cr50_ek_rsa
from generators.ek_ecc import derive_cr50_ek_ecc
from generators.ecc_cert_gen import create_cr50_aik, create_cr50_enrollment_key
from generators.encrypt_ek_cert_aca import encrypt_ek_certificate_for_pca
from generators.tpm2_pcr_quote import tpm2_pcr_quote
from generators.tpm2_certify import tpm2_certify
from generators.extract_aik_cert import unwrap_pca_aik_certificate
from signer_types import RSAKeyPair, ECCKeyPair
from server_requester import send_aik_enrollment_request, send_enrollment_key_sign_request

from proto_gen.aik_enroll import craft_aik_enrollment_protobuf_request
from proto_gen.enrollment_key_enroll import craft_enrollment_key_protobuf_request

KEY_MATERIAL_PRINTS = False

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

def derive_aik_info(
    ek_ecc_keypair: ECCKeyPair, ek_ecc_certificate: bytes,
    pcr0_value: bytes,
    pcr1_value: bytes,
    pcr1_source_hint: bytes,
    enterprise_enrollment_nonce: bytes, # aka DEN
) -> tuple[dict, bytes]:
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

    # Now, generate PCR0 and PCR1 quotes
    pcr0_quote = tpm2_pcr_quote(aik_keypair_info, 0, pcr0_value, source_hint=None)
    pcr1_quote = tpm2_pcr_quote(aik_keypair_info, 1, pcr1_value, source_hint=pcr1_source_hint)

    # Finally, craft the AIK enrollment request
    protorq = craft_aik_enrollment_protobuf_request(
        2, # TPM_2_0
        aik_keypair_info["tpmt_public"],
        encrypted_ek_cert,
        pcr0_quote,
        pcr1_quote,
        enterprise_enrollment_nonce
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

def derive_enrollment_key_info(aik_keypair_info: dict, aik_certificate: bytes):
    enrollment_key_keypair_info = create_cr50_enrollment_key()
    print("Derived Cr50 enrollment certificate keypair")

    signed_enrollment_key_info = tpm2_certify(aik_keypair_info, enrollment_key_keypair_info)
    print("Signed Cr50 enrollment cert keypair with AIK")

    protorq = craft_enrollment_key_protobuf_request(aik_certificate, signed_enrollment_key_info)

    print("Requesting enrollment certificate from PCA...")
    response = send_enrollment_key_sign_request(protorq)
    print("Obtained enrollment certificate from PCA")

    return enrollment_key_keypair_info, response.certified_key_credential, response.intermediate_ca_cert
