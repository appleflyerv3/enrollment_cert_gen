import secrets
import proto.attestation_ca_pb2 as ca

def craft_enrollment_key_protobuf_request(aik_certificate: bytes, signed_enrollment_key_info: dict):
    request = ca.AttestationCertificateRequest()
    
    request.tpm_version = ca.TPM_2_0
    request.identity_credential = aik_certificate
    request.certified_public_key = signed_enrollment_key_info["certified_public_key"]
    request.certified_key_info = signed_enrollment_key_info["certified_key_info"]
    request.certified_key_proof = signed_enrollment_key_info["certified_key_proof"]
    request.message_id = secrets.token_bytes(20)
    request.profile = ca.ENTERPRISE_ENROLLMENT_CERTIFICATE

    return request.SerializeToString(deterministic=True)