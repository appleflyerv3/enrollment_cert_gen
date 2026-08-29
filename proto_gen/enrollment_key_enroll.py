import secrets
import proto_gen.compiled.attestation_ca_pb2 as pca_server_proto

def craft_enrollment_key_protobuf_request(aik_certificate: bytes, signed_enrollment_key_info: dict):
    request = pca_server_proto.AttestationCertificateRequest()

    request.tpm_version = pca_server_proto.TPM_2_0
    request.identity_credential = aik_certificate
    request.certified_public_key = signed_enrollment_key_info["certified_public_key"]
    request.certified_key_info = signed_enrollment_key_info["certified_key_info"]
    request.certified_key_proof = signed_enrollment_key_info["certified_key_proof"]
    request.message_id = secrets.token_bytes(20)
    request.profile = pca_server_proto.ENTERPRISE_ENROLLMENT_CERTIFICATE

    return request.SerializeToString(deterministic=True)