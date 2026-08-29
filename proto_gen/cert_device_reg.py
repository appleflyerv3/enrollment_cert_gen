import secrets

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import proto_gen.compiled.device_management_backend_pb2 as dmserver_proto

def craft_certificate_based_registration_data(
    enrollment_cert_der: bytes,
    intermediate_cert_der: bytes,
    machine_id: str,
    machine_model: str,
    brand_code: str,
    current_state_key: bytes,
) -> bytes:
    leaf_pem = x509.load_der_x509_certificate(
        enrollment_cert_der
    ).public_bytes(Encoding.PEM)

    intermediate_pem = x509.load_der_x509_certificate(
        intermediate_cert_der
    ).public_bytes(Encoding.PEM)

    data = dmserver_proto.CertificateBasedDeviceRegistrationData()
    data.certificate_type = (
        dmserver_proto.CertificateBasedDeviceRegistrationData.ENTERPRISE_ENROLLMENT_CERTIFICATE
    )
    data.device_certificate = leaf_pem + intermediate_pem

    register = data.device_register_request
    register.type = dmserver_proto.DeviceRegisterRequest.DEVICE
    register.flavor = (
        dmserver_proto.DeviceRegisterRequest.FLAVOR_ENROLLMENT_ATTESTATION_SERVER_FORCED
    )
    register.lifetime = (
        dmserver_proto.DeviceRegisterRequest.LIFETIME_INDEFINITE
    )
    register.machine_id = machine_id
    register.machine_model = machine_model
    register.brand_code = brand_code
    register.server_backed_state_key = current_state_key

    return data.SerializeToString(deterministic=True)

def create_signed_devicemanagement_request(
    registration_data: bytes,
    enrollment_key_info: dict,
) -> bytes:
    nonce = secrets.token_bytes(20)
    data_to_sign = registration_data + nonce

    private_key = ec.derive_private_key(
        enrollment_key_info["key_pair"].d,
        ec.SECP256R1(),
    )

    signature = private_key.sign(
        data_to_sign,
        ec.ECDSA(hashes.SHA256()),
    )

    request = dmserver_proto.DeviceManagementRequest()
    signed = (
        request.certificate_based_register_request.signed_request
    )

    signed.data = data_to_sign
    signed.signature = signature
    signed.extra_data_bytes = len(nonce)

    return request.SerializeToString(deterministic=True)