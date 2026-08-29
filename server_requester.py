import requests
import proto_gen.compiled.attestation_ca_pb2 as pca_server_proto
import proto_gen.compiled.device_management_backend_pb2 as dmserver_proto

def send_aik_enrollment_request(request_bytes: bytes):
    response = requests.post(
        "https://chromeos-ca.gstatic.com/enroll",
        data=request_bytes,
        headers={"Content-Type": "application/octet-stream"},
        timeout=30,
    )
    response.raise_for_status()

    reply = pca_server_proto.AttestationEnrollmentResponse()
    reply.ParseFromString(response.content)

    return reply

def send_enrollment_key_sign_request(request_bytes: bytes):
    response = requests.post(
        "https://chromeos-ca.gstatic.com/sign",
        data=request_bytes,
        headers={"Content-Type": "application/octet-stream"},
        timeout=30,
    )
    response.raise_for_status()

    reply = pca_server_proto.AttestationCertificateResponse()
    reply.ParseFromString(response.content)

    return reply

def send_certificate_based_register_dmserver(
    device_id: str,
    request_bytes: bytes,
):
    response = requests.post(
        "https://m.google.com/devicemanagement/data/api",
        params={
            "request": "certificate_based_register",
            "deviceid": device_id,
            "devicetype": "2",
            "apptype": "Chrome",
        },
        data=request_bytes,
        headers={
            "Content-Type": "application/x-protobuffer",
            "Accept": "application/x-protobuffer",
        },
        timeout=30,
    )
    response.raise_for_status()

    reply = dmserver_proto.DeviceManagementResponse()
    reply.ParseFromString(response.content)

    if not reply.HasField("register_response"):
        raise ValueError(f"Missing register_response: {response.error_message}!!!")

    register = reply.register_response

    if not register.HasField("device_management_token"):
        raise ValueError("Missing DMToken!!!")

    if register.HasField("enrollment_type"):
        enrollment_type = dmserver_proto.DeviceRegisterResponse.DeviceMode.Name(
            register.enrollment_type
        )
    else:
        print("Response does not contain enrollment_type, non-fatal.")
        enrollment_type = None

    return {
        "dm_token": register.device_management_token,
        "enrollment_type": enrollment_type,
    }