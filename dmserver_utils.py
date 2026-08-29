import time, hmac, struct, hashlib
from proto_gen.cert_device_reg import (
    craft_certificate_based_registration_data, 
    create_signed_devicemanagement_request
)
from server_requester import send_certificate_based_register_dmserver

STATE_KEYS_QUANTUM_POWER = 23

def generate_state_keys(sds: str, keys: int) -> list[bytes]:
    hmac_key = bytes.fromhex(sds)
    quantum_size = 1 << STATE_KEYS_QUANTUM_POWER
    quantized_time = int(time.time()) & ~(quantum_size - 1)

    keys_list = []

    for _ in range(keys):
        marshalled_time = b"server_backed_state_keys\x00" + struct.pack("<q", quantized_time)
        key = hmac.new(hmac_key, marshalled_time, hashlib.sha256).digest()
        keys_list.append(key)
        quantized_time += quantum_size

    return keys_list

def dmserver_device_register_certificate_based(
    enrollment_key_info: dict,
    enrollment_cert: bytes,
    enrollment_intermediate_cert: bytes,
    sds: str,
    machine_id: str,
    machine_model: str,
    brand_code: str,
    device_id: str,
):  
    # First, generate state key
    state_key = generate_state_keys(sds, 1)[0]

    # Craft the internal CertificateBasedDeviceRegistrationData request
    protorq = craft_certificate_based_registration_data(
        enrollment_cert,
        enrollment_intermediate_cert,
        machine_id,
        machine_model,
        brand_code,
        state_key
    )

    # Wrap cert register request in DeviceManagementRequest and sign it
    # with the enrollment cert keys which are signed by PCA.
    protorq = create_signed_devicemanagement_request(
        protorq,
        enrollment_key_info
    )

    print(send_certificate_based_register_dmserver(device_id, protorq))


    

    