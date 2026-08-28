"""
From the given RO_CERT region data, write an extractor to traverse the ro_cert
structs and extract the requested certificate from the region, if it exists.
"""

import hmac
import hashlib

def verify_eps_matches_ro_certs(ro_certs: bytes, eps: bytes) -> bool:
    eps_hmac_key = hmac.new(eps, b"RSA\x00", hashlib.sha256).digest()
    ro_certs_region = hmac.new(eps_hmac_key, ro_certs[0 : 2048 - 32], hashlib.sha256).digest()
    expected_hmac = ro_certs[2048 - 32 : 2048]

    if ro_certs_region == expected_hmac:
        return True

    return False

def extract_ek_cert(component_number: int, ro_certs: bytes) -> bytes | None:
    # ro_certs points to a ro_cert struct immediately.
    ro_cert_ptr = 0

    # -------- fixed 0x8
    # 0x0 - uint16_t component_size;
    # 0x2 - uint8_t component_type;
    # 0x3 - uint8_t reserved[5];
    # --------
    # 0x8 - uint8_t key_id[4];
    # 0xc - uint32_t cert_len;
    # 0x10 - uint8_t cert[cert_len];

    while True:
        if (ro_cert_ptr + 0x8) > len(ro_certs):
            return None

        # Traverse the certificate region until we find the component we want.
        if ro_certs[ro_cert_ptr + 0x2] != component_number:
            component_size = int.from_bytes(
                ro_certs[ro_cert_ptr+0x0 : ro_cert_ptr+0x2],
                'little'
            )

            ro_cert_ptr += component_size + 0x8
            if ro_cert_ptr > len(ro_certs):
                return None

            continue

        if ro_cert_ptr + 0x10 > len(ro_certs):
            return None
        
        rsa_cert_len = int.from_bytes(
            ro_certs[ro_cert_ptr+0xc : ro_cert_ptr+0x10],
            'little'
        )

        cert_end = ro_cert_ptr + 0x10 + rsa_cert_len
        if cert_end > len(ro_certs):
            return None

        return ro_certs[ro_cert_ptr + 0x10:cert_end]


