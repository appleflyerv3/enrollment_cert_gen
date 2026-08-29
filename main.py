import sys
import hashlib
import hmac
import uuid
import argparse
from pathlib import Path

from ek_certs import PROD_RO_CERT_REGION, PROD_ENDORSEMENT_SEED
from cert_broker import derive_ek_info, derive_aik_info, derive_enrollment_key_info
from dmserver_utils import dmserver_device_register_certificate_based

SAVE_ENROLLMENT_CERT = False

PCR0_VALUES = {
    "verified": "89eaf35134b4b3c649f44c0c765b96aeab8bb34ee83cc7a683c4e53d1581c8c7",
    "developer": "23e14dd9bb51a50e16911f7e11df1e1aaf0b17134dc739c5653607a1ec8dd37a"
}

def derive_aik_info_wrapper(
    ek_ecc_keypair: dict, 
    ek_ecc_cert: bytes, 
    bootmode: str, 
    stable_device_secret: str,
    hwid: str | None = None,
):
    # PCR0 value(we already know it directly, no need to calculate anything)
    pcr0_value = bytes.fromhex(PCR0_VALUES[bootmode])

    # PCR1 value derivation
    if hwid is not None:
        hwid_bytes = hwid.encode("ascii")
        hwid_digest = hashlib.sha256(hwid_bytes).digest()
        # Extend operation of HWID digest over PCR1 empty value
        pcr1_value = hashlib.sha256(b'\x00' * 32 + hwid_digest).digest()
    else:
        pcr1_value = None
        hwid_bytes = None

    # enterprise_enrollment_nonce derivation
    stable_device_secret_bytes = bytes.fromhex(stable_device_secret)
    den = hmac.new(
        b"attestation_based_enrollment",
        stable_device_secret_bytes,
        hashlib.sha256
    ).digest()

    aik_keypair_info, aik_certificate = derive_aik_info(
        ek_ecc_keypair=ek_ecc_keypair, 
        ek_ecc_certificate=ek_ecc_cert, 
        pcr0_value=pcr0_value, 
        enterprise_enrollment_nonce=den,

        # optional pcr1 quoting for hwid
        pcr1_value=pcr1_value, 
        pcr1_source_hint=hwid_bytes,
    )

    return aik_keypair_info, aik_certificate

def main(
    bootmode: str,
    sds: str,
    sn: str,
    output_dmtoken: Path,
    output_device_id: Path,
    hwid: str | None = None, # HWID not required, PCR1 quoting unused?
    rlz: str | None = None, # RLZ not required, not enforced on DMServer
) -> int:
    device_id = str(uuid.uuid4())

    ek_rsa_keypair, ek_rsa_cert, ek_ecc_keypair, ek_ecc_cert = derive_ek_info(PROD_RO_CERT_REGION, PROD_ENDORSEMENT_SEED)

    aik_keypair_info, aik_certificate = derive_aik_info_wrapper(
        ek_ecc_keypair,
        ek_ecc_cert,
        bootmode=bootmode,
        stable_device_secret=sds,
        hwid=hwid, # optional field for PCR1
    )

    enrollment_key_keypair_info, enrollment_key_certificate, enrollment_key_intermediate_ca = derive_enrollment_key_info(aik_keypair_info, aik_certificate)

    if SAVE_ENROLLMENT_CERT:
        with open("enrollment_certificate.der", "wb") as file:
            file.write(enrollment_key_certificate)

    # Send the request to get DMToken based on certificate
    print("Registering device with PCA enrollment certificate")
    dmserver_resp = dmserver_device_register_certificate_based(
        enrollment_key_keypair_info,
        enrollment_key_certificate,
        enrollment_key_intermediate_ca,
        sds, sn, device_id,
        hwid, rlz, # optional fields
    )
    print("Device successfully registered with DMServer!")

    with open(output_dmtoken, "w", encoding="utf-8") as file:
        file.write(dmserver_resp["dm_token"])
    with open(output_device_id, "w", encoding="utf-8") as file:
        file.write(device_id)

    print("dm_token: " + dmserver_resp["dm_token"])
    print("device_id: " + device_id)

    return 0

_argparser = argparse.ArgumentParser(
    prog="verified-spoofer-dmserver",
)

_argparser.add_argument("--bootmode", type=str, default="verified", choices=["verified", "developer"])
_argparser.add_argument("--stable_device_secret", type=str, required=True)
_argparser.add_argument("--serial_number", type=str, required=True)
_argparser.add_argument("--hwid", type=str, default=None)
_argparser.add_argument("--rlz", type=str, default=None)
_argparser.add_argument("--output_dm_token_path", type=Path, required=True)
_argparser.add_argument("--output_device_id_path", type=Path, required=True)
args = _argparser.parse_args()

sys.exit(
    main(
        args.bootmode,
        args.stable_device_secret,
        args.serial_number,
        args.output_dm_token_path,
        args.output_device_id_path,
        args.hwid,
        args.rlz
    )
)