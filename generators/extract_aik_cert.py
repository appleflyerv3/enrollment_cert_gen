"""
Written with ChatGPT's help
"""

import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.modes import CFB

from .helpers.ecc import *
from .helpers.shared import *

def validate_ecc_ek(
    certificate_der: bytes,
    keypair,
) -> None:
    certificate = x509.load_der_x509_certificate(certificate_der)
    public_key = certificate.public_key()

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("ek certificate is not ecc")

    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("ek certificate is not p256")

    numbers = public_key.public_numbers()
    if (numbers.x, numbers.y) != (keypair.x, keypair.y):
        raise ValueError("ek keypair does not match certificate")

    derived_public = ecc_scalar_multiply(keypair.d, G)
    if derived_public != (keypair.x, keypair.y):
        raise ValueError("invalid scalar")

def parse_ecc_encrypted_seed(
    encrypted_seed: bytes,
) -> tuple[bytes, tuple[int, int]]:
    x_bytes, offset = read_tpm2b(encrypted_seed, 0)
    y_bytes, offset = read_tpm2b(encrypted_seed, offset)

    if offset != len(encrypted_seed):
        raise ValueError("extra encrypted seed data")

    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise ValueError("wrong p256 point len")

    x = int.from_bytes(x_bytes, "big")
    y = int.from_bytes(y_bytes, "big")

    if not (0 <= x < P and 0 <= y < P):
        raise ValueError("ecc coordinate is outside the field")

    if (y * y - (x**3 + A * x + B)) % P:
        raise ValueError("ecc point is not on p256")

    return x_bytes, (x, y)

def recover_pca_seed(
    encrypted_seed: bytes,
    ek_keypair,
) -> bytes:
    ephemeral_x_bytes, ephemeral_point = parse_ecc_encrypted_seed(
        encrypted_seed
    )

    shared_point = ecc_scalar_multiply(
        ek_keypair.d,
        ephemeral_point,
    )
    if shared_point is None:
        raise ValueError("invalid ecdh shared point")

    return kdfe_sha256(
        z=shared_point[0].to_bytes(32, "big"),
        label=b"IDENTITY",
        party_u_info=ephemeral_x_bytes,
        party_v_info=ek_keypair.x.to_bytes(32, "big"),
        bits=256,
    )

def get_aik_name(aik_info: dict) -> bytes:
    computed_name = (
        b"\x00\x0b"
        + hashlib.sha256(aik_info["tpmt_public"]).digest()
    )

    supplied_name = aik_info.get("aik_name", computed_name)

    if not hmac.compare_digest(supplied_name, computed_name):
        raise ValueError("incorrect AIK Name")

    return computed_name

def activate_credential_in_software(
    encrypted_identity_credential,
    seed: bytes,
    aik_name: bytes,
) -> bytes:
    storage_key = kdfa_sha256(seed, b"STORAGE", aik_name, b"", 128)
    integrity_key = kdfa_sha256(seed, b"INTEGRITY", b"", b"", 256)

    encrypted_credential = bytes(encrypted_identity_credential.wrapped_certificate.wrapped_key)

    expected_mac = hmac.new(
        integrity_key, encrypted_credential + aik_name, hashlib.sha256
    ).digest()

    if not hmac.compare_digest(
        expected_mac, bytes(encrypted_identity_credential.credential_mac)
    ):
        raise ValueError("credential mac mismatch")

    decryptor = Cipher(
        algorithms.AES(storage_key),
        CFB(b"\x00" * 16),
    ).decryptor()

    encoded_credential = (
        decryptor.update(encrypted_credential)
        + decryptor.finalize()
    )

    if len(encoded_credential) < 2:
        raise ValueError("bad length activated credential")

    size = int.from_bytes(encoded_credential[:2], "big")

    if len(encoded_credential) != size + 2:
        raise ValueError("wrong activated credential")

    return encoded_credential[2:]

def decrypt_wrapped_certificate(
    wrapped_certificate,
    credential: bytes,
) -> bytes:
    aes_key = hashlib.sha256( b"ENCRYPT" + credential).digest()
    mac_key = hashlib.sha256(b"MAC" + credential).digest()

    iv = bytes(wrapped_certificate.iv)
    ciphertext = bytes(wrapped_certificate.encrypted_data)

    if len(iv) != 16:
        raise ValueError("invalid certificate iv")

    expected_mac = hmac.new(
        mac_key, iv + ciphertext, hashlib.sha512
    ).digest()

    if not hmac.compare_digest(
        expected_mac, bytes(wrapped_certificate.mac),
    ):
        raise ValueError("wrapped certificate mac mismatch")

    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()

    padded_certificate = (
        decryptor.update(ciphertext) + decryptor.finalize()
    )

    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded_certificate) + unpadder.finalize())

def validate_aik_certificate(
    certificate_der: bytes,
    aik_info: dict,
) -> x509.Certificate:
    certificate = x509.load_der_x509_certificate(certificate_der)
    public_key = certificate.public_key()

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("aik cert is not ecc")

    numbers = public_key.public_numbers()
    aik_keypair = aik_info["key_pair"]

    if (numbers.x, numbers.y) != (aik_keypair.x, aik_keypair.y):
        raise ValueError("cert does not match aik")

    return certificate

def unwrap_pca_aik_certificate(
    encrypted_identity_credential,
    ek_certificate_der: bytes,
    ek_keypair,
    aik_info: dict,
) -> bytes:
    validate_ecc_ek(ek_certificate_der, ek_keypair)

    seed = recover_pca_seed(
        bytes(encrypted_identity_credential.encrypted_seed),
        ek_keypair,
    )

    aik_name = get_aik_name(aik_info)
    credential = activate_credential_in_software(encrypted_identity_credential, seed, aik_name)
    certificate_der = decrypt_wrapped_certificate(encrypted_identity_credential.wrapped_certificate, credential)

    validate_aik_certificate(certificate_der, aik_info)
    return certificate_der