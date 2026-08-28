import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa


DEFAULT_ACA_MODULUS_HEX = (
    "A2976637E113CC457013F4334312A416395B08D4B2A9724FC9BAD65D0290F39C"
    "866D1163C2CD6474A24A55403C968CF78FA153C338179407FE568C6E550949B1"
    "B3A80731BA9311EC16F8F66060A2C550914D252DB90B44D19BC6C15E923FFCFB"
    "E8A366038772803EE57C7D7E5B3D5E8090BF0960D4F6A6644CB9A456708508F0"
    "6C19245486C3A49F807AB07C65D5E9954F4F8832BC9F882E9EE1AAA2621B1F43"
    "4083FD98758745CBFFD6F55DA699B2EE983307C14C9990DDFB48897F26DF8FB2"
    "CFFF03E631E62FAE59CBF89525EDACD1F7BBE0BA478B5418E756FF3E14AC9970"
    "D334DB04A1DF267D2343C75E5D282A287060D345981ABDA0B2506AD882579FEF"
)

DEFAULT_ACA_KEY_ID = b"\x00\xc7\x0e\x50\xb1"


def encrypt_ek_certificate_for_pca(
    certificate_der: bytes,
    modulus_hex: str = DEFAULT_ACA_MODULUS_HEX,
    wrapping_key_id: bytes = DEFAULT_ACA_KEY_ID,
) -> dict[str, bytes]:
    if not isinstance(certificate_der, bytes):
        raise TypeError("certificate_der must be bytes")

    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)

    padder = symmetric_padding.PKCS7(128).padder()
    padded_certificate = (padder.update(certificate_der) + padder.finalize())

    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()

    encrypted_certificate = (encryptor.update(padded_certificate) + encryptor.finalize())

    mac = hmac.new(aes_key, iv + encrypted_certificate, hashlib.sha512).digest()

    pca_public_key = rsa.RSAPublicNumbers(e=65537, n=int(modulus_hex, 16)).public_key()

    wrapped_key = pca_public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )

    return {
        "wrapped_key": wrapped_key,
        "iv": iv,
        "mac": mac,
        "encrypted_data": encrypted_certificate,
        "wrapping_key_id": wrapping_key_id,
    }