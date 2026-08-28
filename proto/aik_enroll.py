import proto.attestation_ca_pb2 as ca

def encrypted_data_proto(values: dict) -> ca.EncryptedData:
    result = ca.EncryptedData()

    for field in (
        "wrapped_key",
        "iv",
        "mac",
        "encrypted_data",
        "wrapping_key_id",
    ):
        value = values.get(field)
        if value is not None:
            setattr(result, field, value)

    return result


def quote_proto(values: dict) -> ca.Quote:
    result = ca.Quote(
        quote=values["quote"],
        quoted_data=values["quoted_data"],
        quoted_pcr_value=values["quoted_pcr_value"],
    )

    source_hint = values.get("pcr_source_hint")
    if source_hint is not None:
        result.pcr_source_hint = source_hint

    return result

def craft_aik_enrollment_protobuf_request(
    tpm_version: int,
    identity_public_key: bytes,
    encrypted_ek_cert: dict,
    pcr0_quote: dict,
    pcr1_quote: dict,
    den: bytes,
) -> bytes:
    request = ca.AttestationEnrollmentRequest()

    request.tpm_version = tpm_version
    request.identity_public_key = identity_public_key

    request.encrypted_endorsement_credential.CopyFrom(
        encrypted_data_proto(encrypted_ek_cert)
    )

    request.pcr0_quote.CopyFrom(quote_proto(pcr0_quote))
    request.pcr1_quote.CopyFrom(quote_proto(pcr1_quote))

    request.enterprise_enrollment_nonce = den

    return request.SerializeToString(deterministic=True)