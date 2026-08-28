# Enrollment certificate generator

Given an EK certificate and an EK keypair, \
we are able to generate AIKs, get it signed by the PCA, \
generate enrollment certificates, get it signed by the PCA.

This allows us to modify enrollment state under a PCA signed certificate \
and allows us to forge state to the DMServer. Of course, there are more use \
cases for this too.

## How EK certificates are derived

1. When a Cr50(TPM) is created in the factory, a random EPS is generated for the EK private + public key deriviation. 
2. In the factory(where the Cr50 is made), the factory constructs a TBSCertificate which is made up of 
    - EK public key 
    - TPM info
    - cert serial number
    - validity period

2. Next, in the factory, the factory's CA private key then signs this created TBSCertificate with SHA256-RSA. \
The TBSCertificate and the TBSCertificate signature signed by the factory CA is then saved into the Cr50 certificate region persistently, \
as the certificate region is never touched again. \
This certificate region contains the (TBSCertificate | Signature algorithm | Factory CA signature value). \
TBSCertificate contains the EK certificate data.

## How AIK certificates are derived

1. When a Chromebook is set up, ChromeOS requests for an AIK public + private keypair(randomly) to be created within the TPM. \
The AIK private key does not leave the TPM.

2. attestationd then requests for PCR0 and PCR1 quotes, signed by the AIK private key through TPM2_Quote. Each quote contains
    - Selected PCR number
    - PCR digest/hash
    - TPM metadata
    - AIK signature over the quote structure

3. Now, we enroll the AIK. To enroll the AIK, we send the Privacy CA (PCA) server
    - EK certificate encrypted with the ACA public key
    - AIK public key
    - AIK signed PCR0 and PCR1 quotes
    - TPM version
    - Chromebook DEN, which is HMAC-SHA256("attestation_based_enrollment", stable_device_secret)

> When the AIK is enrolled with PCR0 and PCR1 values, we believe that a record is kept on the PCA server of the attested PCR0(boot mode). \
> With this attested boot mode, the enrollment certificates that are signed by the PCA when we prove that we own this AIK end up \
> having device state encoded into the certificate message(CN). This means that a single AIK is bound to a single boot mode state for its \
> lifetime on the PCA server. \
> Public source code does not document this behavior, but this behavior was observed from generated certificates from the PCA server.

4. In return, we get an EncryptedIdentityCredential, containing the PCA signed AIK certificate. 

5. Given the EncryptedIdentityCredential, ChromeOS requests from the Cr50 through TPM2_ActivateCredential to use its EK private key and AIK identity(to verify the AIK belongs to us) to recover an intermediate credential, which is then used to decrypt the encrypted data in the EncryptedIdentityCredential object and to obtain and store the AIK certificate.