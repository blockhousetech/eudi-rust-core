// Copyright (C) 2020-2025  The Blockhouse Technology Limited (TBTL).
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
// License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use bherror::traits::{ErrorContext as _, ForeignError as _};
use openssl::{
    base64,
    error::ErrorStack,
    pkey::{PKey, Public},
    stack::Stack,
    x509::{
        store::{X509Store, X509StoreBuilder},
        verify::X509VerifyFlags,
        X509StoreContext, X509,
    },
};

use crate::{Error, JwtX5Chain, Result};

/// The `x5chain` as defined in [RFC 9360][1].
///
/// The certificates are ordered starting with the certificate containing the end-entity key
/// followed by the certificate that signed it, and so on, as stated in [RFC 9360][1].
///
/// All methods of this type that return an [`Error`] do so in case the `x5chain` is invalid.
///
/// [1]: <https://www.rfc-editor.org/rfc/rfc9360.html#section-2-5.4.1>
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X5Chain {
    leaf: X509,
    intermediates: Vec<X509>,
}

impl X5Chain {
    /// Create a new [`X5Chain`].
    ///
    /// The chain **MUST BE** ordered in such a way that the leaf certificate is at first place,
    /// then goes its parent, and so on.
    ///
    /// # Warning
    ///
    /// The chain is at this point **NOT VALIDATED** against any trusted root certificate. In order
    /// to validate the chain against a trusted root certificate, use the
    /// [`X5Chain::verify_against_trusted_roots`] method.
    pub fn new(chain: Vec<X509>) -> Result<Self> {
        // validate the order of certificates
        validate_chain_order(&chain)?;

        let mut chain = chain.into_iter();
        // `expect` is fine as the length is checked within the `validate_chain_order`
        let leaf = chain.next().expect("chain is empty");
        let intermediates = chain.collect();

        Ok(Self {
            leaf,
            intermediates,
        })
    }

    /// Constructs a [`X5Chain`] from raw bytes.
    ///
    /// Each certificate **MUST BE** represented as a [`Vec`] of bytes of the respective certificate
    /// in the _DER_ format.
    ///
    /// The chain **MUST BE** ordered in such a way that the leaf certificate is at first place,
    /// then goes its parent, and so on.
    ///
    /// # Warning
    ///
    /// The chain is at this point **NOT VALIDATED** against any trusted root certificate. In order
    /// to validate the chain against a trusted root certificate, use the
    /// [`X5Chain::verify_against_trusted_roots`] method.
    pub fn from_raw_bytes(bytes: &[Vec<u8>]) -> Result<Self> {
        let certs = bytes
            .iter()
            .enumerate()
            .map(|(i, der)| X509::from_der(der).foreign_err(|| Error::X5Chain).ctx(|| i))
            .collect::<Result<_>>()
            .ctx(|| "invalid X509 certificate")?;

        Self::new(certs)
    }

    /// Verify the [`X5Chain`] against trusted root certificates.
    ///
    /// The root certificate may be in chain, but it **MUST BE** found in `trust` as well.
    pub fn verify_against_trusted_roots(&self, trust: &X509Trust) -> Result<()> {
        // It is "ugly" that we need to clone here, but if intermediates are kept as a Stack instead
        // of Vec, it messes up a lot of other things, such as Debug, Clone, PartialEq. It is hard
        // to work with it in general.
        let intermediates = chain_to_stack(self.intermediates.clone())?;

        // It is "ugly" that we need to clone here, but if trust is kept as X509Store, instead of
        // Vec, it messes up a lot of other things, such as Debug, Clone. It is hard to work with it
        // as well.
        let trust = certs_to_store(trust.0.clone())?;

        // The `X509StoreContext` doesn't bother if chain has leaf certificate in chain or not. It
        // uses chain as list of untrusted certificates that should help verify target certificate.
        // For more details check https://docs.openssl.org/master/man3/X509_STORE_CTX_new/

        let mut context = X509StoreContext::new().foreign_err(|| Error::X5Chain)?;
        let is_valid = context
            .init(&trust, &self.leaf, &intermediates, |ctx| {
                clean_up_after_openssl(|| ctx.verify_cert())
            })
            .foreign_err(|| Error::X5Chain)?;

        if !is_valid {
            return Err(bherror::Error::root(Error::X5Chain)
                .ctx("Chain validation against trusted root certificates failed")
                .ctx(format!(
                    "OpenSSL error on depth {}: {}",
                    context.error_depth(),
                    context.error()
                )));
        };

        Ok(())
    }

    /// Convert the chain into a list of DER encoded certificates.
    pub fn as_bytes(&self) -> Result<Vec<Vec<u8>>> {
        let mut bytes = Vec::new();

        bytes.push(self.leaf.to_der().foreign_err(|| Error::X5Chain)?);

        for intermediate in &self.intermediates {
            bytes.push(intermediate.to_der().foreign_err(|| Error::X5Chain)?);
        }

        Ok(bytes)
    }

    /// Returns the public key from the leaf certificate.
    pub fn leaf_certificate_key(&self) -> Result<PKey<Public>> {
        self.leaf_certificate()
            .public_key()
            .foreign_err(|| Error::X5Chain)
            .ctx(|| "Failed to access X509 public key")
    }

    /// Returns the leaf certificate.
    pub fn leaf_certificate(&self) -> &X509 {
        &self.leaf
    }

    /// Constructor of test `X5Chain` instance.
    ///
    /// Do NOT use this method for production code, but only tests.
    #[cfg(any(feature = "test-utils", test))]
    pub fn dummy() -> Self {
        let cert = "-----BEGIN CERTIFICATE-----
MIICVDCCAfmgAwIBAgIUPdJpjMqO4Bls4WZx2+BcORTjlJswCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDEyMDMxMTM0NTJaFw0yNTEyMDMx
MTM0NTJaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQUlhlvcCeMLmKr98zpjwL+vFPXFGTqulzZrNfxR0OG3RkjRJ2CM4xk
emDfzwBi/44InVtwa0qOT7J/n4A9H3T2o4HGMIHDMA8GA1UdEwEB/wQFMAMBAf8w
HQYDVR0OBBYEFHqUBkBqqW11hmwTeE3dmAoa5NDEMIGABgNVHSMEeTB3gBR6lAZA
aqltdYZsE3hN3ZgKGuTQxKFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNv
bWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIUPdJp
jMqO4Bls4WZx2+BcORTjlJswDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0kA
MEYCIQDmYbg42vFmrqwp9b1Z2MQYBdE2PBuQL/thL4PHrajW4gIhAOIfUVucqEzT
tGhGJX/ipfAuxvVB4dSElUM+tMOXPqtj
-----END CERTIFICATE-----";

        let cert = X509::from_pem(cert.as_bytes()).unwrap();

        let trust = X509Trust::new(vec![cert.clone()]);

        let chain = X5Chain::new(vec![cert]).unwrap();
        chain.verify_against_trusted_roots(&trust).unwrap();

        chain
    }
}

/// A collection of [`X509`] trusted root certificates.
///
/// This is used to verify the authenticity of the [`X5Chain`].
#[derive(Debug, Clone)]
pub struct X509Trust(Vec<X509>);

impl X509Trust {
    /// Create a new [`X509Trust`].
    pub fn new(trust: Vec<X509>) -> Self {
        Self(trust)
    }
}

/// Helper method for converting certificates to `Stack<x509>`.
fn chain_to_stack(chain: impl IntoIterator<Item = X509>) -> Result<Stack<X509>> {
    let mut intermediates = Stack::new().foreign_err(|| Error::X5Chain)?;

    for cert in chain {
        intermediates.push(cert).foreign_err(|| Error::X5Chain)?;
    }

    Ok(intermediates)
}

/// Helper method for converting certificates to `X509Store`.
fn certs_to_store(certificates: impl IntoIterator<Item = X509>) -> Result<X509Store> {
    let mut builder = X509StoreBuilder::new().foreign_err(|| Error::X5Chain)?;
    builder
        .set_flags(X509VerifyFlags::X509_STRICT | X509VerifyFlags::CHECK_SS_SIGNATURE)
        .foreign_err(|| Error::X5Chain)?;

    for cert in certificates {
        builder.add_cert(cert).foreign_err(|| Error::X5Chain)?;
    }

    Ok(builder.build())
}

/// Validates that the certificates in a chain are in order.
///
/// The chain must be ordered in such a way that the leaf certificate is at the
/// first place, then goes its parent, and so on.
///
/// # Note
///
/// This check is not provided through [`X509StoreContext`]. Without this check,
/// chains in reversed order would seem valid, even though they are not.
fn validate_chain_order(chain: &[X509]) -> Result<()> {
    if chain.is_empty() {
        return Err(bherror::Error::root(Error::X5Chain).ctx("chain is empty"));
    }

    let is_ordered = chain
        .windows(2)
        .try_fold(true, |acc, cert_pair| {
            // this is safe since we use the 2-sized sliding window
            let child = &cert_pair[0];
            let parent = &cert_pair[1];

            let is_child = clean_up_after_openssl(|| child.verify(parent.public_key()?.as_ref()))?;

            Ok::<_, openssl::error::ErrorStack>(acc && is_child)
        })
        .foreign_err(|| Error::X5Chain)?;

    if !is_ordered {
        return Err(bherror::Error::root(Error::X5Chain).ctx("invalid chain order"));
    }

    Ok(())
}

impl TryFrom<JwtX5Chain> for X5Chain {
    type Error = bherror::Error<Error>;

    fn try_from(jwt_x5chain: JwtX5Chain) -> Result<Self> {
        let der_certs: Vec<Vec<u8>> = jwt_x5chain
            .into_base64_ders()
            .iter()
            .enumerate()
            .map(|(i, base64_der)| {
                base64::decode_block(base64_der)
                    .foreign_err(|| Error::X5Chain)
                    .ctx(|| i)
            })
            .collect::<Result<_>>()
            .ctx(|| "invalid base64 string")?;

        X5Chain::from_raw_bytes(&der_certs)
    }
}

/// Wrap a closure calling OpenSSL with low-level cleanup to make it safer in an async context.
///
/// Usage: wrap an `openssl` call in a closure and call this function with it.
/// Try to make the closure as small as possible.
fn clean_up_after_openssl<T>(
    f: impl FnOnce() -> std::result::Result<T, ErrorStack>,
) -> std::result::Result<T, ErrorStack> {
    // Early return on error. Hopefully the error stack will be popped here if everything is correct.
    let return_value = f()?;

    // We did not return early, so we should expect that the call "succeeded".
    // In that case, we expect the error stack to be clean, so clear it if it isn't already.
    drop(ErrorStack::get());

    Ok(return_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Certificates are generated using following script:
    // ```bash
    //
    // # generate root
    // openssl ecparam -genkey -name secp256r1 -out tbtl_root.key
    // openssl req -new -key tbtl_root.key -out tbtl_root.csr -sha256 \
    //     --subj "/C=HR/ST=Grad Zagreb/L=Zagreb/O=TBTL/OU=Team Bee/CN=root"
    // openssl x509 -req -days 365 -in tbtl_root.csr -signkey tbtl_root.key \
    //     -out tbtl_root.crt -extensions v3_ca -extfile root.config
    //
    // # generate intermediary
    // openssl ecparam -genkey -name secp256r1 -out tbtl_intermediary.key
    // openssl req -new -key tbtl_intermediary.key -out tbtl_intermediary.csr -sha256 \
    //     --subj "/C=HR/ST=Grad Zagreb/L=Zagreb/O=TBTL/OU=Team Bee/CN=intermediary"
    // openssl x509 -req -in tbtl_intermediary.csr -CA tbtl_root.crt -CAkey tbtl_root.key \
    //     -out tbtl_intermediary.crt -days 36500 -sha256 -extensions v3_intermediate_ca \
    //     -extfile mid.config
    //
    // # generate leaf
    // openssl ecparam -genkey -name secp256r1 -out tbtl_leaf.key
    // openssl req -new -key tbtl_leaf.key -out tbtl_leaf.csr -sha256 \
    //     --subj "/C=HR/ST=Grad Zagreb/L=Zagreb/O=TBTL/OU=Team Bee/CN=leaf"
    // openssl x509 -req -in tbtl_leaf.csr -CA tbtl_intermediary.crt -CAkey tbtl_intermediary.key \
    //     -out tbtl_leaf.crt -days 36500 -sha256 \
    //
    // cat tbtl_leaf.crt tbtl_intermediary.crt tbtl_root.crt
    // ```
    //
    // The `mid.config`:
    // ```
    // [ v3_intermediate_ca ]
    // subjectKeyIdentifier = hash
    // authorityKeyIdentifier = keyid:always,issuer
    // basicConstraints = critical, CA:true, pathlen:0
    // keyUsage = critical, digitalSignature, cRLSign, keyCertSign
    // ```
    //
    // The `root.config`:
    //```
    // [ v3_ca ]
    // basicConstraints        = critical, CA:TRUE
    // subjectKeyIdentifier    = hash
    // authorityKeyIdentifier  = keyid:always, issuer:always
    // keyUsage                = critical, cRLSign, keyCertSign
    //```
    //
    // Certificates are in order: leaf, intermediary, root
    const CERTS: &str = "
-----BEGIN CERTIFICATE-----
MIICGDCCAb6gAwIBAgIUaZlAtJebcQ6Zk9ZXiVZ48dSaeekwCgYIKoZIzj0EAwIw
bTELMAkGA1UEBhMCSFIxFDASBgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZa
YWdyZWIxDTALBgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMRUwEwYDVQQD
DAxpbnRlcm1lZGlhcnkwIBcNMjQxMjA0MDg1NzEyWhgPMjEyNDExMTAwODU3MTJa
MGUxCzAJBgNVBAYTAkhSMRQwEgYDVQQIDAtHcmFkIFphZ3JlYjEPMA0GA1UEBwwG
WmFncmViMQ0wCwYDVQQKDARUQlRMMREwDwYDVQQLDAhUZWFtIEJlZTENMAsGA1UE
AwwEbGVhZjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABK+HDuLLHyjzQaiQxysC
mPtdksQauXv9S/ZQgTM/AlBZ/J6Lr/Uim7J+r2droplL95Hcpa6MZn1KfAacfAes
MCijQjBAMB0GA1UdDgQWBBSCezR2kWEbEzxHbhXNXbKm+hd8qzAfBgNVHSMEGDAW
gBTwnYWLumOoJFIwwm+auFeyXFFdJTAKBggqhkjOPQQDAgNIADBFAiAYQG8xMTi+
dEWCv7UwquS/6YKaaUHntGhdlU3qoyAskgIhAID2Alt1qOnWb9tPYAjmlSoT5NLZ
8Tig+6l55pHi9XhV
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICPDCCAeKgAwIBAgIUXcbNAmZ3c8WpP4nlWPrfLRyA6yEwCgYIKoZIzj0EAwIw
ZTELMAkGA1UEBhMCSFIxFDASBgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZa
YWdyZWIxDTALBgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMQ0wCwYDVQQD
DARyb290MCAXDTI0MTIwNDA4NTcxMloYDzIxMjQxMTEwMDg1NzEyWjBtMQswCQYD
VQQGEwJIUjEUMBIGA1UECAwLR3JhZCBaYWdyZWIxDzANBgNVBAcMBlphZ3JlYjEN
MAsGA1UECgwEVEJUTDERMA8GA1UECwwIVGVhbSBCZWUxFTATBgNVBAMMDGludGVy
bWVkaWFyeTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJJXtP84I3hrmlSSZxyv
8ATGrPdpEOffsYZikkMumR6cvKX2qZ4RP6tiXAdpOsr0qYlumUR5iHRxRG3u9dYu
bFujZjBkMB0GA1UdDgQWBBTwnYWLumOoJFIwwm+auFeyXFFdJTAfBgNVHSMEGDAW
gBRTPefvvzFcr8+4XU9x1ND5d/YLPjASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1Ud
DwEB/wQEAwIBhjAKBggqhkjOPQQDAgNIADBFAiArVWwaWqiEYWXjY09BZHCFHe9r
ntSfXIHDIZIuKQdjDQIhAI8IZHXM0pDx3otGT0we1/XeW2mOgVL32fVLVY3xvZSM
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICtTCCAlugAwIBAgIUAS+XO01IVXrFnsiOmClfU9A8CRMwCgYIKoZIzj0EAwIw
ZTELMAkGA1UEBhMCSFIxFDASBgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZa
YWdyZWIxDTALBgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMQ0wCwYDVQQD
DARyb290MB4XDTI0MTIwNDA4NTcxMloXDTI1MTIwNDA4NTcxMlowZTELMAkGA1UE
BhMCSFIxFDASBgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZaYWdyZWIxDTAL
BgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMQ0wCwYDVQQDDARyb290MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5xkaU0L4AjAP1odEvrPHorGJyKnlpySA
BXBv855QIsE4RNK3WXdzP67cgbKxqd2sAM4iAICjoZkawvdjUl7hQKOB6DCB5TAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRTPefvvzFcr8+4XU9x1ND5d/YLPjCB
ogYDVR0jBIGaMIGXgBRTPefvvzFcr8+4XU9x1ND5d/YLPqFppGcwZTELMAkGA1UE
BhMCSFIxFDASBgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZaYWdyZWIxDTAL
BgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMQ0wCwYDVQQDDARyb290ghQB
L5c7TUhVesWeyI6YKV9T0DwJEzAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID
SAAwRQIgQFZcV8g8pWID+BtS8nsulkve1i/OEBy9XbnQwt/i2FQCIQDsNlcxSkKK
jdc01UGluQ7Pq6abMWPn5OZaPDyCSqpjbw==
-----END CERTIFICATE-----
";

    fn get_certs() -> [X509; 3] {
        X509::stack_from_pem(CERTS.as_bytes())
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn test_validate_chain_order() {
        let [leaf, intermediary, root] = get_certs();

        // valid order
        validate_chain_order(&[leaf.clone(), intermediary.clone(), root.clone()]).unwrap();

        // reversed order is invalid
        let err = validate_chain_order(&[intermediary, leaf]).unwrap_err();
        assert!(matches!(err.error, Error::X5Chain));
        assert_empty_error_stack();

        // empty is invalid
        let err = validate_chain_order(&[]).unwrap_err();
        assert!(matches!(err.error, Error::X5Chain));
        assert_empty_error_stack();

        // single certificate is valid
        validate_chain_order(&[root]).unwrap();
    }

    #[test]
    fn test_from_raw_bytes() {
        let [leaf, intermediary, root] = get_certs();
        let leaf = leaf.to_der().unwrap();
        let intermediary = intermediary.to_der().unwrap();
        let root = root.to_der().unwrap();

        // valid chain
        X5Chain::from_raw_bytes(&[leaf, intermediary, root]).unwrap();

        // empty chain is invalid
        let err = X5Chain::from_raw_bytes(&[]).unwrap_err();
        assert!(matches!(err.error, Error::X5Chain));
        assert_empty_error_stack();

        // invalid bytes
        let err = X5Chain::from_raw_bytes(&[vec![0u8, 1u8], vec![2u8]]).unwrap_err();
        assert!(matches!(err.error, Error::X5Chain));
        assert_empty_error_stack();
    }

    #[test]
    fn check_x5chain_relationship() {
        let [leaf, intermediary, root] = get_certs();

        // Chain is valid when chain is in right order
        X5Chain::new(vec![leaf.clone()]).unwrap();
        X5Chain::new(vec![leaf.clone(), intermediary.clone()]).unwrap();
        X5Chain::new(vec![leaf.clone(), intermediary.clone(), root]).unwrap();

        // Chain is not valid if chain is not in right order
        X5Chain::new(vec![intermediary, leaf]).unwrap_err();
        assert_empty_error_stack();

        // Chain cannot be empty
        X5Chain::new(Vec::new()).unwrap_err();
        assert_empty_error_stack();
    }

    #[test]
    fn test_verify_against_trusted_roots() {
        let [leaf, intermediary, root] = get_certs();

        let chain = X5Chain::new(vec![leaf.clone()]).unwrap();

        // Chain is valid when both intermediary and root CA are trusted
        let trusted = X509Trust::new(vec![intermediary.clone(), root.clone()]);
        chain.verify_against_trusted_roots(&trusted).unwrap();

        // Chain is not valid when there are no trusted root CAs (this would
        // pass if `X509VerifyFlags::PARTIAL_CHAIN` was used)
        let trusted = X509Trust::new(vec![intermediary.clone()]);
        chain.verify_against_trusted_roots(&trusted).unwrap_err();
        assert_empty_error_stack();

        // Chain is not valid if leaf cannot be traced to root
        let trusted = X509Trust::new(vec![root.clone()]);
        chain.verify_against_trusted_roots(&trusted).unwrap_err();
        assert_empty_error_stack();

        // Chain is not valid when leaf cannot be traced to any trusted root
        let chain = X5Chain::new(vec![leaf, intermediary, root]).unwrap();
        let trusted = X509Trust::new(Vec::new());
        chain.verify_against_trusted_roots(&trusted).unwrap_err();
        assert_empty_error_stack();
    }

    // Kindly taken from bhcrypto
    fn assert_empty_error_stack() {
        let errors = openssl::error::ErrorStack::get();
        assert!(
            errors.errors().is_empty(),
            "Error stack was non-empty: {:?}",
            errors
        );
    }

    #[test]
    fn test_from_jwtx5chain_to_x5chain() {
        let received: X5Chain = JwtX5Chain::dummy().try_into().unwrap();
        let expected = X5Chain::dummy();

        assert_eq!(received, expected);
    }
}
