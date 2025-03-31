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
use serde::{Deserialize, Serialize};

use crate::{error::Error, JwtX5Chain};

/// The `x5chain` as defined in [RFC 9360][1] stored internally in DER format.
///
/// We use DER format for easier serialization ([`openssl::x509::X509`] doesn't implement
/// [`serde`]) and we also currently only depend on that format when using it.
///
/// The certificates are to be ordered starting with the certificate containing the end-entity key
/// followed by the certificate that signed it, and so on, as stated in [RFC 9360][1].
///
/// All methods of this type that return an [`Error`] do so in case the `x5chain` is invalid.
///
/// [1]: <https://www.rfc-editor.org/rfc/rfc9360.html#section-2-5.4.1>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct X5Chain(Vec<Vec<u8>>);

impl X5Chain {
    /// Create a new [`X5Chain`].
    ///
    /// The chain *must* be ordered in such a way that leaf certificate is at first place, then
    /// goes its parent, and so on. The root CA may be in chain, but it *must* be found in
    /// `trusted_root_certificates`.
    ///
    /// Using only intermediary CA in `trusted_root_certificates` will result with an error.
    pub fn new(
        chain: Vec<X509>,
        trusted_root_certificates: Vec<X509>,
    ) -> bherror::Result<Self, Error> {
        let leaf_cert = chain
            .first()
            .ok_or_else(|| bherror::Error::root(Error::X5Chain))
            .ctx(|| "Chain cannot be empty")?
            .clone();

        // validate the order of certificates
        validate_chain_order(&chain)?;

        // The `X509StoreContext` doesn't bother if chain has leaf certificate in chain or not. It
        // uses chain as list of untrusted certificates that should help verify target certificate.
        // For more details check https://docs.openssl.org/master/man3/X509_STORE_CTX_new/
        let chain = chain_to_stack(chain)?;
        let trusted_root_certificates = certs_to_store(trusted_root_certificates)?;

        let mut context = X509StoreContext::new().foreign_err(|| Error::X5Chain)?;
        let is_valid = context
            .init(
                &trusted_root_certificates,
                &leaf_cert,
                &chain,
                |context_ref| clean_up_after_openssl(|| context_ref.verify_cert()),
            )
            .foreign_err(|| Error::X5Chain)?;

        if !is_valid {
            return Err(bherror::Error::root(Error::X5Chain)
                .ctx("Chain validation against trusted root certificates failed")
                .ctx(format!(
                    "OpenSSL error on depth {}: {}",
                    context.error_depth(),
                    context.error()
                )));
        }

        Ok(Self(
            chain
                .into_iter()
                .map(|cert| cert.to_der())
                .collect::<Result<_, _>>()
                .foreign_err(|| Error::X5Chain)
                .ctx(|| "Failed to serialize cert in DER")?,
        ))
    }

    /// Constructs a [`X5Chain`] from raw bytes.
    ///
    /// The chain *must* be ordered in such a way that the leaf certificate is at
    /// the first place, then goes its parent, and so on.
    ///
    /// # Warning
    ///
    /// The chain is not validated against any trusted root certificate.
    pub fn from_raw_bytes(bytes: Vec<Vec<u8>>) -> bherror::Result<Self, Error> {
        if bytes.is_empty() {
            return Err(bherror::Error::root(Error::X5Chain).ctx("chain is empty"));
        }

        let certs = bytes
            .iter()
            .map(|der| X509::from_der(der))
            .collect::<Result<Vec<_>, _>>()
            .foreign_err(|| Error::X5Chain)
            .ctx(|| "invalid X509 certificate(s)")?;

        // validate the order of certificates
        validate_chain_order(&certs)?;

        Ok(Self(bytes))
    }

    /// Convert the chain into a list of DER encoded certificates.
    pub fn into_bytes(self) -> Vec<Vec<u8>> {
        self.0
    }

    /// Returns the public key from the leaf certificate.
    pub fn leaf_certificate_key(&self) -> bherror::Result<PKey<Public>, Error> {
        X509::from_der(self.0.first().expect("Chain cannot be empty"))
            .foreign_err(|| Error::X5Chain)
            .ctx(|| "Failed to create X509 from chain bytes")?
            .public_key()
            .foreign_err(|| Error::X5Chain)
            .ctx(|| "Failed to access X509 public key")
    }

    /// Returns the leaf certificate.
    pub fn leaf_certificate(&self) -> bherror::Result<X509, Error> {
        X509::from_der(self.0.first().expect("Chain cannot be empty"))
            .foreign_err(|| Error::X5Chain)
            .ctx(|| "Failed to create X509 from chain bytes")
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

        X5Chain::new(vec![cert.clone()], vec![cert]).unwrap()
    }
}

/// Helper method for converting certificates to `Stack<x509>`.
fn chain_to_stack(chain: Vec<X509>) -> bherror::Result<Stack<X509>, Error> {
    chain
        .into_iter()
        .try_fold(
            Stack::new().foreign_err(|| Error::X5Chain)?,
            |mut chain, cert| {
                chain.push(cert)?;
                Ok::<_, openssl::error::ErrorStack>(chain)
            },
        )
        .foreign_err(|| Error::X5Chain)
}

/// Helper method for converting certificates to `X509Store`.
fn certs_to_store(certificates: Vec<X509>) -> bherror::Result<X509Store, Error> {
    let mut builder = X509StoreBuilder::new().foreign_err(|| Error::X5Chain)?;
    builder
        .set_flags(X509VerifyFlags::X509_STRICT | X509VerifyFlags::CHECK_SS_SIGNATURE)
        .unwrap();

    Ok(certificates
        .into_iter()
        .try_fold(builder, |mut x509_store_builder, cert| {
            x509_store_builder.add_cert(cert)?;
            Ok::<_, openssl::error::ErrorStack>(x509_store_builder)
        })
        .foreign_err(|| Error::X5Chain)?
        .build())
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
fn validate_chain_order(chain: &[X509]) -> bherror::Result<(), Error> {
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

    fn try_from(jwt_x5chain: JwtX5Chain) -> Result<Self, Self::Error> {
        let base64_ders = jwt_x5chain.into_base64_ders();

        let der_certs = base64_ders
            .iter()
            .map(|base64_der| base64::decode_block(base64_der).foreign_err(|| Error::X5Chain))
            .collect::<bherror::Result<_, _>>()?;

        // TODO(issues/10): Check trusted root certificate
        X5Chain::from_raw_bytes(der_certs)
    }
}

/// Wrap a closure calling OpenSSL with low-level cleanup to make it safer in an async context.
///
/// Usage: wrap an `openssl` call in a closure and call this function with it.
/// Try to make the closure as small as possible.
fn clean_up_after_openssl<T>(f: impl FnOnce() -> Result<T, ErrorStack>) -> Result<T, ErrorStack> {
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

        // empty is valid
        validate_chain_order(&[]).unwrap();

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
        X5Chain::from_raw_bytes(vec![leaf, intermediary, root]).unwrap();

        // empty chain is invalid
        let err = X5Chain::from_raw_bytes(vec![]).unwrap_err();
        assert!(matches!(err.error, Error::X5Chain));
        assert_empty_error_stack();

        // invalid bytes
        let err = X5Chain::from_raw_bytes(vec![vec![0u8, 1u8], vec![2u8]]).unwrap_err();
        assert!(matches!(err.error, Error::X5Chain));
        assert_empty_error_stack();
    }

    #[test]
    fn check_x5chain_relationship() {
        let [leaf, intermediary, root] = get_certs();

        let trusted = vec![root.clone()];

        // Chain is valid when chain is in right order
        assert!(X5Chain::new(vec![leaf.clone(), intermediary.clone()], trusted.clone()).is_ok());

        // Chain is not valid when there are no trusted root CAs (this would pass if
        // `X509VerifyFlags::PARTIAL_CHAIN` was used)
        assert!(X5Chain::new(vec![leaf.clone()], vec![intermediary.clone()]).is_err());
        assert_empty_error_stack();

        // Chain is valid when both intermediary and root CA are trusted
        assert!(X5Chain::new(vec![leaf.clone()], vec![intermediary.clone(), root.clone()]).is_ok());

        // Chain is not valid if chain is not in right order
        assert!(X5Chain::new(vec![intermediary.clone(), leaf.clone()], trusted.clone()).is_err());
        assert_empty_error_stack();

        // Chain is not valid if leaf cannot be traced to root
        assert!(X5Chain::new(vec![leaf.clone()], trusted.clone()).is_err());
        assert_empty_error_stack();

        // Chain cannot be empty
        assert!(X5Chain::new(vec![], trusted).is_err());
        assert_empty_error_stack();

        // Chain is not valid when leaf cannot be traced to any trusted root
        assert!(X5Chain::new(vec![leaf, intermediary, root], vec![]).is_err());
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
        let jwt_x5chain = JwtX5Chain::dummy();

        assert_eq!(X5Chain::try_from(jwt_x5chain).unwrap(), X5Chain::dummy());
    }
}
