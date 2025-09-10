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

use std::{num::NonZeroUsize, ops::Shr};

use bherror::traits::{ErrorContext as _, ForeignError as _};
use iref::UriBuf;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage,
            SubjectAlternativeName as OpenSslSubjectAlternativeName, SubjectKeyIdentifier,
        },
        X509Name, X509NameBuilder, X509VerifyResult, X509,
    },
};
use rand::RngCore;

use crate::{Error, Result, X509Trust, X5Chain};

type PrivateKey = PKey<Private>;
type PublicKey = PKey<Public>;

#[derive(Debug)]
struct CertificatePrivateKeyPair {
    cert: X509,
    private_key: PrivateKey,
}

/// X.509v3
///
/// See [RFC 5280 - section 4.1.2.1](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.1)
const VERSION: i32 = 2;

/// Length of the certificate serial number in bits.
///
/// See [RFC 5280 - section 4.1.2.2](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.2),
/// and this answer from [stackoverflow](https://stackoverflow.com/a/55277597).
const SERIAL_NUMBER_BITS: i32 = 159;

/// Largest serial number allowed, for debug assertion purposes.
//                                        9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
const MAXIMUM_SERIAL_NUMBER_HEX: &str = "7fffffffffffffffffffffffffffffffffffffff";

/// Hardcoded duration of the validity period for this certificate
const VALIDITY_PERIOD_IN_DAYS: u32 = 365 * 10;

impl CertificatePrivateKeyPair {
    fn from_private_key_and_cert(private_key: &str, cert: &str) -> Result<Self> {
        let private_key = PrivateKey::private_key_from_pem(private_key.as_bytes())
            .foreign_err(|| Error::Builder)
            .ctx(|| "couldn't load private key")?;

        let cert = X509::from_pem(cert.as_bytes())
            .foreign_err(|| Error::Builder)
            .ctx(|| "couldn't load certificate")?;

        Ok(Self { cert, private_key })
    }

    /// Generate a vector of `n_bits`-many random bits which are not all zero,
    /// represented as a big endian byte vector of minimum size, i.e. any bits
    /// which are zero due to not being part of the generated bits will be
    /// the most significant bits of the byte at index `0`, and, when the vector
    /// is interpreted as an unsigned big endian integer, it will be nonzero and
    /// will have *at most* `bits` significant bits.
    ///
    /// All-zero bits are avoided using rejection sampling, with at most a constant
    /// number of attempts. Failures to sample a vector beyond this number of attempts
    /// are reported as errors, and the type I error rate under the null hypothesis
    /// that all bits are uniform i.i.d. is at most `2^(-256)`.
    pub(crate) fn generate_random_nonzero_bits_big_endian(n_bits: NonZeroUsize) -> Result<Vec<u8>> {
        let mut rng = rand::rng();

        let bytes: usize = n_bits.get().div_ceil(8);
        debug_assert!(bytes >= 1);
        let leading_zeros: u32 = (bytes * 8 - n_bits.get()) as u32;
        debug_assert!(leading_zeros < 8);
        let most_significant_byte_mask: u8 = u8::MAX.shr(leading_zeros);
        debug_assert_eq!(most_significant_byte_mask.leading_zeros(), leading_zeros);
        debug_assert_eq!(
            most_significant_byte_mask.trailing_ones(),
            8 - leading_zeros
        );

        let mut sample = vec![0u8; bytes];

        // H0: RNG generates i.i.d. samples of `n_bits` bits, each value with probability `2^(-n_bits)`.
        //
        // Under H0, the probability of successfully accepting a sample is `p = 1 - 2^(-n_bits)`.
        // Under H0, the probability of taking strictly more than `k` trials to
        // generate an accepted sample is `alpha = (1 - p)^k`. We wish to limit
        // this (under H0) to `alpha <= 2^(-256)`. This requires `k >= ceil(256 / n_bits)`,
        // so choosing 256 as the maximum allowed number of trials is sufficient
        // to ensure `alpha <= 2^(-256)` under H0.
        //
        // Rejecting H0 if the maximum number of trials is exceeded is then a
        // false positive with probability <= 2^(-256), and we can safely report
        // an error if it happens.
        const MAX_ITERATIONS: usize = 256;
        for _ in 0..MAX_ITERATIONS {
            rng.fill_bytes(&mut sample);
            // Mask out the most signficant byte to get the required number of bits
            sample[0] &= most_significant_byte_mask;

            // Perform rejection sampling: accept and return the sample if it is
            // not all zeros, otherwise reject the sample and continue the loop.
            // Rejection is not likely at all to happen for large `n_bits`, but is
            // required for correctness.
            if !sample.iter().all(|b| *b == 0) {
                return Ok(sample);
            }
        }

        // Reject H0 since it is highly unlikely that the bits *are* uniform i.i.d. and
        // that we are just unlucky.
        Err(bherror::Error::root(Error::Builder)
            .ctx("Failed to generate a nonzero random bit vector"))
    }

    /// See this [stackexchange answer](https://crypto.stackexchange.com/questions/257/unpredictability-of-x-509-serial-numbers)
    /// for more details.
    fn generate_random_serial_number() -> Result<Asn1Integer> {
        let bits = NonZeroUsize::new(SERIAL_NUMBER_BITS as usize).unwrap();
        let serial_number = Self::generate_random_nonzero_bits_big_endian(bits)?;

        let serial_number = BigNum::from_slice(&serial_number)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot create serial number")?;
        // Must be positive
        debug_assert!(serial_number > BigNum::from_u32(0).unwrap());
        // Must have bits <= SERIAL_NUMBER_BITS
        debug_assert!(serial_number.num_bits() <= SERIAL_NUMBER_BITS);
        debug_assert!(serial_number <= BigNum::from_hex_str(MAXIMUM_SERIAL_NUMBER_HEX).unwrap());

        let asn1_integer = serial_number
            .to_asn1_integer()
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot create asn1 integer")?;
        debug_assert!(!asn1_integer.to_bn().unwrap().is_negative());
        Ok(asn1_integer)
    }

    /// Low-level private method for creation of certificates.
    fn issue_certificate(
        &self,
        subject_public_key: &PublicKey,
        subject_name: &X509Name,
        subject_alternative_names: &[SubjectAlternativeName],
    ) -> Result<X509> {
        let mut cert_builder = X509::builder()
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot create cert builder")?;
        cert_builder
            .set_version(VERSION)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot set cert version")?;

        let serial_number = Self::generate_random_serial_number()?;
        cert_builder
            .set_serial_number(&serial_number)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot set serial number")?;

        cert_builder
            .set_pubkey(subject_public_key)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot set public key")?;
        cert_builder
            .set_subject_name(subject_name)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot set subject name")?;
        cert_builder
            .set_issuer_name(self.cert.subject_name())
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot set issuer name")?;

        let not_before = Asn1Time::days_from_now(0)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot create `not_before` time")?;
        cert_builder
            .set_not_before(&not_before)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot set `not_before` time")?;
        let not_after = Asn1Time::days_from_now(VALIDITY_PERIOD_IN_DAYS)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot create `not_after` time")?;
        cert_builder
            .set_not_after(&not_after)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot set `not_after` time")?;

        let basic_constraints = BasicConstraints::new();

        let basic_constraints = basic_constraints
            .build()
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot create basic_constraints")?;

        cert_builder
            .append_extension(basic_constraints)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot append basic constraints")?;

        let mut key_usage = KeyUsage::new();
        key_usage.digital_signature().non_repudiation().critical();

        let key_usage = key_usage
            .build()
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot create key_usage")?;

        cert_builder
            .append_extension(key_usage)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot append key usage")?;

        let subject_key_identifier = SubjectKeyIdentifier::new();

        let subject_key_identifier = subject_key_identifier
            .build(&cert_builder.x509v3_context(Some(self.cert.as_ref()), None))
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot create subject_key_identifier")?;

        cert_builder
            .append_extension(subject_key_identifier)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot append subject key identifier")?;

        let mut authority_key_identifier = AuthorityKeyIdentifier::new();
        authority_key_identifier.keyid(false).issuer(false);

        let authority_key_identifier = authority_key_identifier
            .build(&cert_builder.x509v3_context(Some(self.cert.as_ref()), None))
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot create authority_key_identifier")?;

        cert_builder
            .append_extension(authority_key_identifier)
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot append authority key identifier")?;

        if !subject_alternative_names.is_empty() {
            let mut subject_alternative_name = OpenSslSubjectAlternativeName::new();
            for san in subject_alternative_names {
                match san {
                    SubjectAlternativeName::Uri(uri) => subject_alternative_name.uri(uri),
                };
            }
            let subject_alternative_name = subject_alternative_name
                .build(&cert_builder.x509v3_context(Some(self.cert.as_ref()), None))
                .foreign_err(|| Error::Builder)
                .ctx(|| "Cannot create `subject_alternative_name`")?;

            cert_builder
                .append_extension(subject_alternative_name)
                .foreign_err(|| Error::Builder)
                .ctx(|| "Cannot append `subject_alternative_name`")?;
        }

        let issuer_private_key = self.private_key.as_ref();
        cert_builder
            .sign(issuer_private_key, MessageDigest::sha256())
            .foreign_err(|| Error::Builder)
            .ctx(|| "Cannot sign certificate")?;

        Ok(cert_builder.build())
    }
}

/// Subject Alternative Names options.
/// Currently only URI is needed and supported.
///
/// Used to set URI SAN values to generated x5chain leaf
/// certificates.
///
/// See [RFC 5280 - section
/// 4.2.1.6](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6)
#[non_exhaustive]
enum SubjectAlternativeName {
    Uri(UriBuf),
}

/// Builder of [`X5Chain`]; essentially a lightweight intermediary certificate authority.
///
/// This structure is used for building [`X5Chain`] based on loaded cryptographic material of
/// intermediary and trusted root.
///
/// # Use case
///
/// The purpose of this builder is being able to programatically generate a leaf
/// certificate with a non-trivial certificate chain, without having to shell
/// out to e.g. the `openssl` tool.
///
/// The primary use cases are tests or demo software - this is not a
/// production-grade CA implementation.
///
/// Customization of the leaf certificate is mostly unsupported, as there are
/// far better tools for that.
#[derive(Debug)]
pub struct Builder {
    intermediary_key_pair: CertificatePrivateKeyPair,
    trusted_root_certificate: X509,
}

impl Builder {
    /// Constructor of [`Builder`] expecting all input data to be in PEM format.
    pub fn new(
        intermediary_private_key: &str,
        intermediary_certificate: &str,
        trusted_root_certificate: &str,
    ) -> Result<Self> {
        let trusted_root_certificate = X509::from_pem(trusted_root_certificate.as_bytes())
            .foreign_err(|| Error::Builder)
            .ctx(|| "invalid trusted root certificate")?;

        let verify_relationship = trusted_root_certificate.issued(
            X509::from_pem(intermediary_certificate.as_bytes())
                .foreign_err(|| Error::Builder)?
                .as_ref(),
        );

        if verify_relationship != X509VerifyResult::OK {
            return Err(bherror::Error::root(Error::Builder))
                .ctx(|| "intermediary certificate must be issued by trusted root");
        }

        let intermediary_certificate = std::str::from_utf8(intermediary_certificate.as_bytes())
            .foreign_err(|| Error::Builder)
            .ctx(|| "couldn't parse intermediary private key")?;

        let intermediary_key_pair = CertificatePrivateKeyPair::from_private_key_and_cert(
            intermediary_private_key,
            intermediary_certificate,
        )
        .ctx(|| "invalid certificate and private key pair")?;

        Ok(Self {
            intermediary_key_pair,
            trusted_root_certificate,
        })
    }

    /// Create [`X5Chain`] based on stored certificates & CA private key, using
    /// the given leaf public key in PEM format.
    ///
    /// The leaf certificate will have extensions suitable for general-purpose
    /// signing.
    ///
    /// # Verifiable Credential (VC) Issuer leaf certificate extensions
    ///
    /// If the optional Issuer Identifier `iss` is not [`None`], it will be used as a Subject
    /// Alternative Name for the Issuer certificate created by this method.
    pub fn generate_x5chain(&self, leaf_public_key: &str, iss: Option<&UriBuf>) -> Result<X5Chain> {
        let leaf_public_key = PublicKey::public_key_from_pem(leaf_public_key.as_bytes())
            .foreign_err(|| Error::Builder)
            .ctx(|| "couldn't load leaf public key")?;

        let mut subject_name = X509NameBuilder::new()
            .foreign_err(|| Error::Builder)
            .ctx(|| "couldn't create `subject_name`")?;
        subject_name
            .append_entry_by_text("CN", "issuer")
            .foreign_err(|| Error::Builder)
            .ctx(|| "couldn't append entry to `subject_name`")?;

        let subject_alternative_names = iss
            .map(|iss| SubjectAlternativeName::Uri(iss.clone()))
            .into_iter()
            .collect::<Vec<_>>();

        let leaf_certificate = self
            .intermediary_key_pair
            .issue_certificate(
                &leaf_public_key,
                &subject_name.build(),
                &subject_alternative_names,
            )
            .ctx(|| "couldn't issue leaf certificate")?;

        let intermediary_certificate = self.intermediary_key_pair.cert.clone();

        let chain = X5Chain::new(vec![leaf_certificate, intermediary_certificate])?;

        let trust = X509Trust::new(vec![self.trusted_root_certificate.clone()]);
        chain.verify_against_trusted_roots(&trust)?;

        Ok(chain)
    }

    /// Constructor of test `X5ChainBuilder` instance.
    ///
    /// Do NOT use this method for production code, but only tests.
    #[cfg(any(feature = "test-utils", test))]
    pub fn dummy() -> Self {
        let trusted_root_certificate = "
-----BEGIN CERTIFICATE-----
MIICtTCCAlugAwIBAgIUUBHZN7ILx2HKEt6gRyoJZLqd/VkwCgYIKoZIzj0EAwIw
ZTELMAkGA1UEBhMCSFIxFDASBgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZa
YWdyZWIxDTALBgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMQ0wCwYDVQQD
DARyb290MB4XDTI0MTIxMDEyMjQzNVoXDTI1MTIxMDEyMjQzNVowZTELMAkGA1UE
BhMCSFIxFDASBgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZaYWdyZWIxDTAL
BgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMQ0wCwYDVQQDDARyb290MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzhErPPedB6my6XgHLLdaP7A8+UnWzwP/
Ad1dM0pDLQX55dYar7sbrW0MK4mh4ugIq5+SfCsT7w2OCaMjpCHJ86OB6DCB5TAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQmdvN008MlNbAgMH/aVuXuONeT3TCB
ogYDVR0jBIGaMIGXgBQmdvN008MlNbAgMH/aVuXuONeT3aFppGcwZTELMAkGA1UE
BhMCSFIxFDASBgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZaYWdyZWIxDTAL
BgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMQ0wCwYDVQQDDARyb290ghRQ
Edk3sgvHYcoS3qBHKglkup39WTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID
SAAwRQIhAJapLmxoEijACBXoF86NllGQMKcSTRt9xOXX8wR49HYzAiB1XSSiYyts
bFaZiu2snG0IMMh0tYsJoBnI7XR+ibwipA==
-----END CERTIFICATE-----
";

        let private_key = "
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJgsox2ShM8Ad+4LufmYKR8A9OGXonGjHiGoWvTbEM/4oAoGCCqGSM49
AwEHoUQDQgAEHURmvtjh4mlmkd/kSet4RhGFgeIo1LuxaYYiAgzdCf38QQTfBN1P
3LU93jEquUsj2DLxJrNijDsQ8pL4OiIRYA==
-----END EC PRIVATE KEY-----
";

        let certificate = "
-----BEGIN CERTIFICATE-----
MIICOjCCAeCgAwIBAgIUN7oyPwxqLe2xDMLjDva0HqqKDXwwCgYIKoZIzj0EAwIw
ZTELMAkGA1UEBhMCSFIxFDASBgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZa
YWdyZWIxDTALBgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMQ0wCwYDVQQD
DARyb290MCAXDTI0MTIxMDEyMjQzNVoYDzIxMjQxMTE2MTIyNDM1WjBrMQswCQYD
VQQGEwJIUjEUMBIGA1UECAwLR3JhZCBaYWdyZWIxDzANBgNVBAcMBlphZ3JlYjEN
MAsGA1UECgwEVEJUTDERMA8GA1UECwwIVGVhbSBCZWUxEzARBgNVBAMMCmNvY29u
dXQtY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQdRGa+2OHiaWaR3+RJ63hG
EYWB4ijUu7FphiICDN0J/fxBBN8E3U/ctT3eMSq5SyPYMvEms2KMOxDykvg6IhFg
o2YwZDAdBgNVHQ4EFgQU1R2/SVp29ncQnwtDM6Jpqy4LRnkwHwYDVR0jBBgwFoAU
JnbzdNPDJTWwIDB/2lbl7jjXk90wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8B
Af8EBAMCAYYwCgYIKoZIzj0EAwIDSAAwRQIhANa2uWuaWL/dftBFR3p+ZWJh7X5j
WEAa6VtMpmEa6fTbAiB5N96N2rCIb4giGO86YQBPoWSRA6Qj/babKniAYsJLqQ==
-----END CERTIFICATE-----
";

        Self::new(private_key, certificate, trusted_root_certificate).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use iref::UriBuf;

    use super::Builder;

    #[test]
    fn dummy_generates_valid_x5chain() {
        let public_key = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFIG72O1w04AJgPP/7D8j2oJsOlFD
lbTn6vhkz27afs3GyXfRCsdaMirozmhYm94VB4IdwyVYtSVz6rce4Ut+hg==
-----END PUBLIC KEY-----";

        let iss = UriBuf::new("https://example.com/issuer".into()).unwrap();

        assert!(Builder::dummy()
            .generate_x5chain(public_key, Some(&iss))
            .is_ok());
    }
}
