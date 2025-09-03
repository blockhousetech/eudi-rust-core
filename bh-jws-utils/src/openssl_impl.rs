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

use std::result::Result as StdResult;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bherror::{
    traits::{ErrorContext, ForeignError, PropagateError as _},
    Error, Result,
};
use iref::UriBuf;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcGroupRef, EcKey, EcPointRef},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{Private, Public},
    sha::sha256,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{utils, HasJwkKid, SignatureVerifier, Signer, SigningAlgorithm};
use crate::{
    error::{CryptoError, FormatError},
    json_object, BoxError, JwkPublic,
};

type EcPrivate = EcKey<Private>;
type EcPublic = EcKey<Public>;

/// A 32-byte coordinate for the elliptic curve.
pub type Coordinate = [u8; 32];

// X9_62_PRIME256V1 is basically an alias for secp256r1
//
// ------------------------------------------
//           Curve names chosen by
//      different standards organizations
// ------------+---------------+-------------
// SECG        |  ANSI X9.62   |  NIST
// ------------+---------------+-------------
// secp256r1   |  prime256v1   |   NIST P-256
//
// source: https://tools.ietf.org/search/rfc4492#appendix-A
pub(crate) const ELLIPTIC_CURVE_NID: Nid = Nid::X9_62_PRIME256V1;

/// [`Signer`] implementation supporting the `ES256` algorithm (ECDSA using the
/// P-256 curve and the SHA-256 hash function).
#[derive(Serialize, Deserialize)]
pub struct Es256Signer {
    #[serde(serialize_with = "serialize_key")]
    #[serde(deserialize_with = "deserialize_key")]
    pub(crate) private_key: EcPrivate,
    kid: String,
}

/// [`Signer`] implementation supporting the `ES256` algorithm (ECDSA using the P-256 curve and the
/// SHA-256 hash function). This is a wrapper over `Es256Signer` that adds support for producing
/// [`X5Chain`](bhx5chain::X5Chain).
pub type Es256SignerWithChain = crate::SignerWithChain<Es256Signer>;

const CRV: &str = "P-256";
const ALG: &str = "ES256";
const KTY: &str = "EC";

/// Returns the affine coordinates of the public key.
///
/// The intended use case for this method is when serializing the public key
/// in formats other than the explicitly supported ones.
fn to_affine_coords(
    point: &EcPointRef,
    group: &EcGroupRef,
) -> Result<(Box<Coordinate>, Box<Coordinate>), CryptoError> {
    let mut x = BigNum::new().foreign_err(|| CryptoError::CryptoBackend)?;
    let mut y = BigNum::new().foreign_err(|| CryptoError::CryptoBackend)?;
    let mut ctx = BigNumContext::new().foreign_err(|| CryptoError::CryptoBackend)?;
    point
        .affine_coordinates(group, &mut x, &mut y, &mut ctx)
        .foreign_err(|| CryptoError::CryptoBackend)?;

    // The unwraps are safe, as we choose the length correctly
    let x = x
        .to_vec_padded(32)
        .foreign_err(|| CryptoError::CryptoBackend)?
        .try_into()
        .unwrap();
    let y = y
        .to_vec_padded(32)
        .foreign_err(|| CryptoError::CryptoBackend)?
        .try_into()
        .unwrap();
    Ok((x, y))
}

impl Es256Signer {
    /// Generate a fresh `ES256` key with the given `kid` field when presented as a JWK.
    pub fn generate(kid: String) -> Result<Self, CryptoError> {
        let ec_group = EcGroup::from_curve_name(ELLIPTIC_CURVE_NID)
            .foreign_err(|| CryptoError::CryptoBackend)?;
        let private_key = EcKey::<Private>::generate(ec_group.as_ref())
            .foreign_err(|| CryptoError::KeyGenerationFailed)?;

        Ok(Self { private_key, kid })
    }

    /// Create a `ES256` signer from private key in the PEM format.
    pub fn from_private_key_pem(kid: String, private_key_pem: &[u8]) -> Result<Self, CryptoError> {
        let private_key = EcPrivate::private_key_from_pem(private_key_pem)
            .foreign_err(|| CryptoError::CryptoBackend)?;

        Ok(Self { private_key, kid })
    }

    /// Construct a JWK JSON object for the public counterpart of this key. It
    /// will use the `kid` field set at construction.
    pub fn public_jwk(&self) -> Result<JwkPublic, CryptoError> {
        let (x_bytes, y_bytes) =
            to_affine_coords(self.private_key.public_key(), self.private_key.group())?;

        Ok(ec_public_affine_coords_to_jwk(
            &x_bytes,
            &y_bytes,
            Some(&self.kid),
        ))
    }
}

/// Construct a JWK JSON object for this public key.
/// **Note**: only ECDSA keys using P-256 curve are supported!
pub fn openssl_ec_pub_key_to_jwk(
    key: &EcKey<Public>,
    kid: Option<&str>,
) -> Result<JwkPublic, CryptoError> {
    let (x_bytes, y_bytes) = to_affine_coords(key.public_key(), key.group())?;
    Ok(ec_public_affine_coords_to_jwk(&x_bytes, &y_bytes, kid))
}

/// Constructs the JWK from the coordinates of the public ECDSA key using P-256
/// curve.
///
/// **Note**: this function **DOES NOT** check that the coordinates are valid.
pub fn ec_public_affine_coords_to_jwk(
    x_bytes: &[u8; 32],
    y_bytes: &[u8; 32],
    kid: Option<&str>,
) -> JwkPublic {
    let x = utils::base64_url_encode(x_bytes);
    let y = utils::base64_url_encode(y_bytes);

    let mut jwk = json_object!({
        "kty": KTY,
        "alg": ALG,
        "use": "sig",
        "crv": CRV,
        "x": x,
        "y": y,
    });

    if let Some(kid) = kid {
        jwk.insert("kid".to_owned(), serde_json::Value::String(kid.to_owned()));
    }

    jwk
}

impl Es256SignerWithChain {
    /// Generate a fresh `ES256` key with the given `kid` field when presented
    /// as a JWK.
    #[deprecated(note = "use `SignerWithChain::new` instead")]
    pub fn generate(
        kid: String,
        iss: Option<&UriBuf>,
        builder: &bhx5chain::Builder,
    ) -> Result<Self, CryptoError> {
        let signer = Es256Signer::generate(kid)?;

        let private_key = signer
            .private_key
            .private_key_to_pem()
            .foreign_err(|| CryptoError::CryptoBackend)?;

        let x5chain = builder
            .generate_x5chain(&private_key, iss)
            .foreign_err(|| CryptoError::InvalidX5Chain)?;

        Ok(Self { signer, x5chain })
    }

    /// Create a `ES256` signer from private key in PEM format and
    /// [`bhx5chain::Builder`].
    ///
    /// The `builder` will create valid [`bhx5chain::X5Chain`] with leaf
    /// certificate associated to key from `private_key_pem`.
    #[deprecated(note = "use `SignerWithChain::new` instead")]
    pub fn from_private_key(
        kid: String,
        iss: Option<&UriBuf>,
        private_key_pem: &[u8],
        builder: &bhx5chain::Builder,
    ) -> Result<Self, CryptoError> {
        let signer = Es256Signer::from_private_key_pem(kid, private_key_pem)?;

        let x5chain = builder
            .generate_x5chain(private_key_pem, iss)
            .with_err(|| CryptoError::InvalidX5Chain)?;

        Ok(Self { signer, x5chain })
    }
}

impl Signer for Es256Signer {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Es256
    }

    fn sign(&self, message: &[u8]) -> StdResult<Vec<u8>, BoxError> {
        let digest = sha256(message);
        let signature = EcdsaSig::sign(&digest, self.private_key.as_ref())?;

        // The unwraps are safe, as we've requested a vector of the exact same size as the array
        let r: Box<[u8; 32]> = signature.r().to_vec_padded(32)?.try_into().unwrap();
        let s: Box<[u8; 32]> = signature.s().to_vec_padded(32)?.try_into().unwrap();
        let mut jws = (r as Box<[_]>).into_vec();
        jws.extend_from_slice(&*s);
        Ok(jws)
    }

    fn public_jwk(&self) -> StdResult<JwkPublic, BoxError> {
        Ok(self.public_jwk()?)
    }
}

impl HasJwkKid for Es256Signer {
    fn jwk_kid(&self) -> &str {
        &self.kid
    }
}

impl HasJwkKid for Es256SignerWithChain {
    fn jwk_kid(&self) -> &str {
        &self.signer.kid
    }
}

/// [`SignatureVerifier`] implementation supporting the `ES256` algorithm (ECDSA
/// using the P-256 curve and the SHA-256 hash function).
#[derive(Default)]
pub struct Es256Verifier;

impl SignatureVerifier for Es256Verifier {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Es256
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &JwkPublic,
    ) -> StdResult<bool, BoxError> {
        let public_key = public_key_from_jwk_es256(public_key)?;
        let jws_bytes = <&[u8; 64]>::try_from(signature)?;
        let (r, s) = jws_bytes.split_at(32);
        let r = BigNum::from_slice(r)?;
        let s = BigNum::from_slice(s)?;
        let ecdsa_sig = EcdsaSig::from_private_components(r, s)?;

        let digest = sha256(message);

        let valid_signature = ecdsa_sig.verify(&digest, public_key.as_ref())?;
        if !valid_signature {
            return Ok(false);
        }

        Ok(true)
    }
}

pub(crate) fn public_key_from_jwk_es256(public_key: &JwkPublic) -> Result<EcPublic, FormatError> {
    check_jwk_field(public_key, "kty", KTY)?;
    check_jwk_field(public_key, "crv", CRV)?;

    let x = parse_coord(public_key, "x")?;
    let x = BigNum::from_slice(check_len(&x)?)
        .foreign_err(|| FormatError::JwkParsingFailed("Failed to construct BigNum".to_string()))?;
    let y = parse_coord(public_key, "y")?;
    let y = BigNum::from_slice(check_len(&y)?)
        .foreign_err(|| FormatError::JwkParsingFailed("Failed to construct BigNum".to_string()))?;

    // The unwrap is safe because we always use the same curve.
    let group = EcGroup::from_curve_name(ELLIPTIC_CURVE_NID).unwrap();
    let public_key =
        EcPublic::from_public_key_affine_coordinates(group.as_ref(), x.as_ref(), y.as_ref())
            .foreign_err(|| {
                FormatError::JwkParsingFailed("coordinate construction failed".to_string())
            })?;
    Ok(public_key)
}

fn check_len(coord: &[u8]) -> Result<&[u8; 32], FormatError> {
    <&[u8; 32]>::try_from(coord)
        .foreign_err(|| FormatError::JwkParsingFailed("parsing coord failed".to_string()))
        .ctx(|| format!("check len of {:?} failed", coord))
}

fn check_jwk_field(
    public_key: &JwkPublic,
    field: &str,
    expected_value: &str,
) -> Result<(), FormatError> {
    let error = |message| Error::root(FormatError::JwkParsingFailed(message));

    let value = public_key
        .get(field)
        .ok_or_else(|| error(format!("missing \"{}\" field", field)))?;

    if value == expected_value {
        return Ok(());
    }

    Err(error(format!("incorrect value on \"{}\" field", field))).ctx(|| {
        format!(
            "value on field \"{}\" was {}, expected {}",
            field, value, expected_value
        )
    })
}

fn parse_coord(public_key: &JwkPublic, coord: &str) -> Result<Vec<u8>, FormatError> {
    let error = |message| bherror::Error::root(FormatError::JwkParsingFailed(message));

    let coord = public_key
        .get(coord)
        .ok_or_else(|| error(format!("fetching coordinate {} failed", coord)))?;
    let base64_coord = coord
        .as_str()
        .ok_or_else(|| error("coord not str".to_string()))
        .ctx(|| format!("coord {0} as str failed", coord))?;
    URL_SAFE_NO_PAD
        .decode(base64_coord)
        .foreign_err(|| FormatError::JwkParsingFailed("decoding coord failed".to_string()))
        .ctx(|| format!("decoding coord {0} failed", base64_coord))
}

/// Serialize the private key to PEM format.
fn serialize_key<S>(key: &EcPrivate, serializer: S) -> StdResult<S::Ok, S::Error>
where
    S: Serializer,
{
    let pem = key
        .private_key_to_pem()
        .map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&pem)
}

/// Deserialize the private key from PEM format.
fn deserialize_key<'de, D>(deserializer: D) -> StdResult<EcPrivate, D::Error>
where
    D: Deserializer<'de>,
{
    EcPrivate::private_key_from_pem(
        <&[u8]>::deserialize(deserializer).map_err(serde::de::Error::custom)?,
    )
    .map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::Value;

    use super::*;

    fn simple_verify_setup() -> (JwkPublic, [u8; 25], Vec<u8>) {
        let signer = Es256Signer::generate("test key id".to_owned()).unwrap();
        let public_jwk = signer.public_jwk().unwrap();

        let message = b"Test message to be signed";
        let signature = signer.sign(message).unwrap();

        (public_jwk, *message, signature)
    }

    #[test]
    fn sign_verify_bytes() {
        let (public_jwk, message, signature) = simple_verify_setup();

        Es256Verifier
            .verify(&message, &signature, &public_jwk)
            .unwrap();
    }

    #[test]
    fn es256_verifier_invalid_jwk_missing_kty_field() {
        let (mut public_jwk, message, signature) = simple_verify_setup();

        public_jwk.remove("kty");

        let error = Es256Verifier
            .verify(&message, &signature, &public_jwk)
            .unwrap_err();

        assert_eq!(
            error.downcast::<Error<FormatError>>().unwrap().error,
            FormatError::JwkParsingFailed("missing \"kty\" field".to_string())
        );
    }

    #[test]
    fn es256_verifier_invalid_jwk_invalid_kty_field() {
        let (mut public_jwk, message, signature) = simple_verify_setup();

        public_jwk.insert("kty".to_string(), Value::String("bla".to_string()));

        let error = Es256Verifier
            .verify(&message, &signature, &public_jwk)
            .unwrap_err();

        assert_eq!(
            error.downcast::<Error<FormatError>>().unwrap().error,
            FormatError::JwkParsingFailed("incorrect value on \"kty\" field".to_string())
        );
    }

    #[test]
    fn verify_jwt() {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#appendix-A.5-2
        let public_jwk = json_object!({
            "kty": "EC",
            "crv": "P-256",
            "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
            "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
        });

        // Modified from: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#appendix-A.3-53
        // to include only the issuer jwt part.
        let jwt = "\
            eyJhbGciOiAiRVMyNTYiLCAidHlwIjogInZjK3NkLWp3dCJ9.eyJfc2QiOiBbIjBIWm1\
            uU0lQejMzN2tTV2U3QzM0bC0tODhnekppLWVCSjJWel9ISndBVGciLCAiOVpicGxDN1R\
            kRVc3cWFsNkJCWmxNdHFKZG1lRU9pWGV2ZEpsb1hWSmRSUSIsICJJMDBmY0ZVb0RYQ3V\
            jcDV5eTJ1anFQc3NEVkdhV05pVWxpTnpfYXdEMGdjIiwgIklFQllTSkdOaFhJbHJRbzU\
            4eWtYbTJaeDN5bGw5WmxUdFRvUG8xN1FRaVkiLCAiTGFpNklVNmQ3R1FhZ1hSN0F2R1R\
            yblhnU2xkM3o4RUlnX2Z2M2ZPWjFXZyIsICJodkRYaHdtR2NKUXNCQ0EyT3RqdUxBY3d\
            BTXBEc2FVMG5rb3ZjS09xV05FIiwgImlrdXVyOFE0azhxM1ZjeUE3ZEMtbU5qWkJrUmV\
            EVFUtQ0c0bmlURTdPVFUiLCAicXZ6TkxqMnZoOW80U0VYT2ZNaVlEdXZUeWtkc1dDTmc\
            wd1RkbHIwQUVJTSIsICJ3elcxNWJoQ2t2a3N4VnZ1SjhSRjN4aThpNjRsbjFqb183NkJ\
            DMm9hMXVnIiwgInpPZUJYaHh2SVM0WnptUWNMbHhLdUVBT0dHQnlqT3FhMXoySW9WeF9\
            ZRFEiXSwgImlzcyI6ICJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsICJpYXQiOiA\
            xNjgzMDAwMDAwLCAiZXhwIjogMTg4MzAwMDAwMCwgInZjdCI6ICJodHRwczovL2JtaS5\
            idW5kLmV4YW1wbGUvY3JlZGVudGlhbC9waWQvMS4wIiwgImFnZV9lcXVhbF9vcl9vdmV\
            yIjogeyJfc2QiOiBbIkZjOElfMDdMT2NnUHdyREpLUXlJR085N3dWc09wbE1Makh2UkM\
            0UjQtV2ciLCAiWEx0TGphZFVXYzl6Tl85aE1KUm9xeTQ2VXNDS2IxSXNoWnV1cVVGS1N\
            DQSIsICJhb0NDenNDN3A0cWhaSUFoX2lkUkNTQ2E2NDF1eWNuYzh6UGZOV3o4bngwIiw\
            gImYxLVAwQTJkS1dhdnYxdUZuTVgyQTctRVh4dmhveHY1YUhodUVJTi1XNjQiLCAiazV\
            oeTJyMDE4dnJzSmpvLVZqZDZnNnl0N0Fhb25Lb25uaXVKOXplbDNqbyIsICJxcDdaX0t\
            5MVlpcDBzWWdETzN6VnVnMk1GdVBOakh4a3NCRG5KWjRhSS1jIl19LCAiX3NkX2FsZyI\
            6ICJzaGEtMjU2IiwgImNuZiI6IHsiandrIjogeyJrdHkiOiAiRUMiLCAiY3J2IjogIlA\
            tMjU2IiwgIngiOiAiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkN\
            lR2VtYyIsICJ5IjogIlp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ\
            5RjJIWlEifX19.jeF9GjGbjCr0NND0SbkV4HeSpsysixALFScJl4bYkIykXhF6cRtqni\
            64_d7X6Ef8Rx80rfsgXe0H7TdiSoIJOw";

        // Can't use `jwt::Header` since it doesn't recognize `"typ": "vc+sd-jwt"`,
        // can't use `crate::IssuerJwtHeader` since this example lacks `kid` ...
        #[derive(Debug, Deserialize)]
        struct MinimalHeader {
            alg: jwt::AlgorithmType,
        }
        impl jwt::JoseHeader for MinimalHeader {
            fn algorithm_type(&self) -> jwt::AlgorithmType {
                self.alg
            }
        }

        let _: jwt::Token<MinimalHeader, Value, _> =
            utils::verify_jwt_signature(jwt, &Es256Verifier, &public_jwk).unwrap();
    }
}
