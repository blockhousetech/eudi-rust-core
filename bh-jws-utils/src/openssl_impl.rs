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

use crate::JwkPrivate;
use serde_json::Map;
use serde_json::Value;
use std::result::Result as StdResult;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bherror::{
    traits::{ErrorContext, ForeignError},
    Error, Result,
};
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
use openssl::bn::BigNumRef;
use serde::ser::SerializeMap;

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
    #[serde(
        flatten,
        serialize_with = "serialize_key_jwk",
        deserialize_with = "deserialize_key_jwk"
    )]
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
    pub fn from_private_key_pem(kid: String, private_key_pem: &str) -> Result<Self, CryptoError> {
        let private_key = EcPrivate::private_key_from_pem(private_key_pem.as_bytes())
            .foreign_err(|| CryptoError::CryptoBackend)?;

        Ok(Self { private_key, kid })
    }

    /// Return the private key in PEM format.
    pub fn private_key_pem(&self) -> Result<String, CryptoError> {
        let private_key_pem = self
            .private_key
            .private_key_to_pem()
            .foreign_err(|| CryptoError::CryptoBackend)?;

        Ok(String::from_utf8(private_key_pem).expect("PEM should be valid UTF-8"))
    }

    /// Return the corresponding public key in PEM format.
    pub fn public_key_pem(&self) -> Result<String, CryptoError> {
        let public_key_pem = self
            .private_key
            .public_key_to_pem()
            .foreign_err(|| CryptoError::CryptoBackend)?;

        Ok(String::from_utf8(public_key_pem).expect("PEM should be valid UTF-8"))
    }

    /// Construct a JWK JSON object for this **private** key.
    /// It will use the `kid` field set at construction.
    pub fn private_jwk(&self) -> Result<JwkPrivate, CryptoError> {
        openssl_ec_priv_key_to_jwk(&self.private_key, Some(&self.kid))
    }

    /// Construct a JWK JSON object for the **public** counterpart of this key.
    /// It will use the `kid` field set at construction.
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

/// Serialize the private key to JWK format.
fn serialize_key_jwk<S>(private_key: &EcPrivate, serializer: S) -> StdResult<S::Ok, S::Error>
where
    S: Serializer,
{
    let jwk = openssl_ec_priv_key_to_jwk(private_key, None).map_err(serde::ser::Error::custom)?;

    let mut map = serializer.serialize_map(Some(jwk.len()))?;
    for (key, value) in jwk {
        map.serialize_entry(&key, &value)?;
    }
    map.end()
}
/// Deserialize the private key from JWK format.
fn deserialize_key_jwk<'de, D>(deserializer: D) -> StdResult<EcPrivate, D::Error>
where
    D: Deserializer<'de>,
{
    let jwk = serde_json::Map::deserialize(deserializer).map_err(serde::de::Error::custom)?;
    let d = parse_coord(&jwk, "d").map_err(serde::de::Error::custom)?;
    let public_key = public_key_from_jwk_es256(&jwk).map_err(serde::de::Error::custom)?;

    EcPrivate::from_private_components(public_key.group(), d.as_ref(), public_key.public_key())
        .foreign_err(|| {
            FormatError::JwkParsingFailed("private key construction failed".to_string())
        })
        .map_err(serde::de::Error::custom)
}

/// Construct a JWK JSON object for provided **public** key.
/// **Note**: only ECDSA keys using P-256 curve are supported!
pub fn openssl_ec_pub_key_to_jwk(
    key: &EcPublic,
    kid: Option<&str>,
) -> Result<JwkPublic, CryptoError> {
    let (x_bytes, y_bytes) = to_affine_coords(key.public_key(), key.group())?;
    Ok(ec_public_affine_coords_to_jwk(&x_bytes, &y_bytes, kid))
}

/// Constructs a JWK JSON object for provided **private** key.
/// **Note**: only ECDSA keys using P-256 curve are supported!
fn openssl_ec_priv_key_to_jwk(
    private_key: &EcPrivate,
    kid: Option<&str>,
) -> Result<JwkPrivate, CryptoError> {
    let (x_bytes, y_bytes) = to_affine_coords(private_key.public_key(), private_key.group())?;
    let d_bytes = bignum_to_vec32_bytes(private_key.private_key())?;

    Ok(ec_private_affine_coords_to_jwk(
        &x_bytes, &y_bytes, &d_bytes, kid,
    ))
}

/// Constructs the JWK from the coordinates of the **public** ECDSA key using
/// P-256 curve.
///
/// **Note**: this function **DOES NOT** check that the coordinates are valid.
fn ec_public_affine_coords_to_jwk(
    x_bytes: &[u8; 32],
    y_bytes: &[u8; 32],
    kid: Option<&str>,
) -> JwkPublic {
    ec_affine_coords_to_jwk(x_bytes, y_bytes, None, kid)
}

/// Constructs the JWK from the coordinates of the **private** ECDSA key using
/// P-256 curve.
///
/// **Note**: this function **DOES NOT** check that the coordinates are valid.
fn ec_private_affine_coords_to_jwk(
    x_bytes: &[u8; 32],
    y_bytes: &[u8; 32],
    d_bytes: &[u8; 32],
    kid: Option<&str>,
) -> JwkPrivate {
    ec_affine_coords_to_jwk(x_bytes, y_bytes, Some(d_bytes), kid)
}

/// Constructs the JWK from the coordinates of the ECDSA key using P-256
/// curve. If `d_bytes` parameter is provided JWK represents private key
/// values, in other case it provides public key values.
///
/// **Note**: this function **DOES NOT** check that the coordinates are valid.
fn ec_affine_coords_to_jwk(
    x_bytes: &[u8; 32],
    y_bytes: &[u8; 32],
    d_bytes: Option<&[u8; 32]>,
    kid: Option<&str>,
) -> Map<String, Value> {
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

    if let Some(d_bytes) = d_bytes {
        let d = utils::base64_url_encode(d_bytes);
        jwk.insert("d".to_owned(), serde_json::Value::String(d));
    }
    if let Some(kid) = kid {
        jwk.insert("kid".to_owned(), serde_json::Value::String(kid.to_owned()));
    }

    jwk
}

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

    let x = bignum_to_vec32_bytes(&x)?;
    let y = bignum_to_vec32_bytes(&y)?;
    Ok((x, y))
}

fn bignum_to_vec32_bytes(bignum: &BigNumRef) -> Result<Box<[u8; 32]>, CryptoError> {
    // Unwrap should be safe, since we set correct length of padded vec
    Ok(bignum
        .to_vec_padded(32)
        .foreign_err(|| CryptoError::CryptoBackend)?
        .try_into()
        .unwrap())
}

pub(crate) fn public_key_from_jwk_es256(public_key: &JwkPublic) -> Result<EcPublic, FormatError> {
    check_jwk_field(public_key, "kty", KTY)?;
    check_jwk_field(public_key, "crv", CRV)?;

    let x = parse_coord(public_key, "x")?;
    let y = parse_coord(public_key, "y")?;

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

fn parse_coord(public_key: &Map<String, Value>, coord: &str) -> Result<BigNum, FormatError> {
    let error = |message| bherror::Error::root(FormatError::JwkParsingFailed(message));

    let base64_coord = public_key
        .get(coord)
        .ok_or_else(|| error(format!("fetching coordinate {} failed", coord)))?
        .as_str()
        .ok_or_else(|| error("coord not str".to_string()))
        .ctx(|| format!("coord {0} as str failed", coord))?;
    let coord = URL_SAFE_NO_PAD
        .decode(base64_coord)
        .foreign_err(|| FormatError::JwkParsingFailed("decoding coord failed".to_string()))
        .ctx(|| format!("decoding coord {0} failed", base64_coord))?;
    BigNum::from_slice(check_len(&coord)?)
        .foreign_err(|| FormatError::JwkParsingFailed("Failed to construct BigNum".to_string()))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::Value;

    use super::*;

    // Test example from https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.2,
    // first key in the JWK set, converted to PEM manually
    // JWK from example was modified:
    //  - added "alg": "ES256"
    //  - changed "use" from "enc" to "sig"
    const TEST_JWK: &str = r#"{
            "alg": "ES256",
            "kty":"EC",
            "crv":"P-256",
            "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
            "use":"sig",
            "kid":"1"
        }"#;

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
    fn jwk_serialization() {
        let jwk: Value = serde_json::from_str(TEST_JWK).unwrap();
        let signer: Es256Signer = serde_json::from_value(jwk.clone()).unwrap();

        let round_trip_jwk = serde_json::to_value(signer).unwrap();

        assert_eq!(jwk, round_trip_jwk);
    }

    #[test]
    fn private_key_pem_serialization() {
        // PEM converted from JWK manually
        let jwk: Value = serde_json::from_str(TEST_JWK).unwrap();
        let expected_pem = include_str!("../files/private_key.pem");

        let signer: Es256Signer = serde_json::from_value(jwk).unwrap();
        let pem = signer.private_key_pem().unwrap();

        assert_eq!(pem, expected_pem);
    }

    #[test]
    fn public_key_pem_serialization() {
        // PEM converted from JWK manually
        let jwk: Value = serde_json::from_str(TEST_JWK).unwrap();
        let expected_pem = include_str!("../files/public_key.pem");

        let signer: Es256Signer = serde_json::from_value(jwk).unwrap();
        let pem = signer.public_key_pem().unwrap();

        assert_eq!(pem, expected_pem);
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
