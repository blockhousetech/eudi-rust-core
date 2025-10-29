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

use std::collections::HashSet;

use crate::check_256bit_len;
use crate::openssl_ec_priv_key_to_jwk;
use crate::public_key_from_jwk_es256;
use crate::CryptoError;
use crate::EcPrivate;
use crate::FormatError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bherror::traits::ForeignError;
use openssl::bn::BigNum;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::Deserializer;
use serde::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A JSON object meant to represent a public JWK.
///
/// Since this is a type alias, no aspects of the schema are enforced; this is
/// left to any end-consumers of the public key, such as
/// [`SignatureVerifier`](crate::SignatureVerifier).
pub type JwkPublic = Map<String, Value>;

/// Struct representing private JWK - public JWK + private key part of JWK.
///
/// JWK schema is not enforced; this is left to any end-consumers of the private key.
///
/// Note: Reason for having a special struct for private JWK is handling of
///       private key part more carefully (storing in in `SecretString`).
#[derive(Serialize, Deserialize)]
pub struct JwkPrivate {
    /// Public part of JWK. [RFC7518]
    ///
    /// [RFC7518]: https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1
    #[serde(flatten)]
    pub jwk_public: JwkPublic,
    /// Private key part of JWK - "d" parameter containing the Elliptic
    /// Curve private key value. [RFC7518]
    ///
    /// [RFC7518]: https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2.1
    #[serde(
        rename = "d", // NOTE: attribute requires a string literal, could not place a constant
                      // variable here
        serialize_with = "serialize_secret_string",
        deserialize_with = "deserialize_secret_string"
    )]
    pub private_key_part: SecretString,
}

fn serialize_secret_string<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(secret.expose_secret())
}

fn deserialize_secret_string<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(SecretString::from(s))
}

impl TryFrom<&EcPrivate> for JwkPrivate {
    type Error = bherror::Error<CryptoError>;

    fn try_from(key: &EcPrivate) -> Result<Self, Self::Error> {
        openssl_ec_priv_key_to_jwk(key, None)
    }
}

impl TryInto<EcPrivate> for &JwkPrivate {
    type Error = bherror::Error<FormatError>;

    fn try_into(self) -> Result<EcPrivate, Self::Error> {
        let d = URL_SAFE_NO_PAD
            .decode(self.private_key_part.expose_secret())
            .foreign_err(|| {
                FormatError::JwkParsingFailed("decoding private key part failed".to_string())
            })?;
        let d = BigNum::from_slice(check_256bit_len(&d)?).foreign_err(|| {
            FormatError::JwkParsingFailed("Failed to construct BigNum".to_string())
        })?;

        let public_key = public_key_from_jwk_es256(&self.jwk_public)?;

        EcPrivate::from_private_components(public_key.group(), d.as_ref(), public_key.public_key())
            .foreign_err(|| {
                FormatError::JwkParsingFailed("private key construction failed".to_string())
            })
    }
}

/// Models JWK Set. A JSON object that represents a set of JWKs.
///
/// If any of the JWKs in the JWK Set have parameter `kid` then all of them
/// should have `kid` parameter and different keys within the JWK Set SHOULD use
/// distinct `kid` values.
///
/// NOTE: The notion of different keys can be somewhat subtle. The [RFC] gives
/// the following example - different keys might use the same `kid` value if
/// they have different "kty" (key type) values but are considered to be
/// equivalent alternatives by the application using them. This implementation
/// currently does not support this example, uniqueness of keys is checked if
/// they contain `kid` values and equality between them is checked using only
/// `kid` values.
///
/// For more details see [RFC7517][RFC].
///
/// [RFC]: https://datatracker.ietf.org/doc/html/rfc7517#section-5
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(try_from = "JwkSetUnverified")]
pub struct JwkSet {
    // TODO(issues/13): keys member variable should not be public because it could be modified such
    //                  that JwkSet is an invalid one
    /// Underlying representation of the JWK Set.
    pub keys: Vec<JwkPublic>,
}

impl JwkSet {
    /// Create empty `JwkSet`.
    pub fn empty() -> Self {
        JwkSet { keys: vec![] }
    }
}

/// This is a "shadow" type whose sole purpose of existence is to be able to
/// verify validity of deserialized [JwkSet] without writing deserialization
/// manually. This is achieved with misuse of `TryFrom` trait. For more info see
/// this [github issue].
///
/// [github issue]: https://github.com/serde-rs/serde/issues/642
#[derive(Deserialize, Debug)]
struct JwkSetUnverified {
    // TODO(issues/13) change this to set if it does not include a lot of work
    keys: Vec<JwkPublic>,
}

impl TryFrom<JwkSetUnverified> for JwkSet {
    type Error = &'static str;

    fn try_from(value: JwkSetUnverified) -> std::result::Result<Self, Self::Error> {
        let keys = value.keys;
        let jwk_with_kid_cnt = keys.iter().filter(|jwk| jwk.contains_key("kid")).count();

        if jwk_with_kid_cnt == 0 {
            return Ok(JwkSet { keys });
        }
        if jwk_with_kid_cnt != keys.len() {
            return Err("Some of the provided JWKs contain kid parameter values and some don't");
        }

        let mut uniq = HashSet::new();
        for key in keys.iter() {
            if !uniq.insert(
                key.get("kid")
                    .unwrap() // safe unwrap because of all jwks contain `kid` value
                    .as_str()
                    .ok_or("JWK contains a `kid` parameter that is not a string")?,
            ) {
                return Err("Provided JWKs contain duplicate kid parameter values");
            }
        }

        Ok(JwkSet { keys })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::json;

    use crate::JwkSet;

    // https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1
    #[test]
    fn jwk_set_example_serialization() {
        let jwk_set = json!({"keys":
          [
            {"kty":"EC",
             "crv":"P-256",
             "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
             "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
             "use":"enc",
             "kid":"1"},

            {"kty":"RSA",
             "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
      4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
      tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
      QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
      SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
      w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
             "e":"AQAB",
             "alg":"RS256",
             "kid":"2011-04-29"}
          ]
        });

        let deserialized = serde_json::from_str::<JwkSet>(jwk_set.to_string().as_str()).unwrap();
        let serialized = serde_json::to_string(&deserialized).unwrap();

        let keys = deserialized.keys;
        assert_eq!(
            keys.first().unwrap().get("kid").unwrap().as_str().unwrap(),
            "1"
        );
        assert_eq!(
            keys.get(1).unwrap().get("kid").unwrap().as_str().unwrap(),
            "2011-04-29"
        );
        assert_eq!(serialized, jwk_set.to_string().as_str());
    }

    #[test]
    fn invalid_jwk_set_duplicate_kid() {
        let jwk_set = json!({"keys":
          [
            { "kid": "1" },
            { "kid": "1" }
          ]
        });

        let error = serde_json::from_str::<JwkSet>(jwk_set.to_string().as_str());

        assert_eq!(
            error.unwrap_err().to_string(),
            "Provided JWKs contain duplicate kid parameter values"
        );
    }

    #[test]
    fn jwk_without_kid() {
        let jwk_set = json!({"keys":
          [
            { "key": "1" },
            { "key": "1" }
          ]
        });

        let keys = serde_json::from_str::<JwkSet>(jwk_set.to_string().as_str())
            .unwrap()
            .keys;

        assert_eq!(
            keys.first().unwrap().get("key").unwrap().as_str().unwrap(),
            "1"
        );
        assert_eq!(
            keys.get(1).unwrap().get("key").unwrap().as_str().unwrap(),
            "1"
        );
    }

    #[test]
    fn invalid_jwk_set_some_jwks_without_kid() {
        let jwk_set = json!({"keys":
          [
            { "kid": "1" },
            { "key": "1" }
          ]
        });

        let error = serde_json::from_str::<JwkSet>(jwk_set.to_string().as_str());

        assert_eq!(
            error.unwrap_err().to_string(),
            "Some of the provided JWKs contain kid parameter values and some don't"
        );
    }
}
