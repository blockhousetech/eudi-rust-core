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

//! Util code over `coset` crate

use bh_jws_utils::{ec_public_affine_coords_to_jwk, SigningAlgorithm};
use bherror::traits::ForeignError as _;
use coset::{
    iana::{Algorithm, Ec2KeyParameter, EllipticCurve},
    AsCborValue, KeyType, Label,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::base64::base64_url_decode;
use crate::error::{MdocError, Result};

/// The default `kid` value of the Device's public key.
const DEFAULT_DEVICE_KID: &str = "device_kid";

pub(crate) fn serialize_coset<T, S>(
    cose_value: &T,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    T: AsCborValue + Clone,
    S: Serializer,
{
    let cbor_value = cose_value
        .clone()
        .to_cbor_value()
        .map_err(serde::ser::Error::custom)?;

    cbor_value.serialize(serializer)
}

pub(crate) fn deserialize_coset<'de, T, D>(deserializer: D) -> std::result::Result<T, D::Error>
where
    T: AsCborValue,
    D: Deserializer<'de>,
{
    let cbor_value = ciborium::Value::deserialize(deserializer)?;

    T::from_cbor_value(cbor_value).map_err(serde::de::Error::custom)
}

/// Method for converting JWK to CoseKey. For now we only support EC device keys. For more details
/// on COSE_Key specifications look
/// [here](https://datatracker.ietf.org/doc/html/rfc8152#section-13.1.1)
pub fn cose_key_from_jwk(
    jwk: &serde_json::Map<String, serde_json::Value>,
) -> Result<coset::CoseKey> {
    matches(jwk, "kty", "EC")?;
    matches(jwk, "crv", "P-256")?;

    let x = extract_coord(jwk, "x")?;
    let y = extract_coord(jwk, "y")?;

    Ok(coset::CoseKeyBuilder::new_ec2_pub_key(EllipticCurve::P_256, x, y).build())
}

/// Check if JWK has expected values for specific keys.
fn matches(
    jwk: &serde_json::Map<String, serde_json::Value>,
    key: &'static str,
    expected_value: &'static str,
) -> Result<()> {
    if jwk.get(key).is_some_and(|value| value != expected_value) {
        return Err(bherror::Error::root(MdocError::JwkToCoseKey(format!(
            "Expected key {key} with value {expected_value}"
        ))));
    }

    Ok(())
}

/// Extract coordinates from JWK.
fn extract_coord(
    jwk: &serde_json::Map<String, serde_json::Value>,
    coord_key: &'static str,
) -> Result<Vec<u8>> {
    let coord = jwk
        .get(coord_key)
        .and_then(|coord| coord.as_str())
        .ok_or_else(|| {
            bherror::Error::root(MdocError::JwkToCoseKey(format!(
                "Missing coordinate {coord_key} of type String"
            )))
        })?;

    base64_url_decode(coord)
        .foreign_err(|| MdocError::JwkToCoseKey(format!("Failed to decode coordinate {coord_key}")))
}

/// Converts the `COSE_Key` to JWK.
///
/// It currently supports only the `EC` keys and `P-256` curve.
pub fn cose_key_to_jwk(
    cose_key: &coset::CoseKey,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    if cose_key.kty != KeyType::Assigned(coset::iana::KeyType::EC2) {
        return Err(bherror::Error::root(MdocError::CoseKeyToJwk(
            "only EC keys are supported".to_owned(),
        )));
    }

    let curve = get_cose_key_param(cose_key, &Label::Int(Ec2KeyParameter::Crv as i64))?;
    if curve != &ciborium::Value::from(EllipticCurve::P_256 as u64) {
        return Err(bherror::Error::root(MdocError::CoseKeyToJwk(
            "only P-256 curve is supported".to_owned(),
        )));
    }

    let x = get_ec_key_param(cose_key, Ec2KeyParameter::X)?;
    let y = get_ec_key_param(cose_key, Ec2KeyParameter::Y)?;

    Ok(ec_public_affine_coords_to_jwk(
        x,
        y,
        Some(DEFAULT_DEVICE_KID),
    ))
}

/// Returns the `EC` key parameter from the `params` attribute of the provided
/// `COSE_Key`.
///
/// Its value **MUST BE** a 32-byte vector.
fn get_ec_key_param(cose_key: &coset::CoseKey, param: Ec2KeyParameter) -> Result<&[u8; 32]> {
    let ciborium::Value::Bytes(value) = get_cose_key_param(cose_key, &Label::Int(param as i64))?
    else {
        return Err(bherror::Error::root(MdocError::CoseKeyToJwk(format!(
            "{:?} parameter MUST BE bytes",
            param
        ))));
    };
    value
        .as_slice()
        .try_into()
        .foreign_err(|| MdocError::CoseKeyToJwk(format!("{:?} MUST HAVE 32 bytes", param)))
}

/// Returns the param with the given [`Label`] from the `params` attribute of
/// the provided `COSE_Key`.
///
/// If there are multiple entries with the given [`Label`], only the first-one
/// is returned.
fn get_cose_key_param<'a>(
    cose_key: &'a coset::CoseKey,
    label: &Label,
) -> Result<&'a ciborium::Value> {
    cose_key
        .params
        .iter()
        .find_map(|(l, v)| (l == label).then_some(v))
        .ok_or_else(|| {
            bherror::Error::root(MdocError::CoseKeyToJwk(format!(
                "key param {:?} not found",
                label
            )))
        })
}

/// Maps the [`coset::Algorithm`] to the [`SigningAlgorithm`].
///
/// If the [`coset::Algorithm`] is not supported, [`None`] is returned.
pub(crate) fn coset_alg_to_jws_alg(alg: &Algorithm) -> Option<SigningAlgorithm> {
    Some(match alg {
        Algorithm::ES256 => SigningAlgorithm::Es256,
        Algorithm::ES384 => SigningAlgorithm::Es384,
        Algorithm::ES512 => SigningAlgorithm::Es512,
        Algorithm::PS256 => SigningAlgorithm::Ps256,
        Algorithm::PS384 => SigningAlgorithm::Ps384,
        Algorithm::PS512 => SigningAlgorithm::Ps512,
        _ => return None,
    })
}

/// Maps the [`SigningAlgorithm`] to the [`Algorithm`].
pub(crate) fn jws_alg_to_coset_alg(alg: &SigningAlgorithm) -> Algorithm {
    match alg {
        SigningAlgorithm::Es256 => Algorithm::ES256,
        SigningAlgorithm::Es384 => Algorithm::ES384,
        SigningAlgorithm::Es512 => Algorithm::ES512,
        SigningAlgorithm::Ps256 => Algorithm::PS256,
        SigningAlgorithm::Ps384 => Algorithm::PS384,
        SigningAlgorithm::Ps512 => Algorithm::PS512,
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::cose_key_from_jwk;
    use crate::MdocError;

    #[test]
    fn cose_key_from_ec_jwk() {
        let jwk = serde_json::json!({
            "kty":"EC",
            "crv":"P-256",
            "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "use":"enc",
            "kid":"1",
        })
        .as_object()
        .cloned()
        .unwrap();

        assert_matches!(cose_key_from_jwk(&jwk), Ok(_));
    }

    #[test]
    fn cose_key_from_rsa_jwk() {
        let jwk = serde_json::json!({
            "kty":"RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
                  4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
                  tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
                  QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
                  SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
                  w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e":"AQAB",
            "alg":"RS256",
            "kid":"2011-04-29"
        })
        .as_object()
        .cloned()
        .unwrap();

        assert!(
            matches!(cose_key_from_jwk(&jwk).unwrap_err().error, MdocError::JwkToCoseKey(msg) if msg == "Expected key kty with value EC"),
            "We currently only support EC keys"
        );
    }
}
