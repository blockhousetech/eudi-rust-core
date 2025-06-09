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

use std::{collections::HashSet, str::FromStr};

use bherror::{traits::PropagateError, Error};
use serde_json::Value;

use crate::{
    path_map,
    utils::{is_reserved_key_name, VecDisplayWrapper, SD_ALG_FIELD_NAME},
    DecodingError, DecodingResult, Disclosure, DisclosureByDigestTable, DisclosureByPathTable,
    DisclosureData, Hasher, HashingAlgorithm, JsonObject, ELLIPSIS, SD, SHA_256_ALG_NAME,
};

type PathMap<'a> = path_map::PathMap<&'a Disclosure>;
type PathMapObject<'a> = path_map::PathMapObject<&'a Disclosure>;
type PathMapArray<'a> = path_map::PathMapArray<&'a Disclosure>;

/// **Creates** a [JsonObject] from the provided claims and disclosures by decoding
/// disclosures found in the provided claims. The procedure follows the instructions
/// which can be found at [1]. Alongside the decoded claims, returns the [Hasher]
/// identified in the hash function claim (as described [here]) and used to calculate
/// digest of disclosures, and a [`DisclosureByPathTable`] for further lookup
/// (mostly useful on the Holder).
///
/// # Complexity
///
/// This recreates a copy of the provided `claims` [JsonObject] with the disclosed disclosures by
/// traversing the whole `claims` object recursivley.
///
/// # Notes
///
/// - Argument `get_hasher` needs to support the hash function from the hash function claim
///   or error will be returned.
/// - Digest of the disclosure found in the `claims` or recursively processed disclosures but
///   not found among the digests of the provided disclosures will be skipped.
/// - Decoded claims are valid in terms of not containing any [RESERVED_CLAIM_NAMES]
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.1
/// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-4.1.1
pub(crate) fn decode_disclosed_claims<'dis>(
    claims: &JsonObject,
    disclosures: &'dis [Disclosure],
    get_hasher: impl Fn(HashingAlgorithm) -> Option<Box<dyn Hasher>>,
) -> DecodingResult<(JsonObject, Box<dyn Hasher>, DisclosureByPathTable<'dis>)> {
    // Extract a hashing algorithm to recreate a given payload
    let sd_alg = fetch_hashing_algorithm(claims)?;

    // Use a user-provided hasher for the given algorithm
    let hasher = get_hasher(sd_alg)
        .ok_or_else(|| Error::root(DecodingError::MissingHasher(sd_alg.to_string())))?;
    let mut state = DecoderState::new(DisclosureByDigestTable::new(disclosures, &hasher)?);

    let (decoded_claims, path_map) = decode_object(claims, &mut state, true)?;

    state.finalize()?;

    Ok((decoded_claims, hasher, DisclosureByPathTable::new(path_map)))
}

struct DecoderState<'json, 'dis> {
    /// Precomputes all the disclosure digest for fast lookup afterwards
    ///
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.1.1>
    disclosures_by_digest: DisclosureByDigestTable<'dis>,

    /// Keeps track of all encountered digest in the `claims` object to check for duplicate digests
    ///
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.4>
    processed_digests: HashSet<&'json str>,
}

impl<'dis> DecoderState<'_, 'dis> {
    fn new(disclosures_by_digest: DisclosureByDigestTable<'dis>) -> Self {
        Self {
            processed_digests: HashSet::new(),
            disclosures_by_digest,
        }
    }

    fn finalize(self) -> DecodingResult<()> {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.5
        if !self.disclosures_by_digest.0.is_empty() {
            let unused_disclosures = self.disclosures_by_digest.0.into_keys().collect();
            return Err(Error::root(DecodingError::UnusedDisclosures(
                VecDisplayWrapper(unused_disclosures),
            )));
        }

        Ok(())
    }
}

/// Identifies the hashing algorithm used to generate the disclosure digests in the claims as described [here]
///
/// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-4.1.1
fn fetch_hashing_algorithm(claims: &JsonObject) -> DecodingResult<HashingAlgorithm> {
    let sd_alg_name = claims
        .get(SD_ALG_FIELD_NAME)
        .map_or(Some(SHA_256_ALG_NAME), |value| value.as_str())
        .ok_or_else(|| Error::root(DecodingError::ReservedKeyName(SD_ALG_FIELD_NAME)))?;

    HashingAlgorithm::from_str(sd_alg_name)
        .with_err(|| DecodingError::InvalidHashAlgorithmName(sd_alg_name.to_owned()))
}

// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.3.2.2.1
fn decode_object<'json, 'dis: 'json>(
    object: &'json JsonObject,
    state: &mut DecoderState<'json, 'dis>,
    top_level: bool,
) -> DecodingResult<(JsonObject, PathMapObject<'dis>)> {
    let mut decoded_object = JsonObject::new();
    let mut disclosures_by_path = PathMapObject::default();

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.2.2.1
    if let Some(sd) = object.get(SD) {
        let sd_array = sd
            .as_array()
            .ok_or_else(|| Error::root(DecodingError::MalformedDigest(sd.to_string())))?;

        for digest in sd_array {
            let Some(disclosure) = process_digest(digest, state)? else {
                // ignores the digest if no matching disclosure is found
                // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.3.2.1
                continue;
            };

            match disclosure.data {
                DisclosureData::KeyValue {
                    ref key, ref value, ..
                } => process_key_value(
                    key,
                    value,
                    &mut decoded_object,
                    state,
                    &mut disclosures_by_path,
                    Some(disclosure),
                )?,
                _ => {
                    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.3.2.2.2.1
                    return Err(Error::root(DecodingError::MismatchedDisclosureFormat));
                }
            }
        }
    }

    for (key, value) in object {
        if key.eq(SD) {
            continue;
        }
        // avoids the check of reserved key for [SD_ALG_FIELD_NAME] case when recursion is on the top level and
        // essentially removes the key by skipping the insertion
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.6
        if key.eq(SD_ALG_FIELD_NAME) && top_level {
            continue;
        }
        process_key_value(
            key,
            value,
            &mut decoded_object,
            state,
            &mut disclosures_by_path,
            None,
        )?;
    }

    Ok((decoded_object, disclosures_by_path))
}

/// Processes the (`key`, `value`) pair by:
/// - checking the key for validity
/// - recursively decoding it
/// - inserting it into the provided `object`
/// - updating the constructed path map with a disclosure corresponding to this node, if any.
///
/// Function will return error if:
///
/// - provided `key` is one of the `RESERVED_CLAIM_NAMES`
/// - recursive decoding fails
/// - object already contains a key-value pair with the provided `key`
fn process_key_value<'json, 'dis: 'json>(
    key: &'json str,
    value: &'json Value,
    object: &mut JsonObject,
    state: &mut DecoderState<'json, 'dis>,
    path_map: &mut PathMapObject<'dis>,
    disclosure: Option<&'dis Disclosure>,
) -> DecodingResult<()> {
    if let Some(reserved_key) = is_reserved_key_name(key) {
        return Err(Error::root(DecodingError::ReservedKeyName(reserved_key)));
    }

    let (decoded_value, mut child_map) = decode_value(value, state)?;

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.3.2.2.2.3
    if object.insert(key.to_string(), decoded_value).is_some() {
        return Err(Error::root(DecodingError::DuplicateClaimName(
            key.to_string(),
        )));
    }

    if let Some(disclosure) = disclosure {
        child_map.insert_value(disclosure);
    }

    // Prune empty leaves
    if !child_map.is_empty_leaf() {
        path_map.insert_key(key.to_owned(), child_map)?;
    }

    Ok(())
}

// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.3.2.3.1
fn decode_array<'json, 'dis: 'json>(
    array: &'json [Value],
    state: &mut DecoderState<'json, 'dis>,
) -> DecodingResult<(Value, PathMapArray<'dis>)> {
    let mut decoded_array = Vec::new();
    let mut disclosures_by_path = PathMapArray::default();

    fn resolve_element<'json, 'dis: 'json>(
        value: &'json Value,
        state: &mut DecoderState<'json, 'dis>,
    ) -> DecodingResult<Option<(&'json Value, Option<&'dis Disclosure>)>> {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.2.2.2
        let Some(object) = value.as_object() else {
            return Ok(Some((value, None)));
        };
        let Some(digest) = object.get(ELLIPSIS) else {
            return Ok(Some((value, None)));
        };
        if object.len() != 1 {
            return Err(Error::root(DecodingError::MalformedDigest(
                value.to_string(),
            )));
        }

        let Some(disclosure) = process_digest(digest, state)? else {
            return Ok(None);
        };

        if let DisclosureData::ArrayElement { value, .. } = &disclosure.data {
            Ok(Some((value, Some(disclosure))))
        } else {
            // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.3.2.3.2.1
            Err(Error::root(DecodingError::MismatchedDisclosureFormat))
        }
    }

    for (index, value) in array.iter().enumerate() {
        if let Some((value, disclosure)) = resolve_element(value, state)? {
            let (value, mut child_map) = decode_value(value, state)?;

            decoded_array.push(value);

            if let Some(disclosure) = disclosure {
                child_map.insert_value(disclosure);
            }

            // Prune empty leaves
            if !child_map.is_empty_leaf() {
                disclosures_by_path.insert_element(index as _, child_map);
            }
        };
    }

    Ok((Value::Array(decoded_array), disclosures_by_path))
}

fn decode_value<'json, 'dis: 'json>(
    value: &'json Value,
    state: &mut DecoderState<'json, 'dis>,
) -> DecodingResult<(Value, PathMap<'dis>)> {
    match value {
        Value::Object(object) => {
            let (value, child_map) = decode_object(object, state, false)?;
            Ok((Value::Object(value), child_map.finish_subtree()))
        }
        Value::Array(array) => {
            let (value, child_map) = decode_array(array, state)?;
            Ok((value, child_map.finish_subtree()))
        }
        _ => Ok((value.to_owned(), PathMap::default())),
    }
}

/// Checks if digest was already processed and finds the disclosure that matches the digest
/// and marks the disclosure as resolved
fn process_digest<'json, 'dis>(
    digest: &'json Value,
    state: &mut DecoderState<'json, 'dis>,
) -> DecodingResult<Option<&'dis Disclosure>> {
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.2.2.1
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.2.2.2
    let digest = digest
        .as_str()
        .ok_or_else(|| Error::root(DecodingError::MalformedDigest(digest.to_string())))?;
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.2.2.2
    if !state.processed_digests.insert(digest) {
        return Err(Error::root(DecodingError::DuplicateDigest(
            digest.to_owned(),
        )));
    }

    Ok(state.disclosures_by_digest.0.remove(digest))
}

#[cfg(test)]
pub(crate) mod tests {

    use std::collections::HashSet;

    use serde_json::{json, Value};

    use super::DisclosureByPathTable;
    use crate::{
        decoder::decode_disclosed_claims,
        into_object, path,
        test_utils::dummy_hasher_factory,
        utils::{base64_url_digest, VecDisplayWrapper, SD_ALG_FIELD_NAME},
        DecodingError, Disclosure, DisplayWrapper, Hasher, HashingAlgorithm, JsonNodePath, Sha256,
        ELLIPSIS, SD,
    };

    fn simple_disclosure(key: Option<String>) -> Disclosure {
        Disclosure::new(String::new(), key, Value::String("value".to_string()))
    }

    fn calculate_digest(disclosure: &Disclosure) -> String {
        base64_url_digest(disclosure.as_str().as_bytes(), Sha256)
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#name-example-flat-sd-jwt
    #[test]
    fn flat_sdjwt_example_test() {
        let payload = into_object(json!({
            "_sd": [
            "fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4do"
            ],
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "_sd_alg": "sha-256"
        }));

        let expected_payload = into_object(json!({
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            },
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        }));
        let disclosure_serialized =
            "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIlNjaHVsc3RyLiAxMiIsICJsb2NhbGl0eSI6ICJTY2h1bHBmb3J0YSIsICJyZWdpb24iOiAiU2FjaHNlbi1BbmhhbHQiLCAiY291bnRyeSI6ICJERSJ9XQ";
        let disclosure = Disclosure::try_from(disclosure_serialized.to_owned()).unwrap();
        let disclosures = &[disclosure];

        let (recreated_payload, used_hasher, disclosures_by_path) =
            decode_disclosed_claims(&payload, disclosures, dummy_hasher_factory).unwrap();

        assert_eq!(expected_payload, recreated_payload);
        assert_eq!(HashingAlgorithm::Sha256, used_hasher.algorithm());
        assert_disclosures_on_paths(
            &disclosures_by_path,
            &[(path!["address"], &[&disclosures[0]])],
        );
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#name-example-structured-sd-jwt
    #[test]
    fn structured_object_sdjwt_example_test() {
        let payload = into_object(json!({
          "iss": "https://issuer.example.com",
          "iat": 1683000000,
          "exp": 1883000000,
          "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
          "address": {
            "_sd": [
              "6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0",
              "9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
              "KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88",
              "WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM"
            ]
          },
          "_sd_alg": "sha-256"
        }
        ));

        let expected_payload = into_object(json!({
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            },
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        }));

        let disclosures_serialized = vec![
            // address.street_address
            "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd",
            // address.locality
            "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0",
            // address.region
            "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd",
            // address.country
            "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ",
        ];
        let disclosures = disclosures_from_serialized(disclosures_serialized);

        let (recreated_payload, used_hasher, disclosures_by_path) =
            decode_disclosed_claims(&payload, &disclosures, dummy_hasher_factory).unwrap();

        assert_eq!(expected_payload, recreated_payload);
        assert_eq!(HashingAlgorithm::Sha256, used_hasher.algorithm());
        assert_disclosures_on_paths(
            &disclosures_by_path,
            &[
                (path!["address"], &[]),
                (path!["address", "street_address"], &[&disclosures[0]]),
                (path!["address", "locality"], &[&disclosures[1]]),
                (path!["address", "region"], &[&disclosures[2]]),
                (path!["address", "country"], &[&disclosures[3]]),
            ],
        );
    }

    // similar example to https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#name-example-structured-sd-jwt
    #[test]
    fn structured_array_sdjwt_test() {
        let disclosure_in_array =
            Disclosure::new(String::new(), None, Value::String("US".to_string()));

        let disclosure_in_nested_array =
            Disclosure::new(String::new(), None, Value::String("DE".to_string()));

        let payload = into_object(json!({
          "iss": "https://issuer.example.com",
          "iat": 1683000000,
          "exp": 1883000000,
          "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
          "address": {
            "_sd": [
              "6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0",
              "9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
              "KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88",
              "WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM"
            ],
            "new_key": [
                "bla_key",
                {"...": calculate_digest(&disclosure_in_array)},
                [{"...": calculate_digest(&disclosure_in_nested_array)}]
            ]
          },
          "_sd_alg": "sha-256"
        }
        ));

        let expected_payload = into_object(json!({
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE",
                "new_key": [
                    "bla_key",
                    "US",
                    ["DE"]
                ]
            },
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        }));

        let disclosures_serialized = vec![
            // address.street_address
            "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd",
            // address.locality
            "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0",
            // address.region
            "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd",
            // address.country
            "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ",
            disclosure_in_array.as_str(),
            disclosure_in_nested_array.as_str(),
        ];
        let disclosures = disclosures_from_serialized(disclosures_serialized);

        let (recreated_payload, used_hasher, disclosures_by_path) =
            decode_disclosed_claims(&payload, &disclosures, dummy_hasher_factory).unwrap();

        assert_eq!(expected_payload, recreated_payload);
        assert_eq!(HashingAlgorithm::Sha256, used_hasher.algorithm());
        assert_disclosures_on_paths(
            &disclosures_by_path,
            &[
                (path!["address"], &[]),
                (path!["address", "street_address"], &[&disclosures[0]]),
                (path!["address", "locality"], &[&disclosures[1]]),
                (path!["address", "region"], &[&disclosures[2]]),
                (path!["address", "country"], &[&disclosures[3]]),
                (path!["address", "new_key"], &[]),
                (path!["address", "new_key", 0], &[]),
                (path!["address", "new_key", 1], &[&disclosures[4]]),
                (path!["address", "new_key", 2], &[]),
                (path!["address", "new_key", 2, 0], &[&disclosures[5]]),
            ],
        );
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#name-example-sd-jwt-with-recursi
    #[test]
    fn recursive_sdjwt_example_test() {
        let payload = into_object(json!({
            "_sd": [
              "HvrKX6fPV0v9K_yCVFBiLFHsMaxcD_114Em6VT8x1lg"
            ],
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "_sd_alg": "sha-256"
          }
        ));

        let expected_payload = into_object(json!({
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            },
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        }));

        let disclosures_serialized = vec![
            // address.street_address
            "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd",
            // address.locality
            "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0",
            // address.region
            "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd",
            // address.country
            "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ",
            // address
            "WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7Il9zZCI6IFsiNnZoOWJxLXpTNEdLTV83R3BnZ1ZiWXp6dTZvT0dYcm1OVkdQSFA3NVVkMCIsICI5Z2pWdVh0ZEZST0NnUnJ0TmNHVVhtRjY1cmRlemlfNkVyX2o3NmttWXlNIiwgIktVUkRQaDRaQzE5LTN0aXotRGYzOVY4ZWlkeTFvVjNhM0gxRGEyTjBnODgiLCAiV045cjlkQ0JKOEhUQ3NTMmpLQVN4VGpFeVc1bTV4NjVfWl8ycm8yamZYTSJdfV0",
        ];
        let disclosures = disclosures_from_serialized(disclosures_serialized);

        let (recreated_payload, used_hasher, disclosures_by_path) =
            decode_disclosed_claims(&payload, &disclosures, dummy_hasher_factory).unwrap();

        assert_eq!(expected_payload, recreated_payload);
        assert_eq!(HashingAlgorithm::Sha256, used_hasher.algorithm());
        assert_disclosures_on_paths(
            &disclosures_by_path,
            &[
                (path!["address"], &[&disclosures[4]]),
                (
                    path!["address", "street_address"],
                    &[&disclosures[4], &disclosures[0]],
                ),
                (
                    path!["address", "locality"],
                    &[&disclosures[4], &disclosures[1]],
                ),
                (
                    path!["address", "region"],
                    &[&disclosures[4], &disclosures[2]],
                ),
                (
                    path!["address", "country"],
                    &[&disclosures[4], &disclosures[3]],
                ),
            ],
        );
    }

    impl std::fmt::Debug for dyn Hasher {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Hasher: {}", self.algorithm())
        }
    }

    impl PartialEq for dyn Hasher {
        fn eq(&self, other: &Self) -> bool {
            self.algorithm() == other.algorithm()
        }
    }

    /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.3.2.2.2.2
    #[test]
    fn sdjwt_invalid_claim_name_sd_test() {
        let disclosure = simple_disclosure(Some(SD.to_string()));
        let digest = calculate_digest(&disclosure);

        let payload = into_object(json!({
            SD: [
                digest
            ],
        }));
        let disclosures = &[disclosure];

        let result = decode_disclosed_claims(&payload, disclosures, dummy_hasher_factory);

        assert_eq!(
            result.unwrap_err().error,
            DecodingError::ReservedKeyName(SD)
        );
    }

    /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.3.2.2.2.2
    #[test]
    fn sdjwt_invalid_claim_name_ellipsis_test() {
        let disclosure = simple_disclosure(Some(ELLIPSIS.to_string()));
        let hash = calculate_digest(&disclosure);

        let payload = into_object(json!({
            SD: [
            hash
            ],
        }));
        let disclosures = &[disclosure];

        let invalid_recreate = decode_disclosed_claims(&payload, disclosures, dummy_hasher_factory);

        assert_eq!(
            invalid_recreate.unwrap_err().error,
            DecodingError::ReservedKeyName(ELLIPSIS)
        );
    }

    #[test]
    fn sdjwt_invalid_claim_name_sd_alg_test() {
        let disclosure = simple_disclosure(Some(SD_ALG_FIELD_NAME.to_string()));
        let hash = calculate_digest(&disclosure);

        let payload = into_object(json!({
            SD: [
            hash
            ],
        }));
        let disclosures = &[disclosure];

        let invalid_recreate = decode_disclosed_claims(&payload, disclosures, dummy_hasher_factory);

        assert_eq!(
            invalid_recreate.unwrap_err().error,
            DecodingError::ReservedKeyName(SD_ALG_FIELD_NAME)
        );
    }

    /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.3.2.2.2.1
    #[test]
    fn invalid_payload_value_without_key_in_object() {
        let disclosure = simple_disclosure(None);
        let hash = calculate_digest(&disclosure);

        let payload = into_object(json!({
            SD: [
            hash
            ],
        }));
        let disclosures = &[disclosure];

        let invalid_recreate = decode_disclosed_claims(&payload, disclosures, dummy_hasher_factory);

        assert_eq!(
            invalid_recreate.unwrap_err().error,
            DecodingError::MismatchedDisclosureFormat
        );
    }

    /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.3.2.2.2.3
    #[test]
    fn duplicate_claim_name() {
        let disclosure = simple_disclosure(Some("address".to_string()));

        let payload = into_object(json!({
            "_sd": [
                calculate_digest(&disclosure)
            ],
            "address": "address_value",
            "_sd_alg": "sha-256"
        }));
        let disclosures = &[disclosure];

        let invalid_payload = decode_disclosed_claims(&payload, disclosures, dummy_hasher_factory);

        assert_eq!(
            invalid_payload.unwrap_err().error,
            DecodingError::DuplicateClaimName("address".to_string())
        );
    }

    /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.3.2.3.2.1
    #[test]
    fn invalid_payload_value_with_key_in_array() {
        let disclosure = simple_disclosure(Some("key".to_string()));

        let hash = calculate_digest(&disclosure);

        let payload = into_object(json!({
                "array": [{ELLIPSIS: hash}]
        }));
        let disclosures = &[disclosure];

        let invalid_recreate = decode_disclosed_claims(&payload, disclosures, dummy_hasher_factory);

        assert_eq!(
            invalid_recreate.unwrap_err().error,
            DecodingError::MismatchedDisclosureFormat
        );
    }

    /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.4
    /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.3.2.5
    #[test]
    fn remove_digest_from_payload_that_dont_have_a_matching_disclosure() {
        let disclosure = simple_disclosure(Some("key".to_string()));

        let payload = into_object(json!({
            "_sd": [
                calculate_digest(&disclosure),
                "fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4d2", // should not match
                "fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4d3", // should not match
            ],
            "array": [{"...": "fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4d4"}], // should not match
            "_sd_alg": "sha-256"
        }));
        let disclosures = &[disclosure];

        let expected_payload = into_object(json!({
            "key": "value",
            "array": [],
        }));

        let (recreated_payload, used_hasher, disclosures_by_path) =
            decode_disclosed_claims(&payload, disclosures, dummy_hasher_factory).unwrap();

        assert_eq!(expected_payload, recreated_payload);
        assert_eq!(HashingAlgorithm::Sha256, used_hasher.algorithm());
        assert_disclosures_on_paths(
            &disclosures_by_path,
            &[(path!["key"], &[&disclosures[0]]), (path!["array", 0], &[])],
        );
    }

    /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.4
    #[test]
    fn duplicate_digest_value() {
        let duplicate_digest = "fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4d3".to_string();
        let payload = into_object(json!({
            "_sd": [
            duplicate_digest.as_str()
            ],
            "array": [{"...": duplicate_digest.as_str()}],
            "_sd_alg": "sha-256"
        }));

        let invalid_payload = decode_disclosed_claims(&payload, &[], dummy_hasher_factory);

        assert_eq!(
            invalid_payload.unwrap_err().error,
            DecodingError::DuplicateDigest(duplicate_digest)
        );
    }

    /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-7.1-4.5
    #[test]
    fn unused_disclosure() {
        let used_disclosure = simple_disclosure(Some("key".to_string()));
        let used_disclosure_digest = calculate_digest(&used_disclosure);

        let payload = into_object(json!({
          "address": {
            "_sd": [used_disclosure_digest]
          },
          "_sd_alg": "sha-256"
        }
        ));

        let unused_disclosure =
            Disclosure::new(String::new(), Some("key2".to_string()), Value::Bool(false));
        let unused_disclosure_digest = calculate_digest(&unused_disclosure);

        let disclosures = [used_disclosure, unused_disclosure.clone()];

        let invalid_payload = decode_disclosed_claims(&payload, &disclosures, dummy_hasher_factory);

        assert_eq!(
            invalid_payload.unwrap_err().error,
            DecodingError::UnusedDisclosures(VecDisplayWrapper(vec![unused_disclosure_digest]))
        );
    }

    #[test]
    fn disclosure_in_object_in_array() {
        let disclosure = simple_disclosure(Some("key".to_string()));

        let digest = calculate_digest(&disclosure);
        let payload = into_object(json!({
            "address": [
                {"_sd" : [digest]}
            ]
        }));
        let disclosures = &[disclosure];

        let expected_payload = into_object(json!({
            "address": [
                {"key": "value"}
            ],
        }));

        let (recreated_payload, used_hasher, disclosures_by_path) =
            decode_disclosed_claims(&payload, disclosures, dummy_hasher_factory).unwrap();

        assert_eq!(expected_payload, recreated_payload);
        assert_eq!(HashingAlgorithm::Sha256, used_hasher.algorithm());
        assert_disclosures_on_paths(
            &disclosures_by_path,
            &[
                (path!["address", 0], &[]),
                (path!["address", 0, "key"], &[&disclosures[0]]),
            ],
        );
    }

    #[test]
    fn malfored_digest_in_array_contains_multiple_digests() {
        let payload = into_object(json!({
            "address": [
                {"..." : ["digest1", "digest2"]}
            ]
        }));

        let invalid_payload = decode_disclosed_claims(&payload, &[], dummy_hasher_factory);

        let expected_malformed_digest = "[\"digest1\",\"digest2\"]".to_string();
        assert_eq!(
            invalid_payload.unwrap_err().error,
            DecodingError::MalformedDigest(expected_malformed_digest)
        );
    }

    #[test]
    fn sd_alg_key_value_not_string_on_top_level() {
        let disclosure = simple_disclosure(Some("key".to_string()));

        let payload = into_object(json!({
            "_sd": [
                calculate_digest(&disclosure)
            ],
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "_sd_alg": ["sha-256"]
        }));
        let disclosures = &[disclosure];

        let invalid_payload = decode_disclosed_claims(&payload, disclosures, dummy_hasher_factory);

        assert_eq!(
            invalid_payload.unwrap_err().error,
            DecodingError::ReservedKeyName(SD_ALG_FIELD_NAME)
        );
    }

    #[test]
    fn invalid_hash_algorithm_name() {
        let disclosure = simple_disclosure(Some("key".to_string()));

        let payload = into_object(json!({
            "_sd": [
                calculate_digest(&disclosure)
            ],
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "_sd_alg": "esh-512"
        }));
        let disclosures = &[disclosure];

        let invalid_payload = decode_disclosed_claims(&payload, disclosures, dummy_hasher_factory);

        assert_eq!(
            invalid_payload.unwrap_err().error,
            DecodingError::InvalidHashAlgorithmName("esh-512".to_owned())
        );
    }

    #[test]
    fn reserved_key_name_in_disclosed_object() {
        let disclosure = Disclosure::new(
            String::new(),
            Some("a".to_string()),
            json!({
                ELLIPSIS: 1,
                "b": 2
            }),
        );
        let hash = calculate_digest(&disclosure);
        let payload = into_object(json!({
                "_sd": [hash]
        }));
        let disclosures = &[disclosure];

        let invalid_recreate = decode_disclosed_claims(&payload, disclosures, dummy_hasher_factory);

        assert_eq!(
            invalid_recreate.unwrap_err().error,
            DecodingError::ReservedKeyName(ELLIPSIS)
        );
    }

    fn disclosures_from_serialized(disclosures_serialized: Vec<&str>) -> Vec<Disclosure> {
        disclosures_serialized
            .iter()
            .map(|disclosure_serialized| {
                Disclosure::try_from((*disclosure_serialized).to_owned()).unwrap()
            })
            .collect::<Vec<_>>()
    }

    /// Assert that on each provided path, the **set** of disclosures along that
    /// path contains the given disclosures.
    pub(crate) fn assert_disclosures_on_paths(
        disclosures_by_path: &DisclosureByPathTable,
        test_cases: &[(&JsonNodePath, &[&Disclosure])],
    ) {
        println!("{:#?}", disclosures_by_path);
        for (index, (path, expected_disclosures)) in test_cases.iter().copied().enumerate() {
            // Ignore ordering, as the iterator doesn't guarantee the traversal order
            let disclosures_on_path: HashSet<_> = disclosures_by_path
                .disclosures_covering_paths(&[path])
                .collect();
            let expected_disclosures = HashSet::from_iter(expected_disclosures.iter().copied());
            assert_eq!(
                disclosures_on_path,
                expected_disclosures,
                "test case {}: path `{}`",
                index,
                DisplayWrapper(path),
            );
        }
    }
}
