// Copyright (C) 2020-2026  The Blockhouse Technology Limited (TBTL).
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

use bherror::{traits::ErrorContext, Error};
use rand_core::CryptoRngCore;
use serde_json::{json, Value};

use crate::{
    issuer::IssuerError,
    utils::{self, check_claim_names_object, is_reserved_key_name},
    Disclosure, DisplayWrapper, Hasher, JsonNodePath, JsonNodePathSegment, JsonObject, ELLIPSIS,
    RESERVED_CLAIM_NAMES, SD,
};

type Result<T> = bherror::Result<T, IssuerError>;

/// Encodes values specified in the list of `disclosure_paths` with digests of the values
/// as described [here].
///
/// # Arguments
/// - `claims` : object in which claims are stored
/// - `disclosure_paths` : `paths` to values in `claims` which should be encoded
/// - `hasher` : hashing function used to generate digest values, see [1]
/// - `rng` : random number generator used to generate salt for disclosures, see [2] and [generate_salt]
///
/// # Errors
/// Encoding will fail if:
/// - `claims` contains [RESERVED_CLAIM_NAMES]
/// - `disclosure_paths` contains duplicate paths
/// - `disclosure_paths` contains [RESERVED_CLAIM_NAMES]
/// - `disclosure_paths` contains a path that does not exist in `claims`
/// - `disclosure_paths` contains empty path
///
/// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#name-disclosures
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#name-hashing-disclosures
/// [2]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#section-5.2.1-2.1.2.1
pub(crate) fn encode_claims<H: Hasher, R: CryptoRngCore + ?Sized>(
    claims: &mut JsonObject,
    disclosure_paths: &[&[JsonNodePathSegment<'_>]],
    hasher: &H,
    rng: &mut R,
) -> Result<Vec<Disclosure>> {
    if let Some(name) = check_reserved_keys_in_claims(claims) {
        return Err(Error::root(IssuerError::ReservedOrRegisteredClaimName(
            name,
        )));
    }
    check_duplicate_paths(disclosure_paths)?;

    let mut disclosures = vec![];

    for path in toposort_node_paths(disclosure_paths) {
        let salt = generate_salt(rng);
        disclosures.push(conceal_disclosure(claims, path, hasher, salt)?);
    }

    Ok(disclosures)
}

fn conceal_disclosure<H: Hasher>(
    claims: &mut JsonObject,
    path: &JsonNodePath,
    hasher: &H,
    salt: String,
) -> Result<Disclosure> {
    check_reserved_keys_in_path(path)?;
    // Reject empty paths, as these represent the root object, which is not a child of any
    // parent and as such cannot have a disclosure, as there is no place to put the `_sd`
    // array with its hash.
    let (last_segment, path_without_last) = path
        .split_last()
        .ok_or_else(|| Error::root(IssuerError::InvalidPath(DisplayWrapper(path).to_string())))?;
    // case when root object is the parent of disclosure
    if path_without_last.is_empty() {
        let JsonNodePathSegment::Key(key) = last_segment else {
            // invalid path, this case implies that root object is an array which is not valid
            return Err(Error::root(IssuerError::InvalidPath(
                DisplayWrapper(path).to_string(),
            )));
        };
        return conceal_disclosure_in_object(claims, key, salt, hasher, path);
    }

    let disclosure_parent =
        crate::index_mut_object_by_path(claims, path_without_last).ok_or_else(|| {
            Error::root(IssuerError::NonExistentPath(
                DisplayWrapper(path).to_string(),
            ))
        })?;

    match (disclosure_parent, last_segment) {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#name-disclosures-for-object-prop
        (Value::Object(object), JsonNodePathSegment::Key(key)) => {
            conceal_disclosure_in_object(object, key, salt, hasher, path)
        }
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#name-disclosures-for-array-eleme
        (Value::Array(parent_array), JsonNodePathSegment::Index(index)) => {
            conceal_disclosure_in_array(parent_array, *index, salt, hasher, path)
        }
        // path leads to a parent value which is not array or object
        _ => Err(Error::root(IssuerError::InvalidPath(
            DisplayWrapper(path).to_string(),
        ))),
    }
}

/// This function creates a disclosure for the claim found at the provided `key` of the
/// provided `object` and then conceals the claim with the digest of the created disclosure
/// as specified at [1] and [2]. Returns the [Disclosure] which was concealed.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#name-disclosures-for-object-prop
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#name-object-properties
fn conceal_disclosure_in_object<H: Hasher>(
    object: &mut JsonObject,
    key: &str,
    salt: String,
    hasher: &H,
    path: &JsonNodePath,
) -> Result<Disclosure> {
    let value = object.remove(key).ok_or_else(|| {
        Error::root(IssuerError::NonExistentPath(
            DisplayWrapper(path).to_string(),
        ))
    })?;

    let disclosure = Disclosure::new(salt, Some(key.to_owned()), value);
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#name-hashing-disclosures
    let digest = utils::base64_url_digest(disclosure.as_str().as_bytes(), hasher);

    if let Value::Array(sd_array) = object.entry(SD).or_insert(Value::Array(vec![])) {
        sd_array.push(digest.into());
    } else {
        // object that is not Value::Array is at key _sd which should not happen
        return Err(
            Error::root(IssuerError::ReservedOrRegisteredClaimName(SD)).ctx(format!(
                "_sd value is not an array at {}",
                DisplayWrapper(path)
            )),
        );
    }
    Ok(disclosure)
}

/// This function creates a disclosure for the claim found at the provided `index` of the
/// provided `array` and then conceals the claim with the digest of the created disclosure
/// as specified at [1] and [2]. Returns the [Disclosure] which was concealed.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#section-5.2.2
/// [2]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#name-array-elements
fn conceal_disclosure_in_array<H: Hasher>(
    array: &mut [Value],
    index: u32,
    salt: String,
    hasher: &H,
    path: &JsonNodePath,
) -> Result<Disclosure> {
    let mut value = Value::Null;

    std::mem::swap(
        &mut value,
        array
            .get_mut(index as usize)
            // non-existent path
            .ok_or_else(|| {
                Error::root(IssuerError::NonExistentPath(
                    DisplayWrapper(path).to_string(),
                ))
            })?,
    );

    let disclosure = Disclosure::new(salt, None, value);
    let actual_digest = utils::base64_url_digest(disclosure.as_str().as_bytes(), hasher);
    array[index as usize] = json!({ELLIPSIS: Value::String(actual_digest)});
    // The reason why this is not done in a more simple and usual way - creating the disclosure, calculating
    // the digest and then just doing array[index] = object_with_digest - is because creating the disclosure
    // takes ownership of the [Value] in the array so we need to somehow get that value without cloning and
    // without doing array.remove method (that has linear time complexity)
    Ok(disclosure)
}

/// The [conceal_disclosure], [conceal_disclosure_in_object] and [conceal_disclosure_in_array]
/// methods mutate the model for one selectively disclosable node at a time, and to be able
/// to properly handle recursive disclosures, ancestor nodes need to be processed strictly
/// after all of their descendants. Thus, we can merely sort the paths into a safe order.
fn toposort_node_paths<'p>(
    disclosure_paths: &'p [&'p JsonNodePath],
) -> impl Iterator<Item = &'p JsonNodePath<'p>> {
    // It is sufficient to sort paths descending by length (number of segments), as ancestors
    // are at lower depths than their descendants.
    let mut paths = disclosure_paths.to_owned();
    paths.sort_unstable_by_key(|path| path.len());
    paths.into_iter().rev()
}

/// Generate a salt for the SD-JWT disclosure hashes.
///
/// See the [draft] for more details.
///
/// Generate a base64url string of random bytes as a salt for SD-JWT hashing purposes.
///
/// The string **MUST** be highly unpredictable (except for testing
/// purposes, where this provides a mocking interface). See more in draft
/// sections [11.3] and [11.4].
///
/// [draft]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#section-5.2.1-2.1.2.1
/// [11.3]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#name-entropy-of-the-salt
/// [11.4]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#name-minimum-length-of-the-salt
fn generate_salt<R: CryptoRngCore + ?Sized>(rng: &mut R) -> String {
    let mut salt = [0; SALT_ENTROPY_BYTES];
    rng.fill_bytes(&mut salt);
    bh_jws_utils::base64_url_encode(salt)
}

fn check_duplicate_paths(disclosure_paths: &[&JsonNodePath]) -> Result<()> {
    let mut uniq = HashSet::new();
    for path in disclosure_paths {
        if !uniq.insert(path) {
            return Err(Error::root(IssuerError::DuplicatePath(
                DisplayWrapper(path as &JsonNodePath).to_string(),
            )));
        }
    }

    Ok(())
}

fn check_reserved_keys_in_claims(claims: &JsonObject) -> Option<&'static str> {
    check_claim_names_object(
        claims,
        &|claim| {
            RESERVED_CLAIM_NAMES
                .iter()
                .find(|reserved| **reserved == claim)
                .copied()
        },
        true,
    )
}

fn check_reserved_keys_in_path(path: &[JsonNodePathSegment]) -> Result<()> {
    for segment in path.iter() {
        if let JsonNodePathSegment::Key(key) = segment {
            if let Some(key) = is_reserved_key_name(key) {
                return Err(Error::root(IssuerError::ReservedOrRegisteredClaimName(key)))
                    .ctx(|| format!("invalid path {0}", DisplayWrapper(path)));
            }
        }
    }
    Ok(())
}

const SALT_ENTROPY_BYTES: usize = 16;

#[cfg(test)]
pub(crate) mod tests {
    use bherror::Result;
    use serde_json::{json, Value};
    use JsonNodePathSegment::*;

    use super::encode_claims;
    use crate::{
        encoder::conceal_disclosure, issuer::IssuerError, json_object, utils::SD_ALG_FIELD_NAME,
        JsonNodePath, JsonNodePathSegment, Sha256, ELLIPSIS, RESERVED_CLAIM_NAMES, SD,
    };

    fn encoder_conceal(
        mut claims: Value,
        salts_and_paths: Vec<(String, &JsonNodePath)>,
    ) -> Result<Value, IssuerError> {
        let claims_object = claims.as_object_mut().unwrap();
        let hasher = Sha256;

        for (salt, path) in salts_and_paths {
            conceal_disclosure(claims_object, path, &hasher, salt)?;
        }

        Ok(claims)
    }

    fn test_encoder_conceal(
        claims: Value,
        salts_and_paths: Vec<(String, &JsonNodePath)>,
        expected_value: Value,
    ) -> Result<(), IssuerError> {
        assert_eq!(
            encoder_conceal(claims, salts_and_paths).unwrap(),
            expected_value
        );

        Ok(())
    }

    /// Example taken from [here].
    ///
    /// The payload used for hash can have certain variations, as seen in [1], so expected hash(es)
    /// may be different than ones found in RFC.
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-6.1-1
    /// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.2.1-8
    #[test]
    fn test_encoder_conceal_basic() -> Result<(), IssuerError> {
        let claims = json!({
            "sub": "user_42",
            "given_name": "John",
            "family_name": "Doe",
            "email": "johndoe@example.com",
            "phone_number": "+1-202-555-0101",
            "phone_number_verified": true,
            "address": {
                "street_address": "123 Main St",
                "locality": "Anytown",
                "region": "Anystate",
                "country": "US"
            },
            "birthdate": "1940-01-01",
            "updated_at": 1570000000,
            "nationalities": [
                "US",
                "DE"
            ]
        });

        let salts_and_paths: Vec<(String, &JsonNodePath)> = vec![
            ("2GLC42sKQveCfGfryNRN9w".to_string(), &[Key("given_name")]),
            ("eluV5Og3gSNII8EYnsxA_A".to_string(), &[Key("family_name")]),
            ("6Ij7tM-a5iVPGboS5tmvVA".to_string(), &[Key("email")]),
            ("eI8ZWm9QnKPpNPeNenHdhQ".to_string(), &[Key("phone_number")]),
            (
                "Qg_O64zqAxe412a108iroA".to_string(),
                &[Key("phone_number_verified")],
            ),
            ("AJx-095VPrpTtN4QMOqROA".to_string(), &[Key("address")]),
            ("Pc33JM2LchcU_lHggv_ufQ".to_string(), &[Key("birthdate")]),
            ("G02NSrQfjFXQ7Io09syajA".to_string(), &[Key("updated_at")]),
            (
                "lklxF5jMYlGTPUovMNIvCA".to_string(),
                &[Key("nationalities"), Index(0)],
            ),
            (
                "nPuoQnkRFq3BIeAm7AnXFA".to_string(),
                &[Key("nationalities"), Index(1)],
            ),
        ];

        let expected_value = json!({
            "sub": "user_42",
            "_sd": [
                "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4",
                "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
                "JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE",
                "PorFbpKuVu6xymJagvkFsFXAbRoc2JGlAUA2BA4o7cI",
                "XQ_3kPKt1XyX7KANkqVR6yZ2Va5NrPIvPYbyMvRKBMM",
                "YavaS3viw8YSKdP8UpFfIHJfjkDtTLgrG0eCY5lgWjo", // XzFrzwscM6Gn6CJDc6vVK8BkMnfG8vOSKfpPIZdAfdE with draft's serialization
                "gbOsI4Edq2x2Kw-w5wPEzakob9hV1cRD0ATN3oQL9JM",
                "CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI"
            ],
            "nationalities": [
                {
                    "...": "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo"
                },
                {
                    "...": "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0"
                }
            ]
        });

        test_encoder_conceal(claims, salts_and_paths, expected_value)
    }

    /// Example taken from [here].
    ///
    /// The payload used for hash can have certain variations, a seen in [1], so expected hash(es)
    /// may be different than ones found in RFC.
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#name-example-flat-sd-jwt
    /// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.2.1-8
    #[test]
    fn test_encoder_conceal_flat() -> Result<(), IssuerError> {
        let claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            }
        });

        let salts_and_paths: Vec<(String, &JsonNodePath)> =
            vec![("2GLC42sKQveCfGfryNRN9w".to_string(), &[Key("address")])];

        let expected_value = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "_sd": [
                "zgBGNMzh31Swh6m3LY0JZU_PdBmhsMvz69s8pv1eY54" // fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4do with draft's serialization
            ],
        });

        test_encoder_conceal(claims, salts_and_paths, expected_value)
    }

    /// Example taken from [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#name-example-structured-sd-jwt
    #[test]
    fn test_encoder_conceal_structured() -> Result<(), IssuerError> {
        let claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            }
        });

        let salts_and_paths: Vec<(String, &JsonNodePath)> = vec![
            (
                "2GLC42sKQveCfGfryNRN9w".to_string(),
                &[Key("address"), Key("street_address")],
            ),
            (
                "eluV5Og3gSNII8EYnsxA_A".to_string(),
                &[Key("address"), Key("locality")],
            ),
            (
                "6Ij7tM-a5iVPGboS5tmvVA".to_string(),
                &[Key("address"), Key("region")],
            ),
            (
                "eI8ZWm9QnKPpNPeNenHdhQ".to_string(),
                &[Key("address"), Key("country")],
            ),
        ];

        let expected_value = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": {
                "_sd": [
                    "9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
                    "6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0",
                    "KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88",
                    "WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM",
                ]
            },
        });

        test_encoder_conceal(claims, salts_and_paths, expected_value)
    }

    /// Example taken from [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-7.2-12
    #[test]
    fn test_encoder_conceal_structured_partial() -> Result<(), IssuerError> {
        let claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE",
            }
        });

        let salts_and_paths: Vec<(String, &JsonNodePath)> = vec![
            (
                "2GLC42sKQveCfGfryNRN9w".to_string(),
                &[Key("address"), Key("street_address")],
            ),
            (
                "eluV5Og3gSNII8EYnsxA_A".to_string(),
                &[Key("address"), Key("locality")],
            ),
            (
                "6Ij7tM-a5iVPGboS5tmvVA".to_string(),
                &[Key("address"), Key("region")],
            ),
        ];

        let expected_value = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": {
                "_sd": [
                    "9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
                    "6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0",
                    "KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88",
                ],
                "country": "DE",
            },
        });

        test_encoder_conceal(claims, salts_and_paths, expected_value)
    }

    /// Example taken from [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#name-example-sd-jwt-with-recursi
    #[test]
    fn test_encoder_conceal_recursive() -> Result<(), IssuerError> {
        let claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE",
            }
        });

        let salts_and_paths: Vec<(String, &JsonNodePath)> = vec![
            (
                "2GLC42sKQveCfGfryNRN9w".to_string(),
                &[Key("address"), Key("street_address")],
            ),
            (
                "eluV5Og3gSNII8EYnsxA_A".to_string(),
                &[Key("address"), Key("locality")],
            ),
            (
                "6Ij7tM-a5iVPGboS5tmvVA".to_string(),
                &[Key("address"), Key("region")],
            ),
            (
                "eI8ZWm9QnKPpNPeNenHdhQ".to_string(),
                &[Key("address"), Key("country")],
            ),
            // `address` needs to go last because inner claims need to be concealed
            // first
            ("Qg_O64zqAxe412a108iroA".to_string(), &[Key("address")]),
        ];

        let expected_value = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "_sd": [
                "WBsGX2zH9ek2LlRwRzDkUMBCEa9mY7EhWNiCEE1oAqc" // HvrKX6fPV0v9K_yCVFBiLFHsMaxcD_114Em6VT8x1lg with draft's serialization
            ],
        });

        test_encoder_conceal(claims, salts_and_paths, expected_value)
    }

    #[test]
    fn non_existent_path_through_object() {
        let claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
            }
        });

        let salts_and_paths: Vec<(String, &JsonNodePath)> = vec![
            (
                "2GLC42sKQveCfGfryNRN9w".to_string(),
                &[Key("address"), Key("non_existent_key")],
            ),
            ("Qg_O64zqAxe412a108iroA".to_string(), &[Key("address")]),
        ];

        let error = encoder_conceal(claims, salts_and_paths).unwrap_err().error;

        assert_eq!(
            error,
            IssuerError::NonExistentPath("$.address.non_existent_key".to_string())
        );
    }

    #[test]
    fn non_existent_path_through_array() {
        let claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": [
                "street_address",
                "locality",
                "blabla"
            ]
        });

        let salts_and_paths: Vec<(String, &JsonNodePath)> = vec![
            (
                "2GLC42sKQveCfGfryNRN9w".to_string(),
                &[Key("address"), Index(3)],
            ),
            ("Qg_O64zqAxe412a108iroA".to_string(), &[Key("address")]),
        ];

        assert_eq!(
            encoder_conceal(claims, salts_and_paths).unwrap_err().error,
            IssuerError::NonExistentPath("$.address[3]".to_string())
        );
    }

    #[test]
    fn path_ends_with_reserved_claim_name() {
        let claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": {
                "street_address": "Schulstr. 12",
                "_sd": "Schulpforta",
            }
        });

        let salts_and_paths: Vec<(String, &JsonNodePath)> = vec![
            (
                "2GLC42sKQveCfGfryNRN9w".to_string(),
                &[Key("address"), Key(SD)],
            ),
            ("Qg_O64zqAxe412a108iroA".to_string(), &[Key("address")]),
        ];

        assert_eq!(
            encoder_conceal(claims, salts_and_paths).unwrap_err().error,
            IssuerError::ReservedOrRegisteredClaimName(SD)
        );
    }

    #[test]
    fn path_passes_through_reserved_claim_name() {
        let claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": [
                "street_address",
                {
                    "_sd": {
                        "key1": "value"
                    }
                }
            ]
        });

        let salts_and_paths: Vec<(String, &JsonNodePath)> = vec![
            (
                "2GLC42sKQveCfGfryNRN9w".to_string(),
                &[Key("address"), Index(1), Key(SD), Key("key1")],
            ),
            ("Qg_O64zqAxe412a108iroA".to_string(), &[Key("address")]),
        ];

        assert_eq!(
            encoder_conceal(claims, salts_and_paths).unwrap_err().error,
            IssuerError::ReservedOrRegisteredClaimName(SD)
        );
    }

    #[test]
    fn duplicate_paths() {
        let mut claims = json_object!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        });

        let error = encode_claims(
            &mut claims,
            &[&[Key("sub")], &[Key("sub")]],
            &Sha256,
            &mut rand::thread_rng(),
        )
        .unwrap_err()
        .error;

        assert_eq!(error, IssuerError::DuplicatePath("$.sub".to_string()));
    }

    #[test]
    fn reserved_key_in_claims() {
        for reserved_claim in RESERVED_CLAIM_NAMES {
            let reserved_claim = reserved_claim.to_owned();
            let mut claims = json_object!({
                "ninja": "ninja",
                reserved_claim: "bla"
            });

            let error = encode_claims(
                &mut claims,
                &[&[Key("ninja")]],
                &Sha256,
                &mut rand::thread_rng(),
            )
            .unwrap_err()
            .error;

            assert_eq!(
                error,
                IssuerError::ReservedOrRegisteredClaimName(reserved_claim)
            );
        }
        let extra_test_cases = [
            (json_object!({ SD: ["fake hash"] }), SD),
            (
                json_object!({ "a": { "b": { "c": { SD: ["fake hash"] } } } }),
                SD,
            ),
            (
                json_object!({ "array": [{ ELLIPSIS: "fake hash" }] }),
                ELLIPSIS,
            ),
            (json_object!({ ELLIPSIS: "fake hash" }), ELLIPSIS),
            (
                json_object!({ SD_ALG_FIELD_NAME: "md5" }),
                SD_ALG_FIELD_NAME,
            ),
        ];

        for (mut claims, reserved_key) in extra_test_cases {
            claims.insert("ninja".to_string(), Value::Bool(false));

            let error = encode_claims(
                &mut claims,
                &[&[Key("ninja")]],
                &Sha256,
                &mut rand::thread_rng(),
            )
            .unwrap_err()
            .error;

            assert_eq!(
                error,
                IssuerError::ReservedOrRegisteredClaimName(reserved_key)
            );
        }
    }
}
