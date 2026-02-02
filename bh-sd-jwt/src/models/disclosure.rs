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

use core::fmt;
use std::collections::{HashMap, HashSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bherror::{
    traits::{ErrorContext, ForeignError},
    Error,
};

use super::{error::DecodingResult, path_map::PathMapObject, JsonNodePath, Value};
use crate::{
    error::FormatError,
    utils::{self},
    DecodingError,
};

/// A disclosure for a JSON node in the VC, in both parsed form and the original
/// serialized form.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Disclosure {
    pub(crate) data: DisclosureData,
    // serialized-as-hashed
    serialized: String,
}

impl TryFrom<String> for Disclosure {
    type Error = Error<FormatError>;

    fn try_from(serialized: String) -> Result<Self, Self::Error> {
        let decoded = URL_SAFE_NO_PAD
            .decode(&serialized)
            .foreign_err(|| {
                FormatError::InvalidDisclosure("provided string is not base64 ".to_string())
            })
            .ctx(|| serialized.clone())?;

        let array: Vec<Value> = serde_json::from_slice(&decoded)
            .foreign_err(|| {
                FormatError::InvalidDisclosure(
                    "serde json could not parse decoded base64 string ".to_string(),
                )
            })
            .ctx(|| serialized.clone())?;

        let data = match array.len() {
            3 => {
                let [salt, key, value] = array.try_into().unwrap();
                create_disclosure_data_key_value(salt, key, value)
            }
            2 => {
                let [salt, value] = array.try_into().unwrap();
                create_disclosure_data_array_element(salt, value)
            }
            _ => Err(Error::root(FormatError::InvalidDisclosure(format!(
                "deserialized disclosure array has invalid length {}",
                array.len(),
            )))),
        }
        .ctx(|| "error while creating a disclosure from base64 serialized string ".to_string())
        .ctx(|| serialized.clone())?;

        Ok(Self { data, serialized })
    }
}

fn create_disclosure_data_key_value(
    salt: Value,
    key: Value,
    value: Value,
) -> crate::Result<DisclosureData, FormatError> {
    let Value::String(salt) = salt else {
        return Err(Error::root(FormatError::InvalidDisclosure(
            "salt value is not a string".to_string(),
        )));
    };
    let Value::String(key) = key else {
        return Err(Error::root(FormatError::InvalidDisclosure(
            "key value is not a string".to_string(),
        )));
    };

    Ok(DisclosureData::KeyValue { salt, key, value })
}

fn create_disclosure_data_array_element(
    salt: Value,
    value: Value,
) -> crate::Result<DisclosureData, FormatError> {
    let Value::String(salt) = salt else {
        return Err(Error::root(FormatError::InvalidDisclosure(
            "salt value is not a string".to_string(),
        )));
    };

    Ok(DisclosureData::ArrayElement { salt, value })
}

impl fmt::Display for Disclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.data {
            DisclosureData::KeyValue { salt, key, value } => {
                write!(f, "[{}, {}, {}]", salt, key, value)
            }
            DisclosureData::ArrayElement { salt, value } => write!(f, "[{}, {}]", salt, value),
        }
    }
}

impl Disclosure {
    /// Construct a new [`Disclosure`] from the given `salt`, `claim_name` and `claim_value`.
    pub fn new(salt: String, claim_name: Option<String>, claim_value: Value) -> Self {
        let input = if let Some(name) = &claim_name {
            format!("[\"{}\", \"{}\", {}]", &salt, &name, &claim_value)
        } else {
            format!("[\"{}\", {}]", &salt, &claim_value)
        };

        let encoded = bh_jws_utils::base64_url_encode(input);

        let data = if let Some(name) = claim_name {
            DisclosureData::KeyValue {
                salt,
                key: name,
                value: claim_value,
            }
        } else {
            DisclosureData::ArrayElement {
                salt,
                value: claim_value,
            }
        };

        Self {
            data,
            serialized: encoded,
        }
    }

    /// Disclosure data value.
    pub fn value(&self) -> &Value {
        match &self.data {
            DisclosureData::KeyValue { value, .. } => value,
            DisclosureData::ArrayElement { value, .. } => value,
        }
    }

    /// Disclosure data key, i.e. claim name.
    pub fn claim_name(&self) -> Option<&str> {
        match &self.data {
            DisclosureData::KeyValue { key, .. } => Some(key),
            _ => None,
        }
    }

    /// Serialized form of [`Self`]
    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    /// Serialize [`Self`] into an owned [`String`].
    pub fn into_string(self) -> String {
        self.serialized
    }
}

/// Parsed form of a disclosure.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum DisclosureData {
    /// A key-value pair disclosure data.
    KeyValue {
        /// Disclosure hash salt.
        salt: Salt,
        /// Key (claim name) of the disclosure.
        key: String,
        /// Value of the disclosure.
        value: Value,
    },
    /// An array element disclosure data.
    ArrayElement {
        /// Disclosure hash salt.
        salt: Salt,
        /// Value of the disclosure.
        value: Value,
    },
}

/// Base64url encoded disclosure hash salt.
pub type Salt = String;

/// Base64url encoded hash value.
pub type Digest = String;

#[derive(Debug)]
pub(crate) struct DisclosureByDigestTable<'a>(pub(crate) HashMap<Digest, &'a Disclosure>);

impl<'a> DisclosureByDigestTable<'a> {
    pub(crate) fn new(
        disclosures: &'a [Disclosure],
        hasher: impl crate::Hasher,
    ) -> DecodingResult<Self> {
        let mut disclosure_by_digest = HashMap::new();
        for disclosure in disclosures {
            let digest = utils::base64_url_digest(disclosure.as_str().as_bytes(), &hasher);
            if disclosure_by_digest.insert(digest, disclosure).is_some() {
                return Err(Error::root(DecodingError::DisclosureDigestCollision));
            }
        }
        Ok(Self(disclosure_by_digest))
    }
}

/// Table of disclosures by the path of the JSON node (i.e. key of an object or
/// element of an array) they conceal. Useful for computing required sets of
/// disclosures for presentations.
///
/// It MAY be sparse - i.e. it could not contain subtrees of the original model
/// where no disclosures were present.
#[derive(Debug, yoke::Yokeable)]
pub(crate) struct DisclosureByPathTable<'model>(PathMapObject<&'model Disclosure>);

impl<'model> DisclosureByPathTable<'model> {
    pub(crate) fn new(inner: PathMapObject<&'model Disclosure>) -> Self {
        Self(inner)
    }

    /// Return an iterator over disclosures that "cover" the provided set of
    /// paths. Useful for creating presentations.
    ///
    /// A disclosure _covers_ a given path iff the path of the node the
    /// disclosure conceals is a prefix of the given path, i.e. the given path
    /// is such that when taken from the root of the JWT it passes through the
    /// hash pointer to the disclosure. Such disclosures are the ones which need
    /// to be presented so that the given set of paths would be present in the
    /// reconstructed JSON.
    ///
    /// **Note that paths are not checked for existence!** Nonexistent paths are
    /// simply ignored.
    ///
    /// There is no particular guaranteed order in which the disclosures are yielded.
    pub(crate) fn disclosures_covering_paths(
        &self,
        paths: &[&JsonNodePath],
    ) -> impl Iterator<Item = &'model Disclosure> {
        let mut set = HashSet::new();

        for path in paths {
            // For every non-empty prefix of the path, if the node at that path is
            // behind a disclosure, this disclosure covers the path and must be included
            // when trying to disclose the node at the end of the whole path.

            // Ignore the error in case the path is non-existent, since that
            // could be simply because the table is sparse.
            let _result = self.0.traverse_path(path.iter().copied(), |disclosure| {
                set.insert(*disclosure);
            });
        }

        set.into_iter()
    }
}

#[cfg(test)]
mod tests {

    use bh_jws_utils::base64_url_encode;
    use serde_json::{json, Value};

    use crate::{error::FormatError, Disclosure};

    type Result = std::result::Result<(), Box<dyn std::error::Error>>;

    fn test_disclosure_encode_and_parse(
        salt: &str,
        claim_name: Option<&str>,
        claim_value: Value,
        encoded: &str,
    ) -> Result {
        let disclosure =
            Disclosure::new(salt.to_owned(), claim_name.map(str::to_owned), claim_value);

        assert_eq!(disclosure.as_str(), encoded);

        let parsed = Disclosure::try_from(encoded.to_owned()).unwrap();

        assert_eq!(parsed, disclosure);

        Ok(())
    }

    /// Example taken from [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.2.1-5
    #[test]
    fn test_disclosure_encode_and_parse_object_property() -> Result {
        test_disclosure_encode_and_parse(
            "_26bc4LT-ac6q2KI6cBW5es",
            Some("family_name"),
            Value::String("Möbius".to_owned()),
            "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0",
        )
    }

    /// Example taken from [here].
    ///
    /// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#section-5.2.2-4
    #[test]
    fn test_disclosure_encode_array_element() -> Result {
        test_disclosure_encode_and_parse(
            "lklxF5jMYlGTPUovMNIvCA",
            None,
            Value::String("FR".to_owned()),
            "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0",
        )
    }

    #[test]
    fn invalid_disclosure_not_a_base64_string() {
        let invalid_base64 = "bla";

        let decoded = Disclosure::try_from(invalid_base64.to_string());

        assert_eq!(
            decoded.unwrap_err().error,
            FormatError::InvalidDisclosure("provided string is not base64 ".to_string())
        )
    }

    #[test]
    fn invalid_disclosure_too_few_elements_in_deserialized_array() {
        let input = json!(["bla"]);
        let encoded = base64_url_encode(input.to_string());

        let decoded = Disclosure::try_from(encoded.clone());

        assert_eq!(
            decoded.unwrap_err().error,
            FormatError::InvalidDisclosure(
                "deserialized disclosure array has invalid length 1".to_string(),
            )
        );
    }

    #[test]
    fn invalid_disclosure_too_many_elements_in_deserialized_array() {
        let input = json!(["bla", "bla", 5, "bla"]);
        let encoded = base64_url_encode(input.to_string());

        let decoded = Disclosure::try_from(encoded.clone());

        assert_eq!(
            decoded.unwrap_err().error,
            FormatError::InvalidDisclosure(
                "deserialized disclosure array has invalid length 4".to_string()
            )
        );
    }

    #[test]
    fn invalid_disclosure_salt_not_a_string() {
        let input = json!([{"bla": "bla"}, 10.0]);

        let encoded = base64_url_encode(input.to_string());

        let decoded = Disclosure::try_from(encoded.clone());

        assert_eq!(
            decoded.unwrap_err().error,
            FormatError::InvalidDisclosure("salt value is not a string".to_string())
        );
    }

    #[test]
    fn invalid_disclosure_key_is_not_a_string() {
        let input = json!(["bla", {"bla": "bla"}, 10.0]);

        let encoded = base64_url_encode(input.to_string());

        let decoded = Disclosure::try_from(encoded.clone());

        assert_eq!(
            decoded.unwrap_err().error,
            FormatError::InvalidDisclosure("key value is not a string".to_string())
        );
    }
}
