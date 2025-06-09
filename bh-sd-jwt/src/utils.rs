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

use std::fmt::{self, Display};

use bh_jws_utils::base64_url_encode;
use serde_json::Value;

use crate::{Hasher, JsonObject, RESERVED_CLAIM_NAMES};

#[derive(Debug, PartialEq, Clone)]
pub struct VecDisplayWrapper<T>(pub Vec<T>);

impl<T: Display> Display for VecDisplayWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some((last, without_last)) = self.0.split_last() {
            for element in without_last {
                write!(f, "{}, ", element)?;
            }
            write!(f, "{}", last)?;
        }
        Ok(())
    }
}

/// The field name of the hash algorithm used to hide the claims, as specified [here].
///
/// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#name-hash-function-claim
pub(crate) const SD_ALG_FIELD_NAME: &str = "_sd_alg";

/// Returns the `base64url`-encoded hash digest of the given `input` using the
/// provided [`Hasher`] to calculate the digest.
pub fn base64_url_digest(input: &[u8], hasher: impl Hasher) -> String {
    let digest = hasher.digest(input);

    base64_url_encode(digest)
}

/// Checks if provided argument `key` is one of [RESERVED_CLAIM_NAMES] according to [1], [2] and [3]
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#section-5.1.1-1
/// [2]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#section-5.1-3.7
/// [3]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#section-8.1-4.3.2.3.2.2.2.2
pub(crate) fn is_reserved_key_name(key: &str) -> Option<&'static str> {
    RESERVED_CLAIM_NAMES
        .iter()
        .find(|&name| key.eq(*name))
        .copied()
}

/// The SD-JWT payload MUST NOT contain reserved claims `_sd` and `...`
/// except for the purposes of encoding SD-JWT hash pointers.
///
/// [Reference](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt#section-5.1-3.7)
pub(crate) fn check_claim_names_object(
    object: &JsonObject,
    reserved_predicate: &impl Fn(&str) -> Option<&'static str>,
    recurse: bool,
) -> Option<&'static str> {
    for (claim_name, claim_value) in object {
        if let Some(name) = reserved_predicate(claim_name.as_str()) {
            return Some(name);
        }
        if !recurse {
            continue;
        }
        if let Some(name) = check_claim_names(claim_value, reserved_predicate) {
            return Some(name);
        }
    }
    None
}

fn check_claim_names(
    value: &Value,
    reserved_predicate: &impl Fn(&str) -> Option<&'static str>,
) -> Option<&'static str> {
    match value {
        Value::Object(object) => check_claim_names_object(object, reserved_predicate, true),
        Value::Array(array) => {
            for element in array {
                if let Some(name) = check_claim_names(element, reserved_predicate) {
                    return Some(name);
                }
            }
            None
        }
        _ => None,
    }
}
