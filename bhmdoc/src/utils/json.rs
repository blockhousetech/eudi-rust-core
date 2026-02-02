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

use ciborium::value::{Integer as CborInt, Value as CborValue};
use serde_json::{value::Number as JsonNumber, Value as JsonValue};

/// Consumes the provided CBOR value and returns the owned underlying `String`,
/// or [`None`].
fn cbor_text_into_string(cbor: CborValue) -> Option<String> {
    if let CborValue::Text(text) = cbor {
        Some(text)
    } else {
        None
    }
}

/// Converts the CBOR value into JSON value.
///
/// If the value can not be converted, [`None`] is returned. The value can not be converted if the
/// CBOR numbers do not fit into JSON numbers, or the CBOR `map` has non-`string` keys.
///
/// This conversion is requested to be implemented in the [`ciborium`] directly within this [GitHub
/// Issue][1].
///
/// [1]: <https://github.com/enarx/ciborium/issues/50>
pub fn cbor_to_json(cbor: CborValue) -> Option<JsonValue> {
    Some(match cbor {
        CborValue::Null => JsonValue::Null,
        CborValue::Bool(boolean) => JsonValue::Bool(boolean),
        CborValue::Text(string) => JsonValue::String(string),
        CborValue::Integer(int) => JsonValue::Number({
            let int: i128 = int.into();
            if let Ok(int) = u64::try_from(int) {
                JsonNumber::from(int)
            } else if let Ok(int) = i64::try_from(int) {
                JsonNumber::from(int)
            } else {
                JsonNumber::from_f64(int as f64)?
            }
        }),
        CborValue::Float(float) => JsonValue::Number(JsonNumber::from_f64(float)?),
        CborValue::Array(vec) => {
            JsonValue::Array(vec.into_iter().map(cbor_to_json).collect::<Option<_>>()?)
        }
        CborValue::Map(map) => JsonValue::Object(
            map.into_iter()
                .map(|(k, v)| Some((cbor_text_into_string(k)?, cbor_to_json(v)?)))
                .collect::<Option<_>>()?,
        ),
        CborValue::Bytes(bytes) => bytes.into(),
        CborValue::Tag(_, value) => cbor_to_json(*value)?,
        // needed because `CborValue` is `#[non_exhaustive]`
        _ => unimplemented!(),
    })
}

/// Convert a [`serde_json::Value`] to [`ciborium::Value`].
pub fn json_to_cbor(json: JsonValue) -> CborValue {
    // Due to lack of conversion functions from/to CBOR structures to/from JSON, we implemented it
    // by hand.  This was already requested on [Github Issue][1], but before it is resolved we use
    // our own implementation.
    //
    // [1]: <https://github.com/enarx/ciborium/issues/50>
    match json {
        JsonValue::Null => CborValue::Null,
        JsonValue::Bool(boolean) => CborValue::Bool(boolean),
        JsonValue::String(string) => CborValue::Text(string),
        JsonValue::Number(number) => {
            if let Some(number) = number.as_u64() {
                CborValue::Integer(CborInt::from(number))
            } else if let Some(number) = number.as_i64() {
                CborValue::Integer(CborInt::from(number))
            } else if let Some(number) = number.as_f64() {
                CborValue::Float(number)
            } else {
                unreachable!()
            }
        }
        JsonValue::Array(vec) => CborValue::Array(vec.into_iter().map(json_to_cbor).collect()),
        JsonValue::Object(map) => CborValue::Map(
            map.into_iter()
                .map(|(k, v)| (CborValue::Text(k), json_to_cbor(v)))
                .collect(),
        ),
    }
}
