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

use crate::{JsonObject, Value};

/// Type of JSON node paths, represented as a list of segments to follow
/// starting from the root of the JWT.
///
/// Not to be confused with the JSONPath query syntax.
pub type JsonNodePath<'a> = [JsonNodePathSegment<'a>];

/// A path segment, either an object key or an array index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonNodePathSegment<'a> {
    /// Object key path segment.
    Key(&'a str),
    /// Array index path segment.
    Index(u32),
}

impl<'a> From<&'a str> for JsonNodePathSegment<'a> {
    fn from(key: &'a str) -> Self {
        Self::Key(key)
    }
}

impl From<u32> for JsonNodePathSegment<'_> {
    fn from(index: u32) -> Self {
        Self::Index(index)
    }
}

impl std::fmt::Display for JsonNodePathSegment<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            JsonNodePathSegment::Key(key) => write!(f, "Key: {}", key),
            JsonNodePathSegment::Index(ind) => write!(f, "Ind: {}", ind),
        }
    }
}

/// Utility macro for writing path literals more ergonomically.
///
/// Every element is converted into the [`JsonNodePathSegment`] type via [`From`], which lets the
/// syntax use heterogeneous expressions.
///
/// ```
/// let path = bh_sd_jwt::path!["address", "region", "country"];
/// ```
///
/// ```
/// let path = bh_sd_jwt::path!["array", 2];
/// ```
#[macro_export]
macro_rules! path {
    [ $( $segment:expr ),* ] => {
        &[ $( $crate::JsonNodePathSegment::from($segment) ),* ]
    };
}

// TODO(issues/56) how to expose this nicely? is the rendered syntax even correct?
/// Wrapper struct implementing [`std::fmt::Display`] for [`JsonNodePath`].
pub struct DisplayWrapper<'a, T: ?Sized>(pub &'a T);

impl std::fmt::Display for DisplayWrapper<'_, JsonNodePath<'_>> {
    /// Note: several tests depend on the injectivity of this implementation
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "$")?;
        for segment in self.0 {
            match segment {
                // Use `.{}` to conform to third-party expectations.
                // Note: this approach does not support keys that contain dots.
                JsonNodePathSegment::Key(key) => write!(f, ".{}", key)?,
                JsonNodePathSegment::Index(index) => write!(f, "[{}]", index)?,
            }
        }
        Ok(())
    }
}

fn index_by_path<'v>(mut value: &'v Value, path: &JsonNodePath) -> Option<&'v Value> {
    for segment in path {
        match (value, segment) {
            (Value::Array(array), JsonNodePathSegment::Index(index)) => {
                value = array.get(*index as usize)?;
            }
            (Value::Object(object), JsonNodePathSegment::Key(key)) => {
                value = object.get(*key)?;
            }
            _ => return None,
        }
    }
    Some(value)
}

/// For empty paths, `None` is returned, as `&JsonObject` cannot be converted to `&Value`.
fn index_object_by_path<'o>(object: &'o JsonObject, path: &JsonNodePath) -> Option<&'o Value> {
    let (head, tail) = path.split_first()?;
    match head {
        JsonNodePathSegment::Key(key) => index_by_path(object.get(*key)?, tail),
        _ => None,
    }
}

/// For empty paths, `None` is returned, because it would need to return provided `object`
/// argument wrapped as [Value] which takes ownership
pub(crate) fn index_mut_object_by_path<'a>(
    object: &'a mut JsonObject,
    path: &JsonNodePath,
) -> Option<&'a mut Value> {
    let (head, tail) = path.split_first()?;
    match head {
        JsonNodePathSegment::Key(key) => index_mut_by_path(object.get_mut(*key)?, tail),
        _ => None,
    }
}

fn index_mut_by_path<'a>(mut value: &'a mut Value, path: &JsonNodePath) -> Option<&'a mut Value> {
    for segment in path {
        match (value, segment) {
            (Value::Array(array), JsonNodePathSegment::Index(index)) => {
                value = array.get_mut(*index as usize)?;
            }
            (Value::Object(object), JsonNodePathSegment::Key(key)) => {
                value = object.get_mut(*key)?;
            }
            _ => return None,
        }
    }
    Some(value)
}

pub(crate) fn paths_exist<'a, 'p>(
    value: &'a JsonObject,
    paths: &[&'p JsonNodePath<'a>],
) -> Result<(), Vec<&'p JsonNodePath<'a>>> {
    let mut nonexistent_paths = vec![];

    for path in paths {
        if !path.is_empty() && index_object_by_path(value, path).is_none() {
            nonexistent_paths.push(*path);
        }
    }

    if nonexistent_paths.is_empty() {
        Ok(())
    } else {
        Err(nonexistent_paths)
    }
}

impl<'a> From<&serde_json_path::PathElement<'a>> for JsonNodePathSegment<'a> {
    fn from(value: &serde_json_path::PathElement<'a>) -> Self {
        match *value {
            serde_json_path::PathElement::Index(index) => Self::Index(index as u32),
            serde_json_path::PathElement::Name(name) => Self::Key(name),
        }
    }
}
