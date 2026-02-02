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

//! This module defines the data model that is shared across different data retrieval methods as
//! described in the section "8.3.1 Data model" of the [ISO/IEC 18013-5:2021][1] standard.
//!
//! [1]: <https://www.iso.org/standard/69084.html>

use ciborium::Value;
use serde::{Deserialize, Serialize};

/// [`DocType`] as defined in the section `8.3.1` of the [ISO/IEC 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DocType(pub String);

impl std::fmt::Display for DocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for DocType {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for DocType {
    fn from(value: &str) -> Self {
        value.to_owned().into()
    }
}

/// [`NameSpace`] as defined in the section `8.3.1` of the [ISO/IEC 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NameSpace(pub String);

impl std::fmt::Display for NameSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for NameSpace {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for NameSpace {
    fn from(value: &str) -> Self {
        value.to_owned().into()
    }
}

/// [`DataElementIdentifier`] as defined in the section `8.3.1` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataElementIdentifier(pub String);

impl From<String> for DataElementIdentifier {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for DataElementIdentifier {
    fn from(value: &str) -> Self {
        value.to_owned().into()
    }
}

/// [`DataElementValue`] as defined in the section `8.3.1` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DataElementValue(pub Value);

impl<T: Into<Value>> From<T> for DataElementValue {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}
