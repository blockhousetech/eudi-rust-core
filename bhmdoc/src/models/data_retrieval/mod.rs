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

//! This module defines types and functions which implement the section "8.3 Data retrieval" of the
//! [ISO/IEC 18013-5:2021][1] standard.
//!
//! Subsections of the standard have been correspondingly split into submodules of this module.
//!
//! [1]: <https://www.iso.org/standard/69084.html>

pub mod common;
pub mod device_retrieval;

use std::collections::HashMap;

use common::{DataElementIdentifier, DataElementValue, NameSpace};

use crate::utils::json::cbor_to_json;

/// Claims of the respective [`Document`][device_retrieval::response::Document].
///
/// This just wraps the
/// [`HashMap<NameSpace, HashMap<DataElementIdentifier, DataElementValue>>`],
/// providing the [`into_json`][Claims::into_json] functionality.
#[derive(Debug, Clone, PartialEq)]
pub struct Claims(pub HashMap<NameSpace, HashMap<DataElementIdentifier, DataElementValue>>);

impl Claims {
    /// Converts the [`Claims`] into JSON object.
    ///
    /// If the `claims` can not be converted, [`None`] is returned. That is the
    /// case when CBOR numbers do not fit into JSON numbers, or the CBOR `map`
    /// contains non-`string` keys, which should almost never happen in
    /// practice.
    pub fn into_json(self) -> Option<serde_json::Map<String, serde_json::Value>> {
        self.0
            .into_iter()
            .map(|(k, v)| {
                // convert `HashMap<DataElementIdentifier, DataElementValue>`
                // into JSON object
                let v_json = serde_json::Value::Object(
                    v.into_iter()
                        .map(|(k, v)| Some((k.0, cbor_to_json(v.0)?)))
                        .collect::<Option<_>>()?,
                );

                Some((k.0, v_json))
            })
            .collect::<Option<_>>()
    }
}

/// Claims borrowed from the respective
/// [`IssuerSigned`][device_retrieval::response::IssuerSigned].
///
/// This just wraps the
/// [`HashMap<&NameSpace, HashMap<&DataElementIdentifier, &DataElementValue>>`].
pub struct BorrowedClaims<'a>(
    pub HashMap<&'a NameSpace, HashMap<&'a DataElementIdentifier, &'a DataElementValue>>,
);

impl BorrowedClaims<'_> {
    /// Converts `self` into [`Claims`] by cloning all the underlying claims.
    pub fn into_claims(self) -> Claims {
        Claims(
            self.0
                .into_iter()
                .map(|(k, v)| {
                    let v_owned = v.into_iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                    (k.clone(), v_owned)
                })
                .collect(),
        )
    }
}
