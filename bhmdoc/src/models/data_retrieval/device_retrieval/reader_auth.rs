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

//! This module defines the data model described in the section "9.1.4 mdoc reader authentication"
//! of the [ISO/IEC 18013-5:2021][1] standard.
//!
//! [1]: <https://www.iso.org/standard/69084.html>

use serde::{Deserialize, Serialize};

use crate::utils::coset::{deserialize_coset, serialize_coset};

/// [`ReaderAuth`] as defined in the section `9.1.4.4` of the [ISO/IEC 18013-5:2021][1] standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ReaderAuth(
    #[serde(
        serialize_with = "serialize_coset",
        deserialize_with = "deserialize_coset"
    )]
    coset::CoseSign1,
);
