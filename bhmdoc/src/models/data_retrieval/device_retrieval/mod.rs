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

//! This module defines types and functions which implement the section "8.3.2.1 Device retrieval"
//! of the [ISO/IEC 18013-5:2021][1] standard.
//!
//! Subsections of the standard have been correspondingly split into submodules of this module.
//!
//! [1]: <https://www.iso.org/standard/69084.html>

pub mod device_auth;
pub mod issuer_auth;
pub mod reader_auth;
pub mod request;
pub mod response;
