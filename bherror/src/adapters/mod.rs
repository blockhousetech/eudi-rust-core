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

//! This module provides various adapters for making our [`crate::Error<BhError>`] types work with
//! other libraries and frameworks.
//!
//! Currently, we only have adapters for working with the [axum](https://docs.rs/axum/latest/axum/)
//! framework.  These adapters are available when the `axum` feature is enabled for this crate.

#[cfg(feature = "axum")]
pub mod axum;
