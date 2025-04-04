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

/// Error returned by the crate API.
#[derive(strum_macros::Display, Debug, PartialEq, Clone)]
pub enum Error {
    /// Error when trying to construct or work with an invalid [`X5Chain`][crate::X5Chain].
    #[strum(to_string = "Invalid x5chain")]
    X5Chain,
    /// Error returned by the [`Builder`][crate::Builder] methods.
    #[strum(to_string = "The x5chain builder failed")]
    Builder,
}

impl bherror::BhError for Error {}

/// The [`bherror::Result`] type with the error type of
/// [`x5chain::Error`](Error), used throughout this crate.
pub type Result<T> = bherror::Result<T, Error>;
