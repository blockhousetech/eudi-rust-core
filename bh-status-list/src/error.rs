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

use crate::{StatusBits, UriBuf};

/// Error type defining possible Status List related errors.
#[derive(strum_macros::Display)]
pub enum Error {
    /// Error when compressing Status List.
    #[strum(to_string = "Status List compression error")]
    Compression,

    /// Error when decompressing Status List.
    #[strum(to_string = "Status List decompression error")]
    Decompression,

    /// Error when Status List size is inconsistent with the internal representation.
    #[strum(to_string = "Status List size is inconsistent with the actual list")]
    InconsistentSize,

    /// Error when the status doesn't fit in the specified number of bits.
    #[strum(to_string = "Status {1} does not fit in {0} bits")]
    StatusTooLarge(StatusBits, u8),

    /// Error when the Status List index is out of bounds.
    #[strum(to_string = "index={1} is out of bounds (size={0})")]
    IndexOutOfBounds(usize, usize),

    /// Error when token signing fails.
    #[strum(to_string = "Unable to sign Status List Token")]
    TokenSigningFailed,

    /// Error when token parsing fails.
    #[strum(to_string = "Unable to parse a Status List Token")]
    TokenParsingFailed,

    /// Error when token signature verification fails.
    #[strum(to_string = "Unable to verify the signature of the Status List Token")]
    TokenSignatureVerificationFailed,

    /// Error when the token header `typ` value is invalid.
    #[strum(to_string = "JWT header `typ` MUST be \"statuslist+jwt\", but is \"{0}\"")]
    InvalidTokenHeaderTyp(String),

    /// Error when the token `iss` value is invalid.
    #[strum(to_string = "The `iss` value ({1}) MUST be the same as in the issued VC ({0})")]
    InvalidTokenIss(UriBuf, UriBuf),

    /// Error when the token `sub` value is invalid.
    #[strum(to_string = "The `sub` value ({1}) MUST be the same as `uri` in the issued VC ({0})")]
    InvalidTokenSub(UriBuf, UriBuf),

    /// Error when the token is expired.
    #[strum(to_string = "Token expired (exp={1}, current_time={0})")]
    TokenExpired(u64, u64),

    /// Error when the Status List cannot be fetched from URL.
    #[strum(to_string = "Unable to fetch status from {0}")]
    UnsuccessfulStatusFetch(UriBuf),
}

impl bherror::BhError for Error {}

/// Result type alias for the crate.
pub type Result<T> = bherror::Result<T, Error>;
