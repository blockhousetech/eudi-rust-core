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

use crate::utils::VecDisplayWrapper;

/// Error type defining possible decoding errors while parsing SD-JWTs and VCs
/// (Verifiable Credentials).
#[derive(strum_macros::Display, Debug, PartialEq, Clone)]
pub enum DecodingError {
    /// Error indicating that the disclosure data is in an invalid format.
    #[strum(to_string = "Mismatched disclosure format")]
    MismatchedDisclosureFormat,

    /// Error indicating that a reserved key name is being used inappropriately.
    #[strum(to_string = "Reserved key name {0} usage")]
    ReservedKeyName(&'static str),

    /// Error indicating that the digest is not in the expected format.
    #[strum(to_string = "Malformed digest: {0}")]
    MalformedDigest(String),

    /// Error indicating that there are more than one disclosures with the same
    /// digest.
    #[strum(to_string = "Disclosure digest collision")]
    DisclosureDigestCollision,

    /// Error indicating that a disclosure digest is duplicated.
    #[strum(to_string = "Duplicated digest: {0}")]
    DuplicateDigest(String),

    /// Error indicating that a disclosure is unused.
    #[strum(to_string = "Unused disclosures: {0}")]
    UnusedDisclosures(VecDisplayWrapper<String>),

    /// Error indicating that a claim name is duplicated.
    #[strum(to_string = "Duplicate claim name: {0}")]
    DuplicateClaimName(String),

    /// Error indicating that the hash algorithm name is invalid or not
    /// supported.
    #[strum(to_string = "Invalid hash algorithm name: {0}")]
    InvalidHashAlgorithmName(String),

    /// Error indicating that a hasher is missing for the specified hash
    /// algorithm.
    #[strum(to_string = "Missing hasher: {0}")]
    MissingHasher(String),
}

impl bherror::BhError for DecodingError {}

pub type DecodingResult<T> = bherror::Result<T, DecodingError>;
