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

/// Error in JWK format
#[derive(strum_macros::Display, Debug, PartialEq, Clone)]
pub enum FormatError {
    /// Error that occurs when JWK parsing failed
    #[strum(to_string = "JWK parsing failed: {0}")]
    JwkParsingFailed(String),
}

impl bherror::BhError for FormatError {}

/// Error in JWS signature
#[derive(strum_macros::Display, Debug, PartialEq, Clone)]
pub enum SignatureError {
    /// Error that occurs when the signing algorithm is invalid
    #[strum(to_string = "Invalid signing algorithm {0}")]
    InvalidSigningAlgorithm(String),
}

impl bherror::BhError for SignatureError {}

/// Cryptographic error
#[derive(strum_macros::Display, Debug, PartialEq, Clone)]
pub enum CryptoError {
    /// Error that occurs when key generation failed
    #[strum(to_string = "Key generation failed")]
    KeyGenerationFailed,
    /// Error that occurs when the cryptographic backend
    /// unexpectedly failed
    #[strum(to_string = "Crypto backend failed")]
    CryptoBackend,
    /// Error that occurs when the x5chain is invalid
    #[strum(to_string = "Invalid x5chain")]
    InvalidX5Chain,
    /// Error that occurs when the signing algorithm is unsupported
    #[strum(to_string = "Unsupported: {0}")]
    Unsupported(String),
    /// Error that occurs when a public key is incorrectly formatted or
    /// otherwise not valid.
    #[strum(to_string = "Invalid public key")]
    InvalidPublicKey,
    /// Error that occurs when public keys which are supposed to be match (e.g.
    /// between a [`Signer`](crate::Signer) and [`X5Chain`](bhx5chain::X5Chain))
    /// do not match.
    #[strum(to_string = "Public key mismatch")]
    PublicKeyMismatch,
}

impl bherror::BhError for CryptoError {}
