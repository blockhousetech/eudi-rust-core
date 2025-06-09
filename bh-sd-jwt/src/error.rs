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

use bh_jws_utils::SigningAlgorithm;

use crate::{holder::HolderError, verifier::VerifierError, DecodingError};

/// Top-level error type for the SD-JWT crate.
#[derive(strum_macros::Display, Debug, PartialEq)]
pub enum Error {
    /// Format error, e.g. invalid SD-JWT format or non-parsable JWT.
    #[strum(to_string = "Format error: {0}")]
    Format(FormatError),

    /// Signature error, e.g. invalid JWT signature or missing signature verifier.
    #[strum(to_string = "Signature error: {0}")]
    Signature(SignatureError),

    /// Decoding error, e.g. issues with decoding the JWT or SD-JWT.
    #[strum(to_string = "Decoding error: {0}")]
    Decoding(DecodingError),

    /// JWT not yet valid error, indicating the JWT's `nbf` (not before) claim is in the future.
    #[strum(to_string = "Jwt not yet valid: current time is {0}, nbf is {1}")]
    JwtNotYetValid(u64, u64),

    /// JWT expired error, indicating the JWT's `exp` (expiration) claim is in the past.
    #[strum(to_string = "Jwt expired, current time is {0}, expiration is {1}")]
    JwtExpired(u64, u64),
}

impl bherror::BhError for Error {}

/// Format error related to parsing and validating SD-JWTs and VCs (Verifiable Credentials).
#[derive(strum_macros::Display, Debug, PartialEq, Clone)]
pub enum FormatError {
    /// Error indicating that the SD-JWT format is invalid.
    #[strum(to_string = "Invalid SD-JWT format")]
    InvalidSdJwtFormat,

    /// Error indicating that the SD-JWT is not parsable.
    #[strum(to_string = "Provided JWT is not parsable")]
    NonParseableJwt,

    /// Error indicating that VC schema is invalid.
    #[strum(to_string = "Invalid VC schema")]
    InvalidVcSchema,

    /// Error indicating that the `iat` (issued at) claim is not a number.
    #[strum(to_string = "Invalid Iat format. Iat needs to be a number")]
    InvalidIatFormat,

    /// Error indicating that the disclosure data is in an invalid format.
    #[strum(to_string = "Invalid disclosure: {0}")]
    InvalidDisclosure(String),
}

impl bherror::BhError for FormatError {}

/// Error type for signature-related issues in SD-JWTs.
#[derive(strum_macros::Display, Debug, PartialEq, Clone)]
pub enum SignatureError {
    /// Error indicating that the JWT signature is invalid.
    #[strum(to_string = "Invalid Jwt signature")]
    InvalidJwtSignature,

    /// Error indicating that there is no signature verifier available for the
    /// specified signing algorithm.
    #[strum(to_string = "Missing signature verifier for algorithm {0}")]
    MissingSignatureVerifier(SigningAlgorithm),

    /// Error indicating that the public key lookup failed.
    #[strum(to_string = "Public key lookup failed")]
    PublicKeyLookupFailed,
}

impl bherror::BhError for SignatureError {}

impl Error {
    pub(crate) fn to_holder_error(&self) -> HolderError {
        match self {
            Self::Format(error) => HolderError::Format(error.clone()),
            Self::Signature(error) => HolderError::Signature(error.clone()),
            Self::Decoding(error) => HolderError::Decoding(error.clone()),
            Self::JwtExpired(time, nbf) => HolderError::JwtExpired(*time, *nbf),
            Self::JwtNotYetValid(time, exp) => HolderError::JwtNotYetValid(*time, *exp),
        }
    }

    pub(crate) fn to_verifier_error(&self) -> VerifierError {
        match self {
            Self::Format(error) => VerifierError::Format(error.clone()),
            Self::Signature(error) => VerifierError::Signature(error.clone()),
            Self::Decoding(error) => VerifierError::Decoding(error.clone()),
            Self::JwtExpired(time, nbf) => VerifierError::JwtExpired(*time, *nbf),
            Self::JwtNotYetValid(time, exp) => VerifierError::JwtNotYetValid(*time, *exp),
        }
    }
}

/// Result type used across the crate.
pub type Result<T, E> = bherror::Result<T, E>;
