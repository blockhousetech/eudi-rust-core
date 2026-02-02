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

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! This crate implements Selective Disclosure JSON Web Tokens.
//!
//! It provides functionality to create, sign, and verify JWTs that support selective disclosure of
//! claims, in accordance with emerging IETF drafts: [Selective Disclosure for JWTs (SD-JWT)][1] &
//! [SD-JWT-based Verifiable Credentials (SD-JWT VC)][2].
//!
//! [1]: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt>
//! [2]: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc>
//!
//! # Details
//!
//! The main components of this crate are the following.
//!
//! * [`issuer`] -- Constructs and signs JWTs with standard and custom claims.
//! * [`holder`] -- Imports, manages, and presents SD-JWT credentials with selective disclosure.
//! * [`verifier`] -- Validates JWT signatures, claim integrity, and key binding challenges.
//! * [`lookup`] -- Provides different methods of retrieving an issuer’s public key.
//!
//! # Examples
//!
//! The `bh-sd-jwt` repository contains [the full examples][examples], so you should take a look
//! there to see how things fit together.
//!
//! [examples]: <https://github.com/blockhousetech/eudi-rust-core/tree/main/bh-sd-jwt/examples>

// Re-export the `bh-jws-utils` crate
pub use bh_jws_utils;
pub use error::{Error, FormatError, Result, SignatureError};
use sd_jwt::SdJwt;

mod error;
mod key_binding;
mod models;
mod sd_jwt;
#[cfg(test)]
mod test_utils;
mod traits;
mod utils;

mod decoder;
mod encoder;
pub mod holder;
pub mod issuer;
pub mod lookup;
pub mod verifier;

pub use iref;
pub use issuer::{IssuerJwt, IssuerJwtHeader};
pub use key_binding::KeyBindingChallenge;
pub use models::*;
pub use sd_jwt::SdJwtKB;
pub use traits::*;
