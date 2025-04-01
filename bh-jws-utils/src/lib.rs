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

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! This crate provides functions and types for working with [JSON Web
//! Signatures (JWS)][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/rfc7515
//!
//! # Details
//!
//! The primary way to use this library is via the [`JwtSigner`] and
//! [`JwtVerifier`] traits, which provide functionality for signing JWTs and
//! verifying signed JWTs. A default [`openssl`] backed implementation of these
//! traits is available by using the [`openssl_impl::Es256Signer`] and
//! [`openssl_impl::Es256Verifier`] structs which implement [`JwtSigner`] and
//! [`JwtVerifier`] respectively. These implementations are available under the
//! default feature `openssl` which can be disabled and replaced by a custom
//! implementation.
//!
//! A custom implementation must implement the [`Signer`] trait for signing
//! JWKs, [`SignatureVerifier`] trait for verifying signatures and optionally
//! the [`HasJwkKid`] trait if you need to access the JWK key id. The
//! [`JwtSigner`] and [`JwtVerifier`] traits are implemented automatically for
//! the custom implementation if the custom implementation implements the
//! [`Signer`] and [`SignatureVerifier`] traits respectively.
//!
//! # Examples
//!
//! ## Sign and verify a JWT
//!
//! ```
//! use bh_jws_utils::{json_object, Es256Signer, Es256Verifier, JwtSigner, JwtVerifier};
//!
//! // Construct a new signer
//! let signer = Es256Signer::generate("dummy-kid".to_string()).unwrap();
//!
//! // Construct a JWT
//! let dummy_jwt = json_object!({
//!    "sub": "1234567890",
//!    "name": "John Doe",
//!    "iat": 1516239022
//! });
//!
//! // Sign the JWT
//! let signed_jwt = signer.sign_jwt(dummy_jwt).unwrap();
//!
//! // Get the public JWK for verification
//! let public_jwk = signer.public_jwk().unwrap();
//!
//! // Verify the JWT
//! let token: serde_json::Value = Es256Verifier
//!     .verify_jwt_signature(signed_jwt.as_str(), &public_jwk)
//!     .unwrap();
//! ```

#[cfg(feature = "openssl")]
mod openssl_impl;

mod error;
mod jwk;
mod traits;
mod utils;

pub use error::*;
pub use jwk::*;
// Re-export the `jwt` crate
pub use jwt;
#[cfg(feature = "openssl")]
pub use openssl_impl::*;
pub use traits::*;
pub use utils::*;

/// Helper macro with the same syntax as [`serde_json::json`] specialized for
/// constructing JSON objects.
///
/// It will construct a more specific type ([`serde_json::Map<String,Value>`])
/// than just [`serde_json::Value`] when constructing an object, and panic if
/// the syntax is valid JSON but not an object.
#[macro_export]
macro_rules! json_object {
    ($stuff:tt) => {
        match ::serde_json::json!($stuff) {
            ::serde_json::Value::Object(o) => o,
            _ => unreachable!("JSON literal wasn't an object"),
        }
    };
}
