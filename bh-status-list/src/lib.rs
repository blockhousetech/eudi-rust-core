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

//! A `crate` dedicated to dealing with Status Lists for Verifiable Credentials.
//!
//! The implementation is based on [this specification][1]. Status Lists are
//! used to keep track of statuses of specific Verifiable Credentials (in the
//! specification called the *Referenced Tokens*), e.g. active, revoked, etc.
//!
//! The Status Lists are created, updated and **signed** by issuers of
//! Verifiable Credentials, and are publicly available. They contain statuses of
//! multiple credentials, where each credential contains an URI to fetch a
//! Status List and an index of its status on that list.
//!
//! Note: only the JSON format is currently supported for the Status List (CBOR
//! is not supported) and the JWT format for the Status List Token (CWT is not
//! supported).
//!
//! # Details
//!
//! The main data structures available in the crate are the [`StatusList`],
//! [`StatusListInternal`], [`StatusClaim`] and [`StatusListToken`]. The
//! [`StatusList`] and [`StatusListInternal`] structs are used to create and
//! manage the Status List, while the [`StatusListToken`] struct is used to
//! create and manage the Status List Token while [`StatusClaim`] represents a
//! single status claim within a Status List.
//!
//! The trait [`StatusListClient`] is provided to allow the user to implement
//! their own client to fetch the Status List from a given URI.
//!
//! # Example
//!
//! Construct a [`StatusList`], [`StatusListToken`], implement a dummy
//! [`StatusListClient`] and verify a [`StatusClaim`].
//! ```
//! use bh_jws_utils::{Es256Signer, Es256Verifier};
//! use bh_status_list::{UriBuf, StatusBits, StatusList,
//!  StatusListInternal, StatusClaim, StatusListResponse,
//!  StatusListToken, StatusListTokenClaims, StatusListClient};
//!
//!
//! // Struct representing our dummy client
//! struct DummyClient(Es256Signer);
//!
//! // Dummy error type for the client.
//! struct DummyErr;
//!
//! // `BhError` trait requires `std::fmt::Display` to be implemented.
//! impl std::fmt::Display for DummyErr {
//!     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//!         Ok(())
//!     }
//! }
//!
//! impl bherror::BhError for DummyErr {}
//!
//! fn iss_uri() -> UriBuf {
//!     UriBuf::new(b"http://example.com/issuer".to_vec()).unwrap()
//! }
//!
//! fn status_list_uri() -> UriBuf {
//!    UriBuf::new(b"http://example.com/status_list".to_vec()).unwrap()
//! }
//!
//! // Dummy client implementation of the `StatusListClient` trait.
//! impl StatusListClient for DummyClient {
//!     type Err = bherror::Error<DummyErr>;
//!     async fn get_status(&self, _uri: &UriBuf) -> Result<StatusListResponse, Self::Err> {
//!         let mut status_list = StatusListInternal::new(StatusBits::Two, None);
//!         status_list.push(0b00).unwrap();
//!         status_list.push(0b01).unwrap();
//!         status_list.push(0b10).unwrap();
//!         status_list.push(0b11).unwrap();
//!         let status_list_claims = StatusListTokenClaims::new(
//!             iss_uri(),
//!             status_list_uri(),
//!             1000,
//!             None,
//!             None,
//!             status_list.status_list().clone(),
//!         );
//!         let status_list_token =
//!             StatusListToken::new(status_list_claims, "example_kid".to_string(), &self.0)
//!                 .unwrap();
//!
//!         Ok(StatusListResponse::Jwt(
//!             status_list_token.as_str().to_string(),
//!         ))
//!     }
//! }
//!
//! // Generate a new key pair for the signer using `bh-jws-utils`.
//! let signer = Es256Signer::generate("example_kid".to_string()).unwrap();
//! let public_jwk = signer.public_jwk().unwrap();
//! let client = DummyClient(signer);
//!
//! // Create a new claim to verify.
//! let status_claim = StatusClaim::new(
//!     status_list_uri(),
//!     1,
//! );
//!
//! // Evaluate the status claim using the dummy client
//! // and the public key of the signer.
//! let (_, status) = tokio_test::block_on(status_claim
//!     .evaluate(
//!         &client,
//!         &Es256Verifier,
//!         &public_jwk,
//!         1000,
//!         &iss_uri(),
//!     ))
//!     .unwrap();
//!
//! // Check the status we retrieved from the client.
//! assert_eq!(status, 0b01);
//! ```
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03

pub mod client;
mod error;
mod status_list;
mod status_list_token;
mod utils;
mod vc_claim;

pub use bh_jws_utils::jwt::Error as JwtError;
pub use client::{StatusListClient, StatusListResponse};
pub use error::{Error, Result};
pub use iref::{InvalidUri, UriBuf};
pub use status_list::{StatusBits, StatusList, StatusListInternal};
pub use status_list_token::{StatusListToken, StatusListTokenClaims, StatusListTokenHeader};
pub use vc_claim::StatusClaim;

/// Reexporting the [`bh_jws_utils`] crate's JWT types for convenience.
pub mod token {
    pub use bh_jws_utils::jwt::token::{Signed, Verified};
}
