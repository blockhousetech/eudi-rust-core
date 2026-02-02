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

//! This crate provides the functionality for handling mobile driving licenses (mDLs) and other
//! `mso_mdoc` Credentials in compliance with the [ISO/IEC 18013-5:2021][1] & [ISO/IEC TS
//! 18013-7:2024][2] standards, but modified to work with OpenID for [Verifiable Presentations][3]
//! and [Verifiable Credential Issuance][4] specifications.
//!
//! [1]: <https://www.iso.org/standard/69084.html>
//! [2]: <https://www.iso.org/standard/82772.html>
//! [3]: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
//! [4]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>
//!
//! # Details
//!
//! The crate defines multiple modules, which can be roughly divided as follows.
//!
//!   * High-level modules: [`device`], [`issuer`] and [`verifier`].
//!   * The [`error`] module describing the error values.
//!   * Low-level data model -- [`models`].
//!
//! A typical user of this crate is expected to care only about the high-level modules.  The lower
//! level data model is exposed for advanced users wishing to adapt the crate to their `mso_mdoc`
//! use case.
//!
//! # Examples
//!
//! The `bhmdoc` repository contains [the full examples][examples], so you should take a look there
//! to see how things fit together.
//!
//! Here we will just summarize the most common use cases of the crate.
//!
//! [examples]: <https://github.com/blockhousetech/eudi-rust-core/tree/main/bhmdoc/examples>
//!
//! ## Issuing a Mobile Driving License (mDL)
//!
//! ```ignore
//! use std::str::FromStr;
//!
//! use bhmdoc::models::{
//!     mdl::*,
//!     FullDate,
//! };
//!
//! let mut rng = rand::thread_rng();
//! let issuer_signer = _; // Implementation of [`bh_jws_utils::Signer`]
//! let device_key = _; // Instance of [`bhmdoc::DeviceKey`].
//! let current_time = 100;
//!
//! let mdl_mandatory = MDLMandatory {
//!     family_name: "Doe".to_owned(),
//!     given_name: "John".to_owned(),
//!     birth_date: "1980-01-02".parse().unwrap(),
//!     issue_date: FullDate::from_str("2024-01-01").unwrap().into(),
//!     expiry_date: FullDate::from_str("2029-01-01").unwrap().into(),
//!     issuing_authority: "MUP".to_owned(),
//!     issuing_country: "RH".to_owned(),
//!     document_number: "1234".to_owned(),
//!     portrait: vec![1u8, 2, 3].into(),
//!     driving_privileges: 7,
//!     un_distinguishing_sign: "sign".to_owned(),
//! };
//!
//! let mdl = MDL::new(mdl_mandatory);
//!
//! let issued = bhmdoc::Issuer
//!     .issue_mdl(mdl, device_key, &issuer_signer, &mut rng, current_time)
//!     .unwrap();
//! ```
//!
//! ## Verifying an Issued `mso_mdoc` Credential
//!
//! ```no_run
//! let verifier = bhmdoc::Verifier::from_parts(
//!     "example verifier client id".to_owned(),
//!     "https://example.response.uri".to_owned(),
//!     "example nonce".to_owned(),
//! );
//!
//! // `vp_token` as per <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
//! let vp_token = "Base64url encoded Verifiable Presentation";
//! let device_response = bhmdoc::models::DeviceResponse::from_base64_cbor(vp_token).unwrap();
//! let current_time = 100;
//!
//! // This should return `Some(bh_jws_utils::SignatureVerifier)`
//! // based on the received `bh_jws_utils::SigningAlgorithm`.
//! let get_signature_verifier = |_alg| None;
//!
//! let claims = verifier
//!     .verify(
//!         device_response,
//!         current_time,
//!         "example mdoc generated nonce",
//!         None,
//!         get_signature_verifier,
//!     )
//!     .unwrap();
//! ```

pub mod device;
pub mod error;
pub mod issuer;
pub mod models;
mod utils;
pub mod verifier;

pub use device::Device;
pub use error::{MdocError, Result};
pub use issuer::Issuer;
pub use models::data_retrieval::device_retrieval::issuer_auth::DeviceKey;
pub use utils::{json::json_to_cbor, rand::generate_nonce};
pub use verifier::Verifier;
