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

//! This crate provides functions and types for working with an ordered array of X.509 certificates
//! (`x5chain`) as defined in [RFC 9360][1].
//!
//! [1]: <https://www.rfc-editor.org/rfc/rfc9360.html#section-2-5.4.1>
//!
//! # Details
//!
//! The primary API this crate offers is the [`X5Chain`] struct.
//!
//! We also have a [`JwtX5Chain`] type which should be used when working with JSON Web Token (JWT).
//! This should only be treated as a "wrapper" type around [`X5Chain`], and as such isn't meant for
//! any manipulation of the `x5chain` itself.
//!
//! # Examples
//!
//! ## Simple Use
//!
//! You can construct the [`X5Chain`] directly if you have [`openssl::x509::X509`] certificates.
//! The following example assumes that is the case for `*_certificate` variables.
//!
//! ```ignore
//! let x5chain = bhx5chain::X5Chain::new(vec![issuer_certificate, intermediary_certificate])
//!     .expect("valid x5chain");
//!
//! let trust = bhx5chain::X509Trust::new(vec![trusted_root_certificate]);
//!
//! x5chain
//!     .verify_against_trusted_roots(&trust)
//!     .expect("trusted x5chain");
//!```
//!
//! ## Advanced Use
//!
//! If you need to create multiple Issuer certificates during the runtime but base the `x5chain` on
//! some intermediary certificates & private key, you should use the [`Builder`].
//!
//! ```no_run
//! let intermediary_private_key = std::fs::read_to_string("path-to-intermediary-private-key.pem")
//!     .expect("read intermediary private key");
//! let intermediary_certificate = std::fs::read_to_string("path-to-intermediary-certificate.pem")
//!     .expect("read intermediary certificate");
//! let trusted_root_certificate = std::fs::read_to_string("path-to-root-certificate.pem")
//!     .expect("read trusted root certificate");
//!
//! // Setup the builder for `x5chain`
//! let x5chain_builder = bhx5chain::Builder::new(
//!     intermediary_private_key.as_bytes(),
//!     intermediary_certificate.as_bytes(),
//!     trusted_root_certificate.as_bytes(),
//! )
//! .expect("create x5chain builder");
//!
//! let issuer_private_key =
//!     std::fs::read_to_string("path-to-issuer-private-key.pem").expect("read issuer private key");
//!
//! // Optionally set the Issuer Identifier.
//! let iss = iref::UriBuf::new("https://example.com/issuer".into()).unwrap();
//!
//! // Complete the `x5chain`
//! let x5chain = x5chain_builder
//!     .generate_x5chain(issuer_private_key.as_bytes(), Some(&iss))
//!     .expect("generate x5chain");
//! ```
//!
//! ### Conversion Between [`X5Chain`] & [`JwtX5Chain`]
//!
//! ```ignore
//! // Convert the `x5chain` into `JwtX5Chain` in order to serialize it in a JWT.
//! let jwt_x5chain: bhx5chain::JwtX5Chain = x5chain.try_into().expect("valid x5chain");
//!
//! // Alternatively, after deserializing the `JwtX5Chain` out of JWT, convert to `X5Chain` type.
//! let x5chain: bhx5chain::X5Chain = jwt_x5chain.try_into().expect("valid x5chain");
//! ```

mod builder;
mod error;
mod jwt;
mod x5chain;

pub use builder::*;
pub use error::*;
pub use jwt::*;
pub use x5chain::*;
