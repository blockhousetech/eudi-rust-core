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

use std::future::Future;

use bh_jws_utils::JwkPublic;
use bherror::{BhError, Error};

use crate::issuer::IssuerJwtHeader;

mod hasher;
pub(crate) use hasher::SHA_256_ALG_NAME;
pub use hasher::{Hasher, HashingAlgorithm};
mod r#impl;
pub use r#impl::Sha256;

/// Look up the issuer's public key for the purpose of signature verification
/// based on the alleged `iss` identifier and the JWT header (both obviously not
/// yet verified).
///
/// If it is not possible to retrieve the public key for any reason,
/// error an with appropriate message will be returned.
///
/// The implementations that this trait is intended for (but not limited to) are described in,
/// [Issuer-signed JWT Verification Key Validation] section:
///
///   - retrieving Issuer Metadata using HTTPS GET request
///   - X.509 Certificates from the provided `header`
///   - DID Document resolution from the `iss` value
///
/// This trait should be able to support non-standard implementations (e.g. lookup in database)
/// and mock implementations.
///
/// # Security
///
/// The implementation MUST only look up public keys from trusted sources;
/// otherwise, the protocol as a whole is insecure since there is no guarantee
/// of integrity of would-be-issuer-signed data.
///
/// Depending on the method used for lookup (which varies depending on the `iss`
/// URI), this requirement realizes in different forms, e.g. using HTTPS with
/// proper server certificate validation.
///
/// # References
/// See Section 5. of the [interoperability profile] and the reference therein to section ~5~ 3.5 of the [SD-JWT VC] specification.
/// See also the [issuer phone-home] privacy considerations.
///
/// [interoperability profile]: https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html#section-5-1.8
/// [Issuer-signed JWT Verification Key Validation]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#name-issuer-signed-jwt-verificat
/// [issuer phone-home]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01#name-issuer-phone-home
pub trait IssuerPublicKeyLookup: Sync {
    /// [`BhError`] type used in this trait.
    type Err: BhError;

    /// Lookup a public key for the alleged Issuer Identifier.
    fn lookup(
        &self,
        alleged_iss: &str,
        header: &IssuerJwtHeader,
    ) -> impl Future<Output = Result<JwkPublic, Error<Self::Err>>> + Send;
}
