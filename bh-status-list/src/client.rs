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

//! Module defining the interface for a Status List client.

use std::future::Future;

use bh_jws_utils::{JwkPublic, SignatureVerifier};
use iref::Uri;

use crate::{UnverifiedStatusListToken, UriBuf, VerifiedStatusList};

/// The media type for a JWT Status List Token.
pub const STATUS_LIST_JWT_MEDIA_TYPE: &str = "application/statuslist+jwt";

/// The media type for a CWT Status List Token.
pub const STATUS_LIST_CWT_MEDIA_TYPE: &str = "application/statuslist+cwt";

/// A fetched Status List Token, before signature verification.
///
/// An HTTP client selects the variant based on the response's allowed
/// `Content-Type`.
pub enum StatusListResponse {
    /// JWT Status List Token in JWS compact serialization.
    Jwt(String),
    /// CWT Status List Token as binary, tagged `COSE_Sign1`.
    Cwt(Vec<u8>),
}

impl StatusListResponse {
    /// Parses either wire format for signing-key resolution before verification.
    ///
    /// The returned header fields are untrusted key-selection hints.
    pub fn parse(&self) -> crate::Result<UnverifiedStatusListToken<'_>> {
        UnverifiedStatusListToken::parse(self)
    }

    /// Verifies the token against the credential's Status List URI.
    ///
    /// Supply the public key authorized for this credential's list and a
    /// verifier for an allowed signing algorithm. Pass Unix time in seconds
    /// and the URI from the verified credential, including when the fetch
    /// followed a redirect. The token's subject must match this URI exactly.
    ///
    /// The signature and applicable claims are checked before the list is
    /// decompressed. The issuer claim is optional. Tokens carrying an audience
    /// claim are rejected because this API has no expected audience.
    ///
    /// Call [`VerifiedStatusList::status`] to check the credential's index.
    /// When resolving the key from token headers, use [`Self::parse`] and
    /// then [`UnverifiedStatusListToken::verify`].
    pub fn verify(
        &self,
        verifier: &(impl SignatureVerifier + ?Sized),
        public_key: &JwkPublic,
        current_time: u64,
        uri: &Uri,
    ) -> crate::Result<VerifiedStatusList> {
        self.parse()?
            .verify(verifier, public_key, current_time, uri)
    }
}

/// Trait that defines the interface for a Status List client.
pub trait StatusListClient {
    /// The error type returned by the client.
    type Err;

    /// Fetches a Status List from the given URI.
    ///
    /// For HTTP, advertise the accepted formats with
    /// [`STATUS_LIST_JWT_MEDIA_TYPE`] and [`STATUS_LIST_CWT_MEDIA_TYPE`].
    /// Check the response status and content type before returning the
    /// corresponding variant, and apply the verifier's URI and redirect policy.
    fn get_status(
        &self,
        uri: &UriBuf,
    ) -> impl Future<Output = Result<StatusListResponse, Self::Err>>;
}
