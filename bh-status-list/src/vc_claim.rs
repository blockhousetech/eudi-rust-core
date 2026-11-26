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

use bh_jws_utils::{JwkPublic, SignatureVerifier};
use bherror::{traits::PropagateError as _, BhError};
use iref::Uri;
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result, StatusListClient, StatusListResponse, StatusListToken, StatusListTokenClaims,
    UriBuf,
};

/// The contents of the `status` claim contained in the Verifiable Credential.
///
/// The `status` claim consists of the URI (`uri`) where a Status List can be
/// fetched and the index (`idx`) of a current Verifiable Credential within that
/// Status List.
///
/// More can be read [here][1].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusClaim {
    /// Contents of the `status` claim.
    ///
    /// This is wrapped with [`StatusListPointer`] to wrap the contents within
    /// the `status_list` claim in order to comply with the specification.
    status_list: StatusListPointer,
}

/// Contents of the `status` claim, containing an URI to fetch a Status List and
/// an index of a specific status on that list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StatusListPointer {
    /// The index of the status of a current Verifiable Credential in the Status
    /// List pointed to by the `uri` parameter.
    idx: u64,

    /// The URI pointing to the Status List or Status List Token that contain
    /// the status of a current Verifiable Credential.
    ///
    /// If it points to a Status List Token, it **MUST** be equal to the `sub`
    /// claim of the Status List Token.
    uri: UriBuf,
}

impl StatusClaim {
    /// Creates a new `status` claim value.
    pub fn new(uri: UriBuf, idx: u64) -> Self {
        Self {
            status_list: StatusListPointer { idx, uri },
        }
    }

    /// Gets the index of the status in the given Status List.
    pub fn idx(&self) -> u64 {
        self.status_list.idx
    }

    /// Gets the URI pointing to the Status List
    pub fn uri(&self) -> &UriBuf {
        &self.status_list.uri
    }

    /// Fetches the referenced Status List Token for subsequent verification.
    ///
    /// Verify the credential carrying this reference before fetching the token.
    /// This calls [`StatusListClient::get_status`] with [`Self::uri`]. The
    /// response can be inspected for signing-key hints before calling
    /// [`StatusListResponse::verify`].
    pub async fn fetch<C, E>(&self, client: &C) -> Result<StatusListResponse>
    where
        E: BhError,
        C: StatusListClient<Err = bherror::Error<E>>,
    {
        client
            .get_status(self.uri())
            .await
            .with_err(|| Error::UnsuccessfulStatusFetch(self.uri().clone()))
    }

    /// Fetches and verifies an issuer-bound JWT Status List Token.
    ///
    /// Supply the authorized signing key before fetching. The JWT must name
    /// `iss` as its issuer. Returns the verified JWT claims and the raw
    /// credential status, in that order.
    ///
    /// To resolve a key after fetching or to handle either format, use
    /// [`Self::fetch`], [`StatusListResponse::verify`], and
    /// [`crate::VerifiedStatusList::status`].
    pub async fn evaluate<C, E>(
        &self,
        client: &C,
        verifier: &(dyn SignatureVerifier + Sync),
        public_key: &JwkPublic,
        current_time: u64,
        iss: &Uri,
    ) -> Result<(StatusListTokenClaims, u8)>
    where
        E: BhError,
        C: StatusListClient<Err = bherror::Error<E>>,
    {
        let StatusListResponse::Jwt(token) = self.fetch(client).await? else {
            return Err(bherror::Error::root(Error::TokenParsingFailed)
                .ctx("expected an issuer-bound JWT Status List Token"));
        };
        let verified =
            StatusListToken::verify(&token, verifier, public_key, current_time, iss, self.uri())?;

        let (_, claims) = verified.into();

        let status = claims.status_list.status_at(self.idx())?;

        Ok((claims, status))
    }
}
