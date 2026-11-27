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

use iref::Uri;

use crate::{Error, Result, StatusClaim, StatusList, UriBuf};

/// The authenticated claims of a JWT or CWT Status List Token.
///
/// The list is verified for its subject URI and the time passed to
/// verification. A caller sharing or caching the list applies its signer
/// authorization and freshness policies each time it uses the list.
#[derive(Debug)]
pub struct VerifiedStatusList {
    /// Optional issuer identifier asserted by the signer.
    pub(crate) iss: Option<String>,
    /// The Status List URI, verified against the credential's reference.
    pub(crate) sub: UriBuf,
    /// Issuance time in seconds since the Unix epoch.
    pub(crate) iat: f64,
    /// Optional expiration time in seconds since the Unix epoch.
    pub(crate) exp: Option<f64>,
    /// Optional cache lifetime in seconds from resolution.
    pub(crate) ttl: Option<u64>,
    /// The decoded Status List.
    pub(crate) status_list: StatusList,
}

impl VerifiedStatusList {
    /// Returns the optional issuer identifier asserted in the token.
    ///
    /// The shared verification API binds the list to the expected URI.
    /// Authority to sign for that URI comes from the caller's key policy.
    pub fn issuer(&self) -> Option<&str> {
        self.iss.as_deref()
    }

    /// Returns the authenticated Status List URI.
    pub fn subject(&self) -> &Uri {
        &self.sub
    }

    /// Returns the issuance time in seconds since the Unix epoch.
    ///
    /// Use it to apply the verifier's own freshness limits.
    pub fn issued_at(&self) -> f64 {
        self.iat
    }

    /// Returns the optional expiration time in seconds since the Unix epoch.
    pub fn expires_at(&self) -> Option<f64> {
        self.exp
    }

    /// Returns the optional cache lifetime in seconds from retrieval.
    ///
    /// Record the retrieval time to apply this lifetime to cached lists.
    /// The token also has an independent limit when [`Self::expires_at`]
    /// returns a timestamp.
    pub fn ttl(&self) -> Option<u64> {
        self.ttl
    }

    /// Returns the decoded Status List.
    pub fn status_list(&self) -> &StatusList {
        &self.status_list
    }

    /// Reads the credential's status after checking its URI and index.
    ///
    /// The returned byte is the status code. Zero denotes a valid credential.
    /// Apply the verifier's policy to other values. When reusing a cached list,
    /// enforce its expiration and cache lifetime before calling this method.
    pub fn status(&self, claim: &StatusClaim) -> Result<u8> {
        validate_subject(&self.sub, claim.uri())?;
        self.status_list.status_at(claim.idx())
    }
}

pub(crate) fn validate_subject(sub: &UriBuf, expected: &Uri) -> Result<()> {
    if sub.as_str() != expected.as_str() {
        return Err(bherror::Error::root(Error::InvalidTokenSub(
            expected.to_owned(),
            sub.clone(),
        )));
    }
    Ok(())
}

pub(crate) fn validate_optional_claims(
    iss: Option<&str>,
    ttl: Option<u64>,
    audience_present: bool,
) -> Result<()> {
    if iss.is_some_and(|iss| iss.contains(':') && Uri::new(iss.as_bytes()).is_err()) {
        return Err(bherror::Error::root(Error::InvalidTokenClaims).ctx("invalid issuer"));
    }
    if ttl == Some(0) {
        return Err(bherror::Error::root(Error::InvalidTokenClaims).ctx("ttl must be positive"));
    }
    if audience_present {
        return Err(bherror::Error::root(Error::InvalidTokenClaims)
            .ctx("this verifier has no configured audience for Status List Tokens"));
    }
    Ok(())
}

pub(crate) fn validate_numeric_dates(
    current_time: u64,
    iat: f64,
    exp: Option<f64>,
    nbf: Option<f64>,
) -> Result<()> {
    if [Some(iat), exp, nbf]
        .into_iter()
        .flatten()
        .any(|time| !time.is_finite())
    {
        return Err(bherror::Error::root(Error::InvalidTokenClaims).ctx("invalid NumericDate"));
    }
    if let Some(exp) = exp.filter(|&exp| exp <= current_time as f64) {
        return Err(
            bherror::Error::root(Error::TokenExpired(current_time, exp as u64))
                .ctx(format!("NumericDate exp={exp}")),
        );
    }
    if nbf.is_some_and(|nbf| nbf > current_time as f64) {
        return Err(bherror::Error::root(Error::TokenNotYetValid));
    }
    Ok(())
}
