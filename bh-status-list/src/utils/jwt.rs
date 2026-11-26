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

use bh_jws_utils::{jwt, JwkPublic, JwtSigner, JwtVerifier};
use bherror::traits::{ForeignBoxed as _, ForeignError as _};
use serde::de::DeserializeOwned;

use crate::{token, Error, Result, StatusListTokenClaims, StatusListTokenHeader};

/// Signs a Status List JWT Token.
///
/// # Errors
///
/// If the signing of the token fails, the [`Error::TokenSigningFailed`] is
/// returned.
pub(crate) fn sign_jwt_token(
    header: &StatusListTokenHeader,
    claims: &StatusListTokenClaims,
    key: &impl JwtSigner,
) -> Result<String> {
    let signed: jwt::Token<_, _, token::Signed> = key
        .sign_jwt(jwt::Token::new(header, claims))
        .foreign_boxed_err(|| Error::TokenSigningFailed)?;
    Ok(signed.into())
}

/// Parses the given JWT `token` without verifying its signature.
///
/// # Errors
/// The function returns [`Error::TokenParsingFailed`] if it is unable to parse
/// the JWT token.
pub(crate) fn parse_jwt_token_unverified<C: DeserializeOwned>(
    token: &str,
) -> Result<jwt::Token<StatusListTokenHeader, C, jwt::token::Unverified<'_>>> {
    jwt::Token::parse_unverified(token).foreign_err(|| Error::TokenParsingFailed)
}

/// Verifies the signature of a parsed JWT.
///
/// # Errors
/// Returns [`Error::TokenSignatureVerificationFailed`] on signature failure.
pub(crate) fn verify_jwt_token<C>(
    token: jwt::Token<StatusListTokenHeader, C, jwt::token::Unverified<'_>>,
    verifier: &(impl JwtVerifier + ?Sized),
    public_key: &JwkPublic,
) -> Result<jwt::Token<StatusListTokenHeader, C, token::Verified>> {
    verifier
        .verify_jwt_signature(token, public_key)
        .foreign_boxed_err(|| Error::TokenSignatureVerificationFailed)
}
