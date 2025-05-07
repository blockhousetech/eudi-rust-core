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

use bh_jws_utils::{jwt, JwkPublic, JwtSigner, JwtVerifier};
use bherror::traits::{ForeignBoxed as _, ForeignError as _};

use crate::{token, Error, Result, StatusListTokenClaims, StatusListTokenHeader};

/// Signs a Status List JWT Token.
///
/// # Errors
///
/// If the signing of the token fails, the [`Error::TokenSigningFailed`] is
/// returned.
pub(crate) fn sign_jwt_token(
    header: StatusListTokenHeader,
    claims: StatusListTokenClaims,
    key: &impl JwtSigner,
) -> Result<jwt::Token<StatusListTokenHeader, StatusListTokenClaims, token::Signed>> {
    key.sign_jwt(jwt::Token::new(header, claims))
        .foreign_boxed_err(|| Error::TokenSigningFailed)
}

/// Verifies the signature of the given JWT `token`.
///
/// # Errors
/// The function returns the following errors:
/// - [`Error::TokenParsingFailed`] if it is unable to parse the JWT token,
/// - [`Error::TokenSignatureVerificationFailed`] if the signature of the JWT
///   token is invalid.
pub(crate) fn verify_jwt_token(
    token: &str,
    verifier: &(impl JwtVerifier + ?Sized),
    public_key: &JwkPublic,
) -> Result<jwt::Token<StatusListTokenHeader, StatusListTokenClaims, token::Verified>> {
    // Parse the token (without verification).
    let unverified_token: jwt::Token<StatusListTokenHeader, StatusListTokenClaims, _> =
        jwt::Token::parse_unverified(token).foreign_err(|| Error::TokenParsingFailed)?;

    // Verify the JWT signature.

    verifier
        .verify_jwt_signature(unverified_token, public_key)
        .foreign_boxed_err(|| Error::TokenSignatureVerificationFailed)
}
