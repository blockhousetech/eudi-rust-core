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

use bherror::traits::{ForeignBoxed as _, ForeignError, PropagateError};
use bhx5chain::X5Chain;

use crate::{
    openssl_impl::public_key_from_jwk_es256, BoxError, CryptoError, HasJwkKid, HasX5Chain,
    JwkPublic, Signer, SigningAlgorithm,
};

/// [`Signer`] decorator with an X.509 certificate chain associated with
/// the key pair.
///
/// Useful in contexts which require distributing the certificate chain with the
/// signature (e.g. the `x5c` JWT header parameter).
#[derive(Debug)]
pub struct SignerWithChain<S> {
    pub(crate) signer: S,
    pub(crate) x5chain: X5Chain,
}

impl<S: Signer> SignerWithChain<S> {
    /// Construct a new instance by pairing up a [`Signer`] with the [`X5Chain`]
    /// for its public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the public keys of the [`Signer`] and [`X5Chain`]'s
    /// leaf certificate do not match.
    ///
    /// Currently, due to limited support for signing algorithms, returns an
    /// error if the key algorithm is not supported.
    pub fn new(signer: S, x5chain: X5Chain) -> bherror::Result<Self, CryptoError> {
        public_key_matches(&signer, &x5chain)?;

        Ok(Self { signer, x5chain })
    }

    /// Returns a reference to the contained [`X5Chain`].
    pub fn certificate_chain(&self) -> &X5Chain {
        &self.x5chain
    }

    /// Get the public key in JWK format.
    pub fn public_jwk(&self) -> bherror::Result<JwkPublic, CryptoError> {
        self.signer
            .public_jwk()
            .map_err(|boxed_error| downcast_or_chain(boxed_error, || CryptoError::CryptoBackend))
    }
}

fn public_key_matches<S: Signer>(
    signer: &S,
    x5chain: &X5Chain,
) -> bherror::Result<(), CryptoError> {
    let signer_public_key = signer_public_key_openssl(signer)?;

    let leaf_public_key = x5chain
        .leaf_certificate_key()
        .with_err(|| CryptoError::InvalidX5Chain)?;

    if !leaf_public_key.public_eq(&signer_public_key) {
        return Err(bherror::Error::root(CryptoError::PublicKeyMismatch));
    }

    Ok(())
}

fn signer_public_key_openssl<S: Signer>(
    signer: &S,
) -> bherror::Result<openssl::pkey::PKey<openssl::pkey::Public>, CryptoError> {
    let signer_public_jwk = signer
        .public_jwk()
        .map_err(|boxed_error| downcast_or_chain(boxed_error, || CryptoError::CryptoBackend))?;

    match signer.algorithm() {
        SigningAlgorithm::Es256 => {
            let signer_public_key = public_key_from_jwk_es256(&signer_public_jwk)
                .with_err(|| CryptoError::InvalidPublicKey)?;
            Ok(openssl::pkey::PKey::from_ec_key(signer_public_key)
                .foreign_err(|| CryptoError::CryptoBackend)?)
        }
        _ => Err(bherror::Error::root(CryptoError::Unsupported(
            "only ES256 is currently supported".to_owned(),
        ))),
    }
}

/// Either successfully downcast to the specified [`bherror::BhError`], or chain
/// a new such error onto this one.
fn downcast_or_chain<E, F>(boxed_error: BoxError, f: F) -> bherror::Error<E>
where
    E: bherror::BhError,
    F: FnOnce() -> E,
{
    match boxed_error.downcast() {
        Ok(boxed_downcast_error) => *boxed_downcast_error,
        original_error_result @ Err(_) => original_error_result.foreign_boxed_err(f).unwrap_err(),
    }
}

impl<S: Signer> Signer for SignerWithChain<S> {
    fn algorithm(&self) -> SigningAlgorithm {
        self.signer.algorithm()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, BoxError> {
        self.signer.sign(message)
    }

    fn public_jwk(&self) -> Result<JwkPublic, BoxError> {
        self.signer.public_jwk()
    }
}

impl<S: Signer> HasX5Chain for SignerWithChain<S> {
    fn x5chain(&self) -> X5Chain {
        self.x5chain.clone()
    }
}

impl<S: HasJwkKid> HasJwkKid for SignerWithChain<S> {
    fn jwk_kid(&self) -> &str {
        self.signer.jwk_kid()
    }
}

#[cfg(test)]
mod tests {
    use crate::{CryptoError, Es256Signer};

    use super::SignerWithChain;

    #[test]
    fn signer_with_chain_construction() {
        let correct_key = Es256Signer::generate("correct".into()).unwrap();
        let certificate_chain = bhx5chain::Builder::dummy()
            .generate_x5chain(&correct_key.public_key_pem().unwrap(), None)
            .unwrap();

        let _signer = SignerWithChain::new(correct_key, certificate_chain.clone()).unwrap();

        // Generate a different key pair, not corresponding to the leaf certificate
        let incorrect_key = Es256Signer::generate("incorrect".into()).unwrap();

        // `Es256Signer` does not impl Debug, so this is a workaround
        let Err(error) = SignerWithChain::new(incorrect_key, certificate_chain) else {
            unreachable!()
        };
        assert_eq!(error.error, CryptoError::PublicKeyMismatch);
    }
}
