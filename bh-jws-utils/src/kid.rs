/// [`Signer`] decorator with an kid` parameter associated with the key pair.
#[derive(Debug)]
pub struct SignerWithKid<S> {
    pub(crate) signer: S,
    pub(crate) kid: String,
}

impl<S: Signer> SignerWithKid<S> {
    /// Construct a new instance by pairing up a [`Signer`] with the `kid` parameter
    /// for its public key.
    pub fn new(signer: S, kid: String) -> Self {
        (Self { signer, kid })
    }
}

impl<S: Signer> HasJwkKid for SignerWithKid<S> {
    fn jwk_kid(&self) -> &str {
        self.kid
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

impl<S: HasX5Chain> HasX5Chain> for SignerWithKid<S> {
    fn x5chain(&self) -> X5Chain {
        self.signer.x5chain()
    }
}
