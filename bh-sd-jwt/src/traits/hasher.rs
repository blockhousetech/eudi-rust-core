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

use std::str::FromStr;

use bherror::Error;
use serde::{Deserialize, Serialize};

use crate::DecodingError;

/// The hash algorithm identifier for `SHA-256` as specified in the
/// "*Hash Name String*" column of the *IANA* [Named Information Hash Algorithm
/// Registry].
///
/// [Named Information Hash Algorithm Registry]: https://www.iana.org/assignments/named-information/named-information.xhtml
pub(crate) const SHA_256_ALG_NAME: &str = "sha-256";

/// An identifier of the algorithm used for hashing. All the algorithm variants
/// are deemed secure for the `SD-JWT` purposes.
///
/// The string value of the algorithm is used in the `_sd_alg` field of the
/// `SD-JWT`, formatted as specified in the *IANA* [Named Information Hash
/// Algorithm Registry].
///
/// The default algorithm is `SHA-256`, as specified [here].
///
/// The [`HashingAlgorithm`] can be parsed from string, expecting the same
/// format as specified above.
///
/// [Named Information Hash Algorithm Registry]: https://www.iana.org/assignments/named-information/named-information.xhtml
/// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-07#name-hash-function-claim
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashingAlgorithm {
    /// SHA-256 algorithm for hashing.
    #[serde(rename = "sha-256")]
    #[default]
    Sha256,
}

impl HashingAlgorithm {
    /// Returns the string value of the algorithm, formatted as specified in the
    /// *IANA* [Named Information Hash Algorithm Registry].
    ///
    /// [Named Information Hash Algorithm Registry]: https://www.iana.org/assignments/named-information/named-information.xhtml
    pub fn as_str(&self) -> &'static str {
        match self {
            HashingAlgorithm::Sha256 => SHA_256_ALG_NAME,
        }
    }
}

impl FromStr for HashingAlgorithm {
    type Err = bherror::Error<DecodingError>;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            SHA_256_ALG_NAME => Ok(Self::Sha256),
            _ => Err(Error::root(DecodingError::InvalidHashAlgorithmName(
                value.to_owned(),
            ))),
        }
    }
}

impl std::fmt::Display for HashingAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The trait used for calculating hash digest.
///
/// The algorithm used for calculating the digest needs to be the one returned
/// from the [`Hasher::algorithm`] method.
///
/// The trait is automatically implemented for `&dyn Hasher`, `Box<dyn Hasher>`,
/// `&H`, and `Box<H>`, where `H` implements `Hasher`.
pub trait Hasher: Send + Sync {
    /// Returns the algorithm used for calculating the hash digest within the
    /// [`Hasher::digest`] method.
    fn algorithm(&self) -> HashingAlgorithm;

    /// Computes the hash digest of the given `input` using the algorithm as
    /// returned from the [`Hasher::algorithm`] method.
    fn digest(&self, input: &[u8]) -> Vec<u8>;
}

impl<H: Hasher> Hasher for &H {
    fn algorithm(&self) -> HashingAlgorithm {
        (*self).algorithm()
    }

    fn digest(&self, input: &[u8]) -> Vec<u8> {
        (*self).digest(input)
    }
}

impl<H: Hasher> Hasher for Box<H> {
    fn algorithm(&self) -> HashingAlgorithm {
        self.as_ref().algorithm()
    }

    fn digest(&self, input: &[u8]) -> Vec<u8> {
        self.as_ref().digest(input)
    }
}

impl Hasher for &dyn Hasher {
    fn algorithm(&self) -> HashingAlgorithm {
        (*self).algorithm()
    }

    fn digest(&self, input: &[u8]) -> Vec<u8> {
        (*self).digest(input)
    }
}

impl Hasher for Box<dyn Hasher> {
    fn algorithm(&self) -> HashingAlgorithm {
        self.as_ref().algorithm()
    }

    fn digest(&self, input: &[u8]) -> Vec<u8> {
        self.as_ref().digest(input)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn hashing_algorithm_sha256_serializes_correctly() {
        let alg = HashingAlgorithm::Sha256;
        let expected = format!("\"{}\"", SHA_256_ALG_NAME);

        let serialized = serde_json::to_string(&alg).unwrap();
        assert_eq!(serialized, expected);

        let deserialized: HashingAlgorithm = serde_json::from_str(&expected).unwrap();
        assert_eq!(deserialized, alg);
    }
}
