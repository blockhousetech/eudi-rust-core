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

use crate::{Hasher, HashingAlgorithm};

/// A [`Hasher`] implementation for the `SHA-256` hash function.
#[derive(Debug, Default, Copy, Clone)]
pub struct Sha256;

impl Hasher for Sha256 {
    fn algorithm(&self) -> HashingAlgorithm {
        HashingAlgorithm::Sha256
    }

    fn digest(&self, input: &[u8]) -> Vec<u8> {
        openssl::sha::sha256(input).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_test_vectors() {
        assert_eq!(Sha256.algorithm(), HashingAlgorithm::Sha256);
        assert_eq!(
            &hex::encode(Sha256.digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            &hex::encode(Sha256.digest(b"Some test content")),
            "0a8d48be37831ed288c5d2d0c2eb7d359c4732c34f0a7c8f9bd0797dc5459029"
        );
        assert_eq!(
            &hex::encode(Sha256.digest(b"Some other test content")),
            "a37a5724520c0e4cd8181057f99edecf7fd4d4e44524af432d2d2f93276fc304"
        );
    }
}
