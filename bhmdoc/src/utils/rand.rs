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

use rand::Rng;

use super::base64::base64_url_encode;

/// A length in bytes of the `random` value from the
/// [`IssuerSignedItem`][crate::models::data_retrieval::device_retrieval::response::IssuerSignedItem].
///
/// The minimum value is specified to be `16` in the section `9.1.2.5` of the [ISO/IEC
/// 18013-5:2021][1].
///
/// [1]: <https://www.iso.org/standard/69084.html>
const SALT_ENTROPY_BYTES: usize = 16;

pub fn generate_salt<R: Rng + ?Sized>(rng: &mut R) -> Vec<u8> {
    let mut salt = vec![0u8; SALT_ENTROPY_BYTES];
    rng.fill_bytes(&mut salt);
    debug_assert_eq!(
        salt.len(),
        SALT_ENTROPY_BYTES,
        "`salt` length MUST be {}",
        SALT_ENTROPY_BYTES
    );
    salt
}

/// Generates a `nonce` value.
///
/// The `nonce` is generated as a random, `base64-url` encoded `String` with 256
/// bits of entropy.
pub fn generate_nonce<R: Rng + ?Sized>(rng: &mut R) -> String {
    let mut nonce_bytes = [0u8; 32];
    rng.fill_bytes(&mut nonce_bytes);
    base64_url_encode(nonce_bytes)
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_generate_salt() {
        let mut rng = thread_rng();

        let salt = generate_salt(&mut rng);

        assert_eq!(salt.len(), SALT_ENTROPY_BYTES);

        let all_zero = salt.into_iter().all(|b| b == 0);

        assert!(!all_zero);
    }
}
