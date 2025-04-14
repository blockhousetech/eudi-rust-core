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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// Returns the `base64url`-encoded string **without padding** of the given
/// `payload`.
pub fn base64_url_encode<T: AsRef<[u8]>>(payload: T) -> String {
    URL_SAFE_NO_PAD.encode(payload)
}

/// Decodes the given `payload` as the `base64url`-encoded string **without
/// padding** into bytes.
pub fn base64_url_decode<T: AsRef<[u8]>>(payload: T) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CASES: [(&str, &str); 4] = [
        ("Hello, World!", "SGVsbG8sIFdvcmxkIQ"),
        ("", ""),
        ("Rust! 🚀", "UnVzdCEg8J-agA"),
        ("no padding here", "bm8gcGFkZGluZyBoZXJl"),
    ];

    #[test]
    fn test_base64_url_encode() {
        for (input, expected) in TEST_CASES {
            let result = base64_url_encode(input);
            assert_eq!(result, expected, "{input}");
        }
    }

    #[test]
    fn test_base64_url_encode_binary_data() {
        let input = [0xDE, 0xAD, 0xBE, 0xEF];
        let expected = "3q2-7w";
        let result = base64_url_encode(input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_base64_url_decode() {
        for (expected, input) in TEST_CASES {
            let result = base64_url_decode(input).unwrap();
            assert_eq!(result, expected.as_bytes(), "{input}");
        }
    }

    #[test]
    fn test_base64_url_decode_binary_data() {
        let input = "3q2-7w";
        let expected = [0xDE, 0xAD, 0xBE, 0xEF];
        let result = base64_url_decode(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_base64_url_decode_padded_input() {
        let input = "SGVsbG8sIFdvcmxkIQ==";
        let err = base64_url_decode(input).unwrap_err();
        assert!(matches!(err, base64::DecodeError::InvalidPadding));
    }

    #[test]
    fn test_base64_url_decode_invalid_input() {
        let input = "inv@lid";
        let err = base64_url_decode(input).unwrap_err();
        assert!(matches!(err, base64::DecodeError::InvalidByte(3, b'@')));
    }
}
