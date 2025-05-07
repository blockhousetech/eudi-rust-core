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

pub(crate) mod jwt;

use std::io::{Read as _, Write as _};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, DecodeError, Engine as _};
use bherror::traits::ForeignError as _;
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};

use crate::{Error, Result, StatusBits};

/// Compresses the given `payload` using `DEFLATE` with the `ZLIB` data format,
/// and `base64url`-encodes the result.
///
/// As **RECOMMENDED** in [the specification][1], the highest possible
/// compression level is used.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03#section-4-2.3.1
pub(crate) fn compress_and_encode(payload: impl AsRef<[u8]>) -> Result<String> {
    let compressed = compress_deflate_zlib(payload).foreign_err(|| Error::Compression)?;
    Ok(base64_url_encode(compressed))
}

/// Decodes the `base64url`-encoded `payload` and decompresses the result using
/// `DEFLATE` with the `ZLIB` data format.
pub(crate) fn decode_and_decompress(payload: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    let decoded = base64_url_decode(payload).foreign_err(|| Error::Decompression)?;
    decompress_deflate_zlib(decoded).foreign_err(|| Error::Decompression)
}

/// Returns the `base64url`-encoded `String` of the given `payload`.
fn base64_url_encode(payload: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(payload)
}

/// Decodes the `base64url`-encoded `String`.
fn base64_url_decode(payload: impl AsRef<[u8]>) -> std::result::Result<Vec<u8>, DecodeError> {
    URL_SAFE_NO_PAD.decode(payload)
}

/// Compresses the given `payload` using `DEFLATE` with the `ZLIB` data format.
fn compress_deflate_zlib(payload: impl AsRef<[u8]>) -> std::io::Result<Vec<u8>> {
    // `Compression::best()` sets the highest possible compression level.
    let mut e = ZlibEncoder::new(Vec::new(), Compression::best());
    e.write_all(payload.as_ref())?;
    let compressed = e.finish()?;
    Ok(compressed)
}

/// Decompresses the given `payload` that was compressed using `DEFLATE` with
/// the `ZLIB` data format.
fn decompress_deflate_zlib(payload: impl AsRef<[u8]>) -> std::io::Result<Vec<u8>> {
    let mut d = ZlibDecoder::new(payload.as_ref());
    let mut decompressed = Vec::new();
    d.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// The number of statuses contained in a single `byte`, where each status is
/// represented with `bits` amount of bits.
///
/// Note that it can only ever be a value between `1` and `8` (inclusive).
pub(crate) fn statuses_per_byte(bits: StatusBits) -> u8 {
    8 / bits as u8
}

/// Returns an index of a `byte` and an index within that `byte` that will
/// contain the Status List element at the given index (`idx`), where each
/// status is represented with `bits` amount of bits.
///
/// Note that the latter can only ever be a value between `0` and `7`
/// (inclusive).
pub(crate) fn byte_and_inner_idx(bits: StatusBits, idx: usize) -> (usize, u8) {
    let spb = statuses_per_byte(bits) as usize;

    (idx / spb, (idx % spb) as u8)
}

/// Checks if the `status` fits in the `bits` amount of bits.
///
/// # Errors
///
/// The [`Error::StatusTooLarge`] error is returned if the `status` does not fit
/// in the `bits` amount of bits.
pub(crate) fn check_status_against_bits(bits: StatusBits, status: u8) -> Result<()> {
    // Shifting by >= `N` bits results in an overflow panic, hence the cast
    // of `status` to `u16`.
    if status as u16 >> bits as u8 != 0 {
        return Err(bherror::Error::root(Error::StatusTooLarge(bits, status)));
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Taken from [this example][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03#section-4.1-3
    #[test]
    fn test_compress_encode1() {
        let payload = [0xb9u8, 0xa3];
        let expected = "eNrbuRgAAhcBXQ";

        let encoded = compress_and_encode(payload).unwrap();

        assert_eq!(expected, encoded);
    }

    /// Taken from [this example][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03#section-10.1-6
    #[test]
    fn test_compress_encode2() {
        let payload = [0xc9u8, 0x44, 0xf9];
        let expected = "eNo76fITAAPfAgc";

        let encoded = compress_and_encode(payload).unwrap();

        assert_eq!(expected, encoded);
    }

    /// Taken from [this example][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03#section-4.1-3
    #[test]
    fn test_decode_decompress1() {
        let encoded = "eNrbuRgAAhcBXQ";
        let expected = vec![0xb9u8, 0xa3];

        let decompressed = decode_and_decompress(encoded).unwrap();

        assert_eq!(expected, decompressed);
    }

    /// Taken from [this example][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03#section-10.1-6
    #[test]
    fn test_decode_decompress2() {
        let encoded = "eNo76fITAAPfAgc";
        let expected = vec![0xc9u8, 0x44, 0xf9];

        let decompressed = decode_and_decompress(encoded).unwrap();

        assert_eq!(expected, decompressed);
    }

    #[test]
    fn test_round_empty_payload() {
        let payload: [u8; 0] = [];

        let compressed = compress_deflate_zlib(payload).unwrap();

        let encoded = base64_url_encode(&compressed);

        let decoded = base64_url_decode(encoded).unwrap();

        let decompressed = decompress_deflate_zlib(&decoded).unwrap();

        assert_eq!(decoded, compressed);
        assert_eq!(decompressed, payload);
    }
}
