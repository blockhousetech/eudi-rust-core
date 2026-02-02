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

/// Computes the `SHA-256` digest of the `payload`.
pub fn sha256<T: AsRef<[u8]>>(payload: T) -> [u8; 32] {
    openssl::sha::sha256(payload.as_ref())
}

/// Computes the `SHA-384` digest of the `payload`.
pub fn sha384<T: AsRef<[u8]>>(payload: T) -> [u8; 48] {
    openssl::sha::sha384(payload.as_ref())
}

/// Computes the `SHA-512` digest of the `payload`.
pub fn sha512<T: AsRef<[u8]>>(payload: T) -> [u8; 64] {
    openssl::sha::sha512(payload.as_ref())
}
