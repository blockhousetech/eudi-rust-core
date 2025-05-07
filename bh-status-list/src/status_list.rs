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

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{
    utils::{
        byte_and_inner_idx, check_status_against_bits, compress_and_encode, decode_and_decompress,
    },
    Error, Result, UriBuf,
};

/// The allowed values for the number of bits that each status takes on a Status
/// List.
#[derive(Debug, Clone, Copy, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum StatusBits {
    /// The status is represented with `1` bit.
    One = 1,
    /// The status is represented with `2` bits.
    Two = 2,
    /// The status is represented with `4` bits.
    Four = 4,
    /// The status is represented with `8` bits.
    Eight = 8,
}

impl StatusBits {
    /// Creates a new [`StatusBits`] from the given `bits` value. If the `bits`
    /// value is not one of the allowed values, `None` is returned.
    pub fn from_u8(bits: u8) -> Option<Self> {
        match bits {
            b if b == Self::One as u8 => Some(Self::One),
            b if b == Self::Two as u8 => Some(Self::Two),
            b if b == Self::Four as u8 => Some(Self::Four),
            b if b == Self::Eight as u8 => Some(Self::Eight),
            _ => None,
        }
    }
}

impl std::fmt::Display for StatusBits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", *self as u8)
    }
}

/// A Status List intended to be used by the Status List Owners to manipulate
/// the list.
///
/// It consists of a [`StatusList`] and its `size`, which is needed to
/// successfully manipulate the list.
///
/// This provides functionalities to create a new empty list, load an existing
/// list, append new elements to the list and update the existing elements.
///
/// # Note
///
/// This is only intended to be used by the Status List Owners, as they are the
/// ones that are changing the list. All other parties should use the
/// [`StatusList`], which will enable them to read the list at a specific index.
/// It is also what they will receive after fetching the list from the owner.
#[derive(Debug)]
pub struct StatusListInternal {
    /// The actual [`StatusList`].
    status_list: StatusList,

    /// The length of the Status List.
    ///
    /// This field is needed because the size can not be determined from the
    /// `lst` itself, since the last `byte` can still have some space available.
    size: usize,
}

/// A list of status values for all the referenced Verifiable Credentials.
///
/// It is basically an ordered list of bits, where the status of each Credential
/// is represented with a fixed amount of `bits`. Verifiable Credential will
/// then also contain an exact index pointing at its status within this list.
///
/// More about Status Lists can be read [here][1], and more about its parameters
/// [here][2].
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03#name-status-list
/// [2]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03#name-status-list-in-json-format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusList {
    /// The number of bits that each Verifiable Credential uses in the Status
    /// List (`lst`).
    bits: StatusBits,

    /// Status values for all the Verifiable Credentials contained in the Status
    /// List.
    ///
    /// It is represented as a [`Vec`] of `bytes`, where each status is
    /// represented with a fixed amount of `bits` within each `byte`.
    ///
    /// The field value is serialized by compressing it using `DEFLATE` with the
    /// `ZLIB` data format and `base64url`-encoding the result, resulting in a
    /// `String` value. It is deserialized from `String` by reversing the
    /// serialization operations.
    #[serde(serialize_with = "serialize_lst", deserialize_with = "deserialize_lst")]
    lst: Vec<u8>,

    /// An optional URI to retrieve the Status List Aggregation.
    ///
    /// The Status List Aggregation is a list of URIs to fetch all the relevant
    /// Status Lists, allowing for caching mechanisms and offline validation.
    ///
    /// More can be read [here][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03#name-status-list-aggregation
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregation_uri: Option<UriBuf>,
}

fn serialize_lst<S: Serializer>(lst: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    let lst_encoded =
        compress_and_encode(lst).map_err(|e| serde::ser::Error::custom(format!("{:?}", e)))?;

    s.serialize_str(&lst_encoded)
}

fn deserialize_lst<'de, D>(d: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let lst_encoded = String::deserialize(d)?;

    let lst = decode_and_decompress(lst_encoded)
        .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))?;

    Ok(lst)
}

impl StatusListInternal {
    /// Initializes a new empty [`StatusList`].
    pub fn new(bits: StatusBits, aggregation_uri: Option<UriBuf>) -> Self {
        Self {
            status_list: StatusList {
                bits,
                lst: Vec::new(),
                aggregation_uri,
            },
            size: 0,
        }
    }

    /// Returns the number of recorded statuses in the Status List.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns a reference to the underlying [`StatusList`].
    pub fn status_list(&self) -> &StatusList {
        &self.status_list
    }

    /// Creates a new [`StatusList`] from its exact parts.
    ///
    /// This function exists as a convenience for Status List Owners to be able
    /// to store the Status List field by field and load it later to utilize the
    /// implemented functionalities.
    ///
    /// # Errors
    ///
    /// The `size` argument **MUST** point to the last `byte` of the `lst` and
    /// all the statuses from there until the end of the last `byte` (and
    /// consequently the `lst` itself) need to be set to `0`, otherwise, the
    /// [`Error::InconsistentSize`] is returned.
    ///
    /// # Note
    ///
    /// The `size` argument can still be abused to rewrite all the trailing
    /// statuses set to `0` in the last `byte`, but there is no way to add a
    /// check for that, so the caller needs not to mess with the `size` in order
    /// to prevent bugs.
    pub fn new_from_parts(
        bits: StatusBits,
        lst: Vec<u8>,
        aggregation_uri: Option<UriBuf>,
        size: usize,
    ) -> Result<Self> {
        // If the `lst` is not empty, but the `size` is zero, and vice-versa, it
        // is an error since the `size` is thus invalid.
        if lst.is_empty() ^ (size == 0) {
            return Err(bherror::Error::root(Error::InconsistentSize)
                .ctx("`lst` not empty but the `size` is 0 or vice-versa"));
        }

        // If the `size` is zero (and consequently `lst` is empty because of the
        // check above), no more checks are needed, otherwise, do more checks.
        if size > 0 {
            // Take the indexes of the last element (at `size - 1`).
            let (byte_idx, inner_idx) = byte_and_inner_idx(bits, size - 1);

            // The last element needs to be in the last `byte`.
            if byte_idx + 1 != lst.len() {
                return Err(bherror::Error::root(Error::InconsistentSize)
                    .ctx("`size` does not point to the last `byte`"));
            }

            // The `unwrap` should be fine because `size` is positive.
            let last_byte = lst.last().unwrap();

            // The last `byte` needs to be empty (`0`) after the `inner_idx`
            // until its end, because otherwise `size` is for sure less than the
            // actual size of the list. This will catch some more (but still not
            // all) inconsistency errors.
            // Shifting by >= `N` bits results in an overflow panic, hence the
            // cast of `last_byte` to `u16`.
            if *last_byte as u16 >> ((inner_idx + 1) * bits as u8) != 0 {
                return Err(bherror::Error::root(Error::InconsistentSize)
                    .ctx("last `byte` is not empty after `size` elements"));
            }
        }

        Ok(Self {
            status_list: StatusList {
                bits,
                lst,
                aggregation_uri,
            },
            size,
        })
    }

    /// Adds a new status entry at the end of the Status List and returns an
    /// index of that entry within the list.
    ///
    /// # Errors
    ///
    /// If the provided `status` takes more bits than specified with
    /// [`StatusBits`], the method results in the [`Error::StatusTooLarge`].
    pub fn push(&mut self, status: u8) -> Result<usize> {
        let list = &mut self.status_list;

        // Check `status` size in bits.
        check_status_against_bits(list.bits, status)?;

        let (_, inner_idx) = byte_and_inner_idx(list.bits, self.size);

        // There are two cases when adding a new element to the list:
        //   1. - add to the last existing `byte`, but not to the beginning as
        //        it is covered with the 2nd case,
        //   2. - add a new `byte` and add an element to the beginning of that
        //        `byte`.
        //
        // If the `inner_idx` is `0`, it is a 2nd case and a new `byte` needs to
        // be added to the back of the list.
        if inner_idx == 0 {
            list.lst.push(0);
        }

        // The `unwrap` should be fine because there is at least one `byte`.
        let last_byte = list.lst.last_mut().unwrap();

        // Shift `status` to its index and set those bits in the `byte`-array.
        *last_byte |= status << (inner_idx * list.bits as u8);

        self.size += 1;

        Ok(self.size - 1)
    }

    /// Updates the status at the given `index` to the provided `status` value.
    ///
    /// # Errors
    ///
    /// The method results in the [`Error::IndexOutOfBounds`] error if the
    /// `index` is out of bounds, and the [`Error::StatusTooLarge`] error if the
    /// `status` does not fit in the correct amount of bits.
    pub fn update(&mut self, index: usize, status: u8) -> Result<()> {
        if index >= self.size {
            return Err(bherror::Error::root(Error::IndexOutOfBounds(
                self.size, index,
            )));
        }

        let list = &mut self.status_list;

        // Check `status` size in bits.
        check_status_against_bits(list.bits, status)?;

        let (byte_idx, inner_idx) = byte_and_inner_idx(list.bits, index);

        let byte = list
            .lst
            .get_mut(byte_idx)
            // This should never happen because of the earlier `index` check.
            .ok_or_else(|| bherror::Error::root(Error::IndexOutOfBounds(self.size, index)))?;

        let bits_per_status = list.bits as u8;

        // How much the `status` should be shifted to it's place in the list.
        let shift = inner_idx * bits_per_status;

        // `1`s on the first `self.status_list.bits` bits, `0` on others.
        // Cast to u16 is to avoid the overflow.
        let mask = ((1u16 << bits_per_status) - 1) as u8;

        // The update is as follows:
        //   1. shift `mask` to the right place, negate it and `and` with the
        //      `byte` to clear the current status there,
        //   2. `or` the result with the `status` shifted to the right place to
        //      set the new status value.
        *byte = *byte & !(mask << shift) | (status << shift);

        Ok(())
    }
}

impl StatusList {
    /// Gets the number of bits of each status in the list.
    pub fn bits(&self) -> StatusBits {
        self.bits
    }

    /// Gets the reference to the raw Status List data.
    pub fn lst(&self) -> &[u8] {
        &self.lst
    }

    /// Returns the Uri of the Status List Aggregation if it exists.
    pub fn aggregation_uri(&self) -> Option<&UriBuf> {
        self.aggregation_uri.as_ref()
    }

    /// Returns the status at the given `index`.
    ///
    /// If the `index` is out of bounds for the current [`StatusList`], `None`
    /// is returned.
    pub fn get(&self, index: usize) -> Option<u8> {
        let (byte_idx, inner_idx) = byte_and_inner_idx(self.bits, index);

        let mut byte = *self.lst.get(byte_idx)?;

        let bits_per_status = self.bits as u8;

        // The idea is as follows:
        //   1. - shift left to remove all the trailing statuses,
        //   2. - shift right to remove all the preceding statuses and extract
        //        the actual status value.
        byte <<= 8 - (inner_idx + 1) * bits_per_status;
        byte >>= 8 - bits_per_status;

        Some(byte)
    }
}

impl From<StatusListInternal> for StatusList {
    fn from(list: StatusListInternal) -> Self {
        list.status_list
    }
}

#[cfg(test)]
mod tests {
    use std::ops::RangeInclusive;

    use rand::{
        distributions::{Distribution as _, Uniform},
        thread_rng, Rng,
    };
    use serde_json::{Map, Value};

    use super::*;
    use crate::utils::statuses_per_byte;

    fn json_value_to_object<T: Serialize>(value: T) -> Map<String, Value> {
        if let Value::Object(obj) = serde_json::to_value(value).unwrap() {
            obj
        } else {
            panic!("JSON value is not a JSON object")
        }
    }

    fn get_lst(status_list: &StatusList) -> String {
        if let Value::String(lst) = json_value_to_object(status_list).remove("lst").unwrap() {
            lst
        } else {
            panic!("StatusList's `lst` field is not a `String`")
        }
    }

    fn create_json_object(
        bits: StatusBits,
        lst: &str,
        aggregation_uri: &Option<UriBuf>,
    ) -> Map<String, Value> {
        let mut expected = Map::new();

        expected.insert("bits".to_owned(), (bits as u8).into());
        expected.insert("lst".to_owned(), lst.into());

        if let Some(aggregation_uri) = aggregation_uri {
            expected.insert(
                "aggregation_uri".to_owned(),
                aggregation_uri.to_string().into(),
            );
        }

        expected
    }

    fn random_statuses(
        rng: &mut impl Rng,
        size: usize,
        bits: StatusBits,
    ) -> impl Iterator<Item = u8> + '_ {
        let max_status = ((1u16 << bits as u8) - 1) as u8;

        let dist = Uniform::new_inclusive(0, max_status);

        dist.sample_iter(rng).take(size)
    }

    fn test_status_list_push(
        bits: StatusBits,
        statuses: &[u8],
        expected_lst: &str,
        aggregation_uri: Option<UriBuf>,
    ) {
        let expected_json = create_json_object(bits, expected_lst, &aggregation_uri);

        let mut status_list = StatusListInternal::new(bits, aggregation_uri);

        for (i, &status) in statuses.iter().enumerate() {
            let new_i = status_list.push(status).unwrap();

            // Test return index from `push`.
            assert_eq!(i, new_i, "invalid returned index from `push`");
        }

        // Test `get` method.
        for (i, &status) in statuses.iter().enumerate() {
            let get_res = status_list.status_list.get(i).unwrap();
            assert_eq!(status, get_res, "`get` did not return the correct value");
        }

        // Test `push` correctness and `lst` serialization.
        assert_eq!(
            expected_lst,
            get_lst(&status_list.status_list),
            "invalid `lst` value"
        );

        // Test `StatusList` serialization.
        let actual_json = json_value_to_object(&status_list.status_list);
        assert_eq!(
            expected_json, actual_json,
            "invalid `StatusList` serialization"
        );
    }

    /// Taken from [this example][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03#section-4-3
    #[test]
    fn test_status_list_one_bit_push() {
        let bits = StatusBits::One;
        let statuses = [1u8, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
        let expected_lst = "eNrbuRgAAhcBXQ";

        test_status_list_push(bits, &statuses, expected_lst, None);
    }

    /// Taken from [this example][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03#name-status-list-token-with-2-bi
    #[test]
    fn test_status_list_two_bits_push() {
        let bits = StatusBits::Two;
        let statuses = [1u8, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
        let expected_lst = "eNo76fITAAPfAgc";

        test_status_list_push(bits, &statuses, expected_lst, None);
    }

    fn test_status_list_push_large_status(bits: StatusBits) {
        let mut status_list = StatusListInternal::new(bits, None);
        let status = 1 << bits as u8;

        // Adding the maximum allowed value should be fine.
        let idx = status_list.push(status - 1).unwrap();
        assert_eq!(0, idx);

        // `get` should work for that value.
        let get_res = status_list.status_list.get(0).unwrap();
        assert_eq!(status - 1, get_res);

        // Adding a `status` of more bits than `bits` should be an error.
        let err = status_list.push(status).unwrap_err();
        assert!(matches!(err.error, Error::StatusTooLarge(b, s) if b == bits && s == status));
    }

    #[test]
    fn test_status_list_push_large_status_fails() {
        test_status_list_push_large_status(StatusBits::One);
        test_status_list_push_large_status(StatusBits::Two);
        test_status_list_push_large_status(StatusBits::Four);
    }

    #[test]
    fn test_status_list_eight_bits_push_max_value() {
        let bits = StatusBits::Eight;
        let status = u8::MAX;

        let mut status_list = StatusListInternal::new(bits, None);

        let idx = status_list.push(status).unwrap();
        assert_eq!(0, idx);

        // `get` should work for that value.
        let get_res = status_list.status_list.get(0).unwrap();
        assert_eq!(status, get_res);
    }

    /// Taken from [this example][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03#section-4-3
    #[test]
    fn test_status_list_deserialize() {
        let bits = StatusBits::One;
        let lst = "eNrbuRgAAhcBXQ";
        // 1|0|1|1|1|0|0|1, 1|0|1|0|0|0|1|1
        let expected_lst = [0xb9u8, 0xa3];

        let json_value = Value::Object(create_json_object(bits, lst, &None));

        let status_list: StatusList = serde_json::from_value(json_value).unwrap();

        assert_eq!(bits, status_list.bits);
        assert_eq!(expected_lst, *status_list.lst);
    }

    #[test]
    fn test_status_list_new_success() {
        let bits = StatusBits::Four;
        let aggregation_uri = None;

        let status_list = StatusListInternal::new(bits, aggregation_uri.clone());

        assert_eq!(0, status_list.size);
        assert!(status_list.status_list.lst.is_empty());
        assert_eq!(aggregation_uri, status_list.status_list.aggregation_uri);
        assert_eq!(bits, status_list.status_list.bits);

        // `get` for any index on empty list should return `None`.
        let get_res = status_list.status_list.get(0);
        assert!(get_res.is_none());
    }

    fn test_status_list_new_from_parts(
        bits: StatusBits,
        lst: Vec<u8>,
        size: usize,
        aggregation_uri: Option<UriBuf>,
    ) {
        let status_list =
            StatusListInternal::new_from_parts(bits, lst.clone(), aggregation_uri.clone(), size)
                .unwrap();

        assert_eq!(size, status_list.size);
        assert_eq!(lst, status_list.status_list.lst);
        assert_eq!(aggregation_uri, status_list.status_list.aggregation_uri);
        assert_eq!(bits, status_list.status_list.bits);
    }

    #[test]
    fn test_status_list_new_from_parts_full_byte_success() {
        let bits = StatusBits::Two;
        // 10|10|00|11, 10|00|11|11
        let lst = vec![0xa3u8, 0x8f];
        let size = 8;

        test_status_list_new_from_parts(bits, lst, size, None);
    }

    #[test]
    fn test_status_list_new_from_parts_partial_byte_success() {
        let bits = StatusBits::Four;
        // 1010|0011, 0000|1001
        let lst = vec![0xa3u8, 0x09];
        let size = 3;

        test_status_list_new_from_parts(bits, lst, size, None);
    }

    #[test]
    fn test_status_list_new_from_parts_full_byte_fill_zeros_success() {
        let bits = StatusBits::Four;
        // 1010|0011, 0000|1001
        let lst = vec![0xa3u8, 0x09];
        let size = 4;

        test_status_list_new_from_parts(bits, lst, size, None);
    }

    #[test]
    fn test_status_list_new_from_parts_empty_success() {
        let bits = StatusBits::Eight;
        let lst = Vec::new();
        let size = 0;

        test_status_list_new_from_parts(bits, lst, size, None);
    }

    #[test]
    fn test_status_list_new_from_parts_empty_lst_not_size_fail() {
        let bits = StatusBits::One;
        let lst = Vec::new();
        let size = 1;

        let err = StatusListInternal::new_from_parts(bits, lst, None, size).unwrap_err();

        assert!(matches!(err.error, Error::InconsistentSize));
    }

    #[test]
    fn test_status_list_new_from_parts_zero_size_full_lst_fail() {
        let bits = StatusBits::Eight;
        // 10010111, 00000011, 10100001
        let lst = vec![0x97u8, 0x03, 0xa1];
        let size = 0;

        let err = StatusListInternal::new_from_parts(bits, lst, None, size).unwrap_err();

        assert!(matches!(err.error, Error::InconsistentSize));
    }

    #[test]
    fn test_status_list_new_from_parts_size_not_last_byte_fail() {
        let bits = StatusBits::Four;
        // 1001|0111, 0000|0011, 1010|0001
        let lst = vec![0x97u8, 0x03, 0xa1];
        let size = 4;

        let err = StatusListInternal::new_from_parts(bits, lst, None, size).unwrap_err();

        assert!(matches!(err.error, Error::InconsistentSize));
    }

    #[test]
    fn test_status_list_new_from_parts_size_mid_last_byte_fail() {
        let bits = StatusBits::One;
        // 1|0|0|1|0|1|1|1, 0|0|0|0|0|0|1|1, 1|0|1|0|0|0|0|1
        let lst = vec![0x97u8, 0x03, 0xa1];
        let size = 23;

        let err = StatusListInternal::new_from_parts(bits, lst, None, size).unwrap_err();

        assert!(matches!(err.error, Error::InconsistentSize));
    }

    #[test]
    fn test_status_list_get_index_too_large() {
        let bits = StatusBits::One;
        // 1|0|0|1|0|1|1|1, 0|0|0|0|0|0|1|1, 1|0|1|0|0|0|0|1
        let lst = vec![0x97u8, 0x03, 0xa1];
        let size = lst.len() * statuses_per_byte(bits) as usize;

        let list = StatusListInternal::new_from_parts(bits, lst, None, size)
            .unwrap()
            .status_list;

        // `get` should work for last value.
        let get_res = list.get(size - 1).unwrap();
        assert_eq!(1, get_res);

        // `get` should not work for next value.
        let get_res = list.get(size);
        assert!(get_res.is_none());
    }

    #[test]
    fn test_status_list_update_empty_list_fails() {
        let mut status_list = StatusListInternal::new(StatusBits::Four, None);

        let err = status_list.update(0, 3).unwrap_err();
        assert!(matches!(err.error, Error::IndexOutOfBounds(0, 0)));
    }

    #[test]
    fn test_status_list_update_index_too_large_fails() {
        let mut status_list = StatusListInternal::new(StatusBits::Two, None);

        status_list.push(3).unwrap();

        let err = status_list.update(1, 1).unwrap_err();
        assert!(matches!(err.error, Error::IndexOutOfBounds(1, 1)));

        let err = status_list.update(5, 2).unwrap_err();
        assert!(matches!(err.error, Error::IndexOutOfBounds(1, 5)));
    }

    fn test_status_list_update_status_too_large(bits: StatusBits) {
        let mut status_list = StatusListInternal::new(bits, None);
        status_list.push(0).unwrap();

        let status = 1 << bits as u8;

        // Updating with the maximum allowed value should be fine.
        status_list.update(0, status - 1).unwrap();

        // `get` should work fine.
        let get_res = status_list.status_list.get(0).unwrap();
        assert_eq!(status - 1, get_res, "bits={}", bits);

        // Updating with a `status` of more bits than `bits` should be an error.
        let err = status_list.update(0, status).unwrap_err();
        assert!(
            matches!(err.error, Error::StatusTooLarge(b, s) if b == bits && s == status),
            "bits={}",
            bits
        );
    }

    #[test]
    fn test_status_list_update_status_too_large_fails() {
        test_status_list_update_status_too_large(StatusBits::One);
        test_status_list_update_status_too_large(StatusBits::Two);
        test_status_list_update_status_too_large(StatusBits::Four);
    }

    #[test]
    fn test_status_list_eight_bits_update_max_value_success() {
        let status = u8::MAX;

        let mut status_list = StatusListInternal::new(StatusBits::Eight, None);
        status_list.push(0).unwrap();

        status_list.update(0, status).unwrap();

        let get_res = status_list.status_list.get(0).unwrap();
        assert_eq!(status, get_res);
    }

    fn test_status_list_update_success(rng: &mut impl Rng, bits: StatusBits, statuses: &[u8]) {
        let mut status_list = StatusListInternal::new(bits, None);

        // create random initial Status List state
        for status in random_statuses(rng, statuses.len(), bits) {
            status_list.push(status).unwrap();
        }

        for (i, &status) in statuses.iter().enumerate() {
            status_list.update(i, status).unwrap();

            let get_res = status_list.status_list.get(i).unwrap();
            assert_eq!(
                status, get_res,
                "index={}, statuses={:?}, status_list={:?}",
                i, statuses, status_list
            );
        }

        for (i, &status) in statuses.iter().enumerate() {
            let get_res = status_list.status_list.get(i).unwrap();
            assert_eq!(
                status, get_res,
                "index={}, statuses={:?}, status_list={:?}",
                i, statuses, status_list
            );
        }
    }

    fn test_status_list_update_random(
        rng: &mut impl Rng,
        bits: StatusBits,
        size_range: RangeInclusive<usize>,
    ) {
        // generate a random number of statuses
        let size = rng.gen_range(size_range);

        let statuses: Vec<u8> = random_statuses(rng, size, bits).collect();

        test_status_list_update_success(rng, bits, &statuses);
    }

    #[test]
    fn test_status_list_update_random_success() {
        let mut rng = thread_rng();

        test_status_list_update_random(&mut rng, StatusBits::One, 50..=100);
        test_status_list_update_random(&mut rng, StatusBits::Two, 50..=100);
        test_status_list_update_random(&mut rng, StatusBits::Four, 50..=100);
        test_status_list_update_random(&mut rng, StatusBits::Eight, 50..=100);
    }
}
