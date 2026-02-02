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

//! This module defines the core data types & functions used in the crate to implement the [ISO/IEC
//! 18013-5:2021][1] standard.
//!
//! This is the main module for various models that represent the core concepts and data structures
//! involved in the issuance, retrieval, and verification of mobile driving licenses (mDLs) and
//! other `mso_mdoc` Credentials.  Essentially, this module implements the [ISO/IEC
//! 18013-5:2021][1] standard, but modified to work with OpenID for [Verifiable Presentations][2]
//! and [Verifiable Credential Issuance][3].  Submodules roughly correspond to sections of the
//! [ISO/IEC 18013-5:2021][1] standard.
//!
//! [1]: <https://www.iso.org/standard/69084.html>
//! [2]: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
//! [3]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>

pub mod data_retrieval;
pub mod issue;
pub mod mdl;

use std::str::FromStr;

use bherror::traits::{ErrorContext as _, ForeignError as _};
use chrono::{Timelike as _, Utc};
use ciborium::{from_reader, into_writer, value::Value};
pub use data_retrieval::{
    common::NameSpace,
    device_retrieval::{
        reader_auth::ReaderAuth,
        request::{DeviceRequest, DocRequest, IntentToRetain},
        response::DeviceResponse,
    },
    Claims,
};
use hex::FromHexError;
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{utils::rand::generate_salt, MdocError};

/// A _CBOR_ tag value for the `full-date` as specified by the section `7.2.1` of the [ISO/IEC
/// 18013-5:2021][1].
///
/// [1]: <https://www.iso.org/standard/69084.html>
const MDOC_FULL_DATE_CBOR_TAG: u64 = 1004;

/// A _CBOR_ tag value for date-time as specified in [RFC 8949][1] which is used by [ISO/IEC
/// 18013-5:2021][2].
///
/// [1]: <https://datatracker.ietf.org/doc/html/rfc8949#name-standard-date-time-string>
/// [2]: <https://www.iso.org/standard/69084.html>
const MDOC_TDATE_CBOR_TAG: u64 = 0;

/// A _CBOR_ tag value for the _CBOR_ byte-string as specified by the section `8.1` of the [ISO/IEC
/// 18013-5:2021][1].
///
/// [1]: <https://www.iso.org/standard/69084.html>
const MDOC_BYTES_CBOR_TAG: u64 = 24;

/// A _CBOR_ _byte string_.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(into = "Value")]
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// Decode a hex string into [`Bytes`].
    pub fn from_hex(value: &str) -> Result<Self, FromHexError> {
        let value = hex::decode(value)?;
        Ok(Self(value))
    }

    /// Generate [`Bytes`] to be used a salt value.
    pub fn random_salt<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let salt = generate_salt(rng);
        Self(salt)
    }
}

impl FromStr for Bytes {
    type Err = FromHexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_hex(value)
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<Bytes> for Value {
    fn from(bytes: Bytes) -> Self {
        Self::Bytes(bytes.0)
    }
}

/// A _CBOR_ _byte string_ where the bytes represent a _CBOR_ representation of the underlying
/// type.
///
/// It is assigned a _CBOR_ tag value of `24` as specified in section `8.1` of [ISO/IEC
/// 18013-5:2021][1].
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Clone, Debug, PartialEq)]
pub struct BytesCbor<T> {
    pub(crate) inner: T,

    pub(crate) original_data: Option<Vec<u8>>,
}

impl<T> BytesCbor<T> {
    /// Try to create a [`BytesCbor`] from a CBOR [`Value`].
    ///
    /// If the [`Value`] isn't valid, an error message is returned.
    pub fn try_from_cbor(value: &Value) -> Result<Self, String>
    where
        T: serde::de::DeserializeOwned,
    {
        let tagged_value @ Value::Tag(MDOC_BYTES_CBOR_TAG, ref value) = value else {
            return Err(format!(
                "`bstr .cbor` MUST be tagged with `{}`",
                MDOC_BYTES_CBOR_TAG
            ));
        };

        let bytes = value
            .as_bytes()
            .ok_or_else(|| "`bstr .cbor` MUST be `Bytes`".to_owned())?;

        let inner = from_reader(bytes.as_slice()).map_err(|err| err.to_string())?;

        let mut original_data = Vec::new();
        // we can serialize Value again because it preserves the ordering
        into_writer(tagged_value, &mut original_data).map_err(|err| err.to_string())?;

        Ok(Self {
            inner,
            original_data: Some(original_data),
        })
    }

    /// Convert the [`BytesCbor`] into a CBOR [`Value`].
    ///
    /// An error is returned if we fail to write out the bytes, which generally shouldn't happen.
    pub fn try_into_cbor(&self) -> Result<Value, ciborium::ser::Error<std::io::Error>>
    where
        T: Serialize,
    {
        let bytes = match self.original_data {
            Some(ref bytes) => return Ok(from_reader(bytes.as_slice()).unwrap()),
            None => {
                let mut bytes = vec![];
                into_writer(&self.inner, &mut bytes)?;
                bytes
            }
        };

        let bytes = Value::Bytes(bytes);

        let tag = Value::Tag(MDOC_BYTES_CBOR_TAG, Box::new(bytes));

        Ok(tag)
    }
}

impl<T> From<T> for BytesCbor<T> {
    fn from(value: T) -> Self {
        Self {
            inner: value,
            original_data: None,
        }
    }
}

impl<T> Serialize for BytesCbor<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = self.try_into_cbor().map_err(serde::ser::Error::custom)?;

        value.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for BytesCbor<T>
where
    T: serde::de::DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;

        Self::try_from_cbor(&value).map_err(serde::de::Error::custom)
    }
}

/// A `tdate` _CBOR_ type, as defined in the section `7.2.1` of the [ISO/IEC 18013-5:2021][1].
///
/// The following requirements apply to the representation of [`DateTime`]:
/// - fraction of seconds is not used;
/// - no local offset from UTC is used, as indicated by setting the `time-offset` defined in
///   [RFC 3339][2] to `"Z"`.
///
/// [1]: <https://www.iso.org/standard/69084.html>
/// [2]: <https://datatracker.ietf.org/doc/html/rfc3339>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(into = "Value", try_from = "Value")]
pub struct DateTime(chrono::DateTime<Utc>);

impl FromStr for DateTime {
    type Err = bherror::Error<MdocError>;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let date_time = chrono::DateTime::parse_from_rfc3339(value)
            .foreign_err(|| MdocError::InvalidDateTime)
            .ctx(|| format!("{value} not a valid Date Time string"))?;

        if date_time.offset().utc_minus_local() != 0 {
            return Err(bherror::Error::root(MdocError::InvalidDateTime)
                .ctx("Date Time is not in UTC (offset must be Z)"));
        }

        let date_time = date_time.with_timezone(&Utc);

        DateTime::try_from(date_time)
    }
}

impl TryFrom<u64> for DateTime {
    type Error = bherror::Error<MdocError>;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let value_i64 = value
            .try_into()
            .foreign_err(|| MdocError::InvalidDateTime)
            .ctx(|| format!("{value} seconds do not fit into i64"))?;

        let date_time = chrono::DateTime::from_timestamp(value_i64, 0).ok_or_else(|| {
            bherror::Error::root(MdocError::InvalidDateTime)
                .ctx(format!("{value} seconds out of range"))
        })?;

        DateTime::try_from(date_time)
    }
}

impl From<DateTime> for Value {
    fn from(date_time: DateTime) -> Self {
        let date_time = date_time
            .0
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        Self::Tag(MDOC_TDATE_CBOR_TAG, Box::new(Self::Text(date_time)))
    }
}

impl TryFrom<Value> for DateTime {
    type Error = bherror::Error<MdocError>;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let Value::Tag(MDOC_TDATE_CBOR_TAG, value) = value else {
            return Err(
                bherror::Error::root(MdocError::InvalidDateTime).ctx(format!(
                    "`tdate` MUST be tagged with `{}`",
                    MDOC_TDATE_CBOR_TAG
                )),
            );
        };

        let value = value.as_text().ok_or_else(|| {
            bherror::Error::root(MdocError::InvalidDateTime).ctx("`tdate` MUST be `String`")
        })?;

        value.parse::<DateTime>()
    }
}

impl TryFrom<chrono::DateTime<Utc>> for DateTime {
    type Error = bherror::Error<MdocError>;

    fn try_from(value: chrono::DateTime<Utc>) -> Result<Self, Self::Error> {
        // ISO/IEC 18013-5:2021: "fraction of seconds shall not be used"
        if value.nanosecond() != 0 {
            return Err(bherror::Error::root(MdocError::InvalidDateTime)
                .ctx("Date Time should not use fraction of seconds"));
        }

        Ok(Self(value))
    }
}

impl From<DateTime> for chrono::DateTime<Utc> {
    fn from(date_time: DateTime) -> Self {
        date_time.0
    }
}

/// A `full-date` as defined in the section `7.2.1` of the [ISO/IEC 18013-5:2021][1].
///
/// It is assigned a _CBOR_ tag value of `1004`.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(into = "Value", try_from = "Value")]
pub struct FullDate(chrono::NaiveDate);

impl FromStr for FullDate {
    type Err = chrono::ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")?))
    }
}

impl From<FullDate> for Value {
    fn from(full_date: FullDate) -> Self {
        let text = full_date.0.format("%Y-%m-%d").to_string();

        let text = Self::Text(text);

        Self::Tag(MDOC_FULL_DATE_CBOR_TAG, Box::new(text))
    }
}

impl TryFrom<Value> for FullDate {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let Value::Tag(MDOC_FULL_DATE_CBOR_TAG, value) = value else {
            return Err(format!(
                "`full-date` MUST be tagged with `{}`",
                MDOC_FULL_DATE_CBOR_TAG
            ));
        };

        value
            .as_text()
            .ok_or_else(|| "`full-date` MUST be `String`".to_owned())?
            .parse()
            .map_err(|err: chrono::ParseError| err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ciborium::{from_reader, into_writer};

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct Vehicle {
        vehicle_category_code: String,
        issue_date: FullDate,
        expiry_date: FullDate,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Vehicles {
        vehicles: Vec<Vehicle>,
    }

    /// Example taken from the `Annex D.2.1` of the [ISO/IEC 18013-5:2021][1].
    ///
    /// [1]: <https://www.iso.org/standard/69084.html>
    #[test]
    fn test_cbor() {
        const EXPECTED_CBOR: &str = "\
82a37576656869636c655f63617465676f72795f636f646561416a69737375655f64617465d903ec6a32303138\
2d30382d30396b6578706972795f64617465d903ec6a323032342d31302d3230a37576656869636c655f636174\
65676f72795f636f646561426a69737375655f64617465d903ec6a323031372d30322d32336b6578706972795f\
64617465d903ec6a323032342d31302d3230";

        let model = Vehicles {
            vehicles: vec![
                Vehicle {
                    vehicle_category_code: "A".to_owned(),
                    issue_date: "2018-08-09".parse().unwrap(),
                    expiry_date: "2024-10-20".parse().unwrap(),
                },
                Vehicle {
                    vehicle_category_code: "B".to_owned(),
                    issue_date: "2017-02-23".parse().unwrap(),
                    expiry_date: "2024-10-20".parse().unwrap(),
                },
            ],
        };

        let mut encoded = Vec::new();

        into_writer(&model, &mut encoded).unwrap();

        let encoded_hex = hex::encode(&encoded);

        assert_eq!(EXPECTED_CBOR, encoded_hex);

        let decoded: Vehicles = from_reader(encoded.as_slice()).unwrap();

        assert_eq!(model, decoded);
    }

    #[test]
    fn test_datetime_success() {
        const EXPECTED_CBOR: &str = "c074323032302d31302d30315431333a33303a30325a";

        let date_time: DateTime = "2020-10-01T13:30:02Z".parse().unwrap();

        let mut encoded = Vec::new();
        into_writer(&date_time, &mut encoded).unwrap();

        let encoded_hex = hex::encode(&encoded);

        assert_eq!(EXPECTED_CBOR, encoded_hex);

        let decoded: DateTime = from_reader(encoded.as_slice()).unwrap();

        assert_eq!(date_time, decoded);
    }

    #[test]
    fn test_datetime_sub_secs_fails() {
        // 50 seconds success
        let dt = "1985-04-12T23:20:50Z";

        let _date_time: DateTime = dt.parse().unwrap();

        let _date_time: DateTime =
            Value::Tag(MDOC_TDATE_CBOR_TAG, Box::new(Value::Text(dt.to_owned())))
                .try_into()
                .unwrap();

        // 50.52 seconds should fail
        let dt = "1985-04-12T23:20:50.52Z";

        let err = dt.parse::<DateTime>().unwrap_err();
        assert_matches!(err.error, MdocError::InvalidDateTime);

        let err = DateTime::try_from(Value::Tag(
            MDOC_TDATE_CBOR_TAG,
            Box::new(Value::Text(dt.to_owned())),
        ))
        .unwrap_err();
        assert_matches!(err.error, MdocError::InvalidDateTime);
    }

    #[test]
    fn test_datetime_non_utc_fails() {
        // UTC (Z) success
        let dt = "1996-12-19T16:39:57Z";

        let _date_time: DateTime = dt.parse().unwrap();

        let _date_time: DateTime =
            Value::Tag(MDOC_TDATE_CBOR_TAG, Box::new(Value::Text(dt.to_owned())))
                .try_into()
                .unwrap();

        // -08:00 from UTC (Pacific Standard Time) should fail
        let dt = "1996-12-19T16:39:57-08:00";

        let err = dt.parse::<DateTime>().unwrap_err();
        assert_matches!(err.error, MdocError::InvalidDateTime);

        let err = DateTime::try_from(Value::Tag(
            MDOC_TDATE_CBOR_TAG,
            Box::new(Value::Text(dt.to_owned())),
        ))
        .unwrap_err();
        assert_matches!(err.error, MdocError::InvalidDateTime);
    }

    #[test]
    fn test_cbor_tdate_untagged_fails() {
        const THIRD_PARTY_TDATE_CBOR: &str = "74323032302d31302d30315431333a33303a30325a"; // untagged 2020-10-01T13:30:02Z

        let data = hex::decode(THIRD_PARTY_TDATE_CBOR).unwrap();

        let err = from_reader::<DateTime, _>(data.as_slice()).unwrap_err();

        assert_matches!(err, ciborium::de::Error::Semantic(None, m) if m == "Invalid value for Date Time");
    }

    #[test]
    fn test_value_tdate_untagged_fails() {
        let data = ciborium::Value::Text("2020-10-01T13:30:02Z".to_owned());

        let err = DateTime::try_from(data).unwrap_err();

        assert_matches!(err.error, MdocError::InvalidDateTime);
    }
}
