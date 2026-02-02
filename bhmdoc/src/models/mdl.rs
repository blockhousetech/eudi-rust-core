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

//! This module contains types and functions for handling `mDL` (mobile driving license) documents.

use std::collections::HashMap;

use ciborium::Value;
use serde::{Deserialize, Serialize};

use super::{
    data_retrieval::common::{DataElementIdentifier, DataElementValue},
    Bytes, DateTime, FullDate,
};

/// The document type for an _mDL_ document.
///
/// The value is currently specified in the section `7.1` of the
/// [ISO/IEC 18013-5:2021][1].
///
/// [1]: <https://www.iso.org/standard/69084.html>
pub(crate) const MDL_DOCUMENT_TYPE: &str = "org.iso.18013.5.1.mDL";

/// The namespace for _mDL_ data.
///
/// The value is currently specified in the section `7.1` of the
/// [ISO/IEC 18013-5:2021][1].
///
/// [1]: <https://www.iso.org/standard/69084.html>
pub(crate) const MDL_NAMESPACE: &str = "org.iso.18013.5.1";

/// This is either a [`FullDate`] or a [`DateTime`] value.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DateTimeOrFull {
    /// `full-date` as defined in the section `7.2.1` of the ISO/IEC 18013-5:2021.
    FullDate(FullDate),
    /// `tdate` _CBOR_ type, as defined in the section `7.2.1` of the ISO/IEC 18013-5:2021.
    DateTime(DateTime),
}

impl From<DateTime> for DateTimeOrFull {
    fn from(date_time: DateTime) -> Self {
        Self::DateTime(date_time)
    }
}

impl From<FullDate> for DateTimeOrFull {
    fn from(full_date: FullDate) -> Self {
        Self::FullDate(full_date)
    }
}

impl From<DateTimeOrFull> for Value {
    fn from(date: DateTimeOrFull) -> Self {
        match date {
            DateTimeOrFull::DateTime(date_time) => date_time.into(),
            DateTimeOrFull::FullDate(full_date) => full_date.into(),
        }
    }
}

/// Represents a `mDL` (mobile driving license) document.
#[derive(Debug, Serialize, Deserialize)]
pub struct MDL {
    /// Mandatory claims of a `mDL` document.
    #[serde(flatten)]
    pub mandatory: MDLMandatory,
    /// Optional claims of a `mDL` document.
    #[serde(flatten)]
    pub optional: MDLOptional,
}

impl MDL {
    /// Construct a new `mDL` document with given mandatory claims.
    pub fn new(mandatory: MDLMandatory) -> Self {
        Self {
            mandatory,
            optional: MDLOptional::default(),
        }
    }
}

impl From<MDL> for HashMap<DataElementIdentifier, DataElementValue> {
    fn from(value: MDL) -> Self {
        let mut mandatory_map = Self::from(value.mandatory);
        let optional_map = Self::from(value.optional);

        mandatory_map.extend(optional_map);

        mandatory_map
    }
}

macro_rules! with_into_map {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident {
            $($(#[$fattr:meta])* $field_vis:vis $field_name:ident: Option<$field_type:ty>,)*
        }
    ) => {
        $(#[$attr])*
        $vis struct $name {
            $($(#[$fattr])* $field_vis $field_name: Option<$field_type>,)*
        }

        impl From<$name> for HashMap<DataElementIdentifier, DataElementValue> {
            fn from(value: $name) -> Self {
                let mut map = HashMap::new();

                $(
                    if let Some(v) = value.$field_name {
                        map.insert(stringify!($field_name).into(), v.into());
                    }
                )*

                map
            }
        }
    };

    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident {
            $($(#[$fattr:meta])* $field_vis:vis $field_name:ident: $field_type:ty,)*
        }
    ) => {
        $(#[$attr])*
        $vis struct $name {
            $($(#[$fattr])* $field_vis $field_name: $field_type,)*
        }

        impl From<$name> for HashMap<DataElementIdentifier, DataElementValue> {
            fn from(value: $name) -> Self {
                let mut map = HashMap::new();

                $(
                    map.insert(stringify!($field_name).into(), value.$field_name.into());
                )*

                map
            }
        }
    };
}

with_into_map! {
    /// Mandatory claims of a [`MDL`] document as defined in Table 5 of ISO/IEC 18013-5:2021
    /// standard.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct MDLMandatory {
        /// Last name, surname, or primary identifier, of the `mDL` holder.
        pub family_name: String,
        /// First name(s), other name(s), or secondary identifier, of the `mDL` holder.
        pub given_name: String,
        /// [`FullDate`] on which the `mDL` holder was born.
        ///
        /// If unknown, approximate date of birth.
        pub birth_date: FullDate,
        /// Date when `mDL` was issued.
        pub issue_date: DateTimeOrFull,
        /// Date when `mDL` expires.
        pub expiry_date: DateTimeOrFull,
        /// Alpha-2 country code, as defined in ISO3166-1, of the issuing authority’s country or
        /// territory.
        pub issuing_country: String,
        /// Issuing authority name.
        pub issuing_authority: String,
        /// The number assigned or calculated by the issuing authority.
        pub document_number: String,
        /// Portrait of `mDL` holder.
        pub portrait: Bytes,
        // TODO(issues/25): section 7.2.4 of ISO
        /// Categories of vehicles, restrictions and conditions.
        pub driving_privileges: u8,
        /// Distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F.
        pub un_distinguishing_sign: String,
    }
}

with_into_map! {
    /// Optional claims of a [`MDL`] document as defined in Table 5 of ISO/IEC 18013-5:2021
    /// standard.
    #[derive(Debug, Default, Serialize, Deserialize)]
    pub struct MDLOptional {
        /// An audit control number assigned by the issuing authority.
        pub administrative_number: Option<String>,
        /// `mDL` holder’s sex using values as defined inISO/IEC 5218.
        pub sex: Option<u64>,
        /// `mDL` holder’s height in centimeters.
        pub height: Option<u64>,
        /// `mDL` holder’s weight in kilograms.
        pub weight: Option<u64>,
        /// `mDL` holder’s eye colour.
        pub eye_colour: Option<String>,
        /// `mDL` holder's hair colour.
        pub hair_colour: Option<String>,
        /// `mDL` holder's place of birth.
        pub birth_place: Option<String>,
        /// `mDL` holder's permanent place of residence.
        pub resident_address: Option<String>,
        /// Date when the `mDL` holder's portrait was taken.
        pub portrait_capture_date: Option<DateTime>,
        /// `mDL` holder's age.
        pub age_in_years: Option<u64>,
        /// `mDL` holder's year of birth.
        pub age_birth_year: Option<u64>,
        // TODO(issues/26): `age_over_NN`, section 7.2.5 of ISO, at most 2 NN values, maybe should
        // not be present here but only in presentation, IDK
        /// Country subdivision code of the jurisdiction that issued the `mDL` as defined in ISO
        /// 3166-2:2020, Clause 8.
        pub issuing_jurisdiction: Option<String>,
        /// Nationality of the `mDL` holder as a two letter country code (alpha-2 code) defined in
        /// ISO 3166-1.
        pub nationality: Option<String>,
        /// The city where the `mDL` holder lives.
        pub resident_city: Option<String>,
        /// The state/province/district where the `mDL` holder lives.
        pub resident_state: Option<String>,
        /// `mDL` holder's postal code.
        pub resident_postal_code: Option<String>,
        /// The country where the `mDL` holder lives as a two letter country code (alpha-2 code)
        /// defined in ISO 3166-1.
        pub resident_country: Option<String>,
        // TODO(issues/27): `biometric_template_xx`, section 7.2.6 of ISO
        /// The family name of the `mDL` holder using full UTF-8 character set.
        pub family_name_national_character: Option<String>,
        /// The given name of the `mDL` holder using full UTF-8 character set.
        pub given_name_national_character: Option<String>,
        /// Image of the signature or usual mark of the `mDL` holder.
        pub signature_usual_mark: Option<Bytes>,
    }
}
