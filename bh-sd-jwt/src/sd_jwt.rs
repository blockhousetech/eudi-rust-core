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

//! Implementation of basic `SD-JWT` and `SD-JWT+KB` presentation construction and parsing.

use bherror::Error;

use crate::error::FormatError;

pub(crate) const SD_JWT_DELIMITER: &str = "~";

/// A struct representing an `SD-JWT`.
///
/// An `SD-JWT` is composed of the following:
/// - an Issuer-signed JWT,
/// - zero or more Disclosures.
///
/// Instance of an `SD-JWT` can be parsed from a `&str` containing an `SD-JWT`
/// in the JWS Compact Serialization format.
///
/// Instance of an `SD-JWT` can be turned into `SD-JWT+KB` by adding a Key Binding
/// JWT (KB-JWT) to the instance.
#[derive(Debug)]
pub(crate) struct SdJwt {
    pub(crate) jwt: String,
    pub(crate) disclosures: Vec<String>,
}

/// A struct representing an `SD-JWT+KB`.
///
/// An `SD-JWT+KB` is composed of the following:
/// - an SD-JWT (i.e., an Issuer-signed JWT and zero or more Disclosures), and
/// - Key Binding JWT.
///
/// Instance of an `SD-JWT+KB` can be parsed from a `&str` containing an `SD-JWT+KB`
/// in the Compact Serialization format.
#[derive(Debug)]
pub struct SdJwtKB {
    pub(crate) sd_jwt: SdJwt,
    pub(crate) key_binding_jwt: String,
}

impl SdJwt {
    pub(crate) fn new(jwt: String, disclosures: Vec<String>) -> Self {
        Self { jwt, disclosures }
    }
}

impl SdJwtKB {
    /// Create a new instance of an [`SdJwtKB`], from the provided parts.
    /// The provided key binding string should not be a empty.
    ///
    /// # Note
    /// The function only check if key binding is not empty. No other checks
    /// are carried out on any of the provided parts, e.g. there is not a
    /// check on the `jwt` signature.
    pub(crate) fn new(
        sd_jwt: SdJwt,
        key_binding_jwt: String,
    ) -> Result<Self, bherror::Error<FormatError>> {
        if key_binding_jwt.is_empty() {
            return Err(Error::root(FormatError::InvalidSdJwtFormat));
        }
        Ok(Self {
            sd_jwt,
            key_binding_jwt,
        })
    }
}

impl std::str::FromStr for SdJwt {
    type Err = bherror::Error<FormatError>;

    /// Create a new instance of an [`SdJwt`], from the provided string in the
    /// JWS Compact Serialization format.
    ///
    /// As specified in the [draft v13], the compact format is composed of
    /// the Issuer-signed `JWT`, a `~` (tilde character), zero or more
    /// Disclosures each followed by a `~`. The provided string is expected
    /// to end with `~` character.
    ///
    /// # Note
    /// No checks are carried out on any of the provided parts, e.g. there is
    /// not a check on the `jwt` signature.
    ///
    /// # Examples
    ///
    /// An `SD-JWT` without Disclosures:\
    /// `<Issuer-signed JWT>~`.
    ///
    /// An `SD-JWT` with Disclosures:\
    /// `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure N>~`.
    ///
    /// [draft v13]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#name-sd-jwt-and-sd-jwtkb-data-fo
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#section-4-8
        if !value.ends_with('~') {
            return Err(Error::root(FormatError::InvalidSdJwtFormat));
        }
        let sd_jwt_parts: Vec<&str> = value.split(SD_JWT_DELIMITER).collect();

        // NOTE: removes the last element because it is a empty string which split
        //       function collects after the final SD_JWT_DELIMITER '~'
        debug_assert!(sd_jwt_parts.last().unwrap().is_empty());
        sd_jwt_from_parts(&sd_jwt_parts[0..sd_jwt_parts.len() - 1])
    }
}

impl std::str::FromStr for SdJwtKB {
    type Err = bherror::Error<FormatError>;

    /// Create a new instance of an [`SdJwtKB`], from the provided string in the
    /// JWS Compact Serialization format.
    ///
    /// As specified in the [draft v13], the compact format is composed of
    /// the Issuer-signed `JWT`, a `~` (tilde character), zero or more
    /// Disclosures each followed by a `~`, and lastly a Key Binding JWT (`KB-JWT`).
    ///
    /// # Note
    /// No checks are carried out on any of the provided parts, e.g. there is
    /// not a check on the `jwt` signature.
    ///
    /// # Examples
    ///
    /// An `SD-JWT+KB` without Disclosures:\
    /// `<Issuer-signed JWT>~<KB-JWT>`.
    ///
    /// An `SD-JWT+KB` with Disclosures:\
    /// `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure N>~<KB-JWT>`.
    ///
    /// [draft v13]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#name-sd-jwt-and-sd-jwtkb-data-fo
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let sd_jwt_parts: Vec<&str> = value.split(SD_JWT_DELIMITER).collect();

        let parts_len = sd_jwt_parts.len();
        let sd_jwt = sd_jwt_from_parts(&sd_jwt_parts[0..parts_len - 1])?;
        let key_binding_jwt = sd_jwt_parts[parts_len - 1];

        Self::new(sd_jwt, key_binding_jwt.to_owned())
    }
}

impl std::fmt::Display for SdJwt {
    /// Serialize the `SD-JWT` in the JWS Compact Serialization format.
    ///
    /// As specified in the [draft v13], the JWS Compact Serialization format is
    /// composed of the Issuer-signed `JWT`, a `~` (tilde character) and zero or
    /// more Disclosures each followed by a `~`. The last separating tilde
    /// character must not be omitted.
    ///
    /// # Examples
    ///
    /// An `SD-JWT` without Disclosures:\
    /// `<Issuer-signed JWT>~`.
    ///
    /// An `SD-JWT` with Disclosures:\
    /// `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure N>~`.
    ///
    /// [draft v13]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#name-sd-jwt-and-sd-jwtkb-data-fo
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.jwt, SD_JWT_DELIMITER)?;

        for disclosure in &self.disclosures {
            write!(f, "{}{}", disclosure, SD_JWT_DELIMITER)?;
        }

        Ok(())
    }
}

impl std::fmt::Display for SdJwtKB {
    /// Serialize the `SD-JWT+KB` in the JWS Compact serialization format.
    ///
    /// As specified in the [draft v13], the compact format is composed of the
    /// Issuer-signed `JWT`, a `~` (tilde character), zero or more Disclosures
    /// each followed by a `~`, and lastly a Key Binding JWT (`KB-JWT`).
    ///
    /// # Examples
    ///
    /// An `SD-JWT+KB` without Disclosures:\
    /// `<Issuer-signed JWT>~<KB-JWT>`.
    ///
    /// An `SD-JWT+KB` with Disclosures:\
    /// `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure N>~<KB-JWT>`.
    ///
    /// [draft v13]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-13#name-sd-jwt-and-sd-jwtkb-data-fo
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.sd_jwt, self.key_binding_jwt)?;
        Ok(())
    }
}

fn sd_jwt_from_parts(sd_jwt_parts: &[&str]) -> Result<SdJwt, bherror::Error<FormatError>> {
    let sd_jwt_parts = sd_jwt_parts.split_first();
    let Some((jwt, disclosures)) = sd_jwt_parts else {
        return Err(Error::root(FormatError::InvalidSdJwtFormat));
    };

    let disclosures: Vec<String> = disclosures.iter().map(|&s| s.to_owned()).collect();

    Ok(SdJwt::new(jwt.to_string(), disclosures))
}

#[cfg(test)]
mod test {
    use super::*;

    const JWT: &str = "\
eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBb\
IkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZ\
akg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBL\
dVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1\
SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tB\
TmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2\
Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFr\
b2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpn\
bGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUu\
Y29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjog\
InVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15\
VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1\
ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjog\
InNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0y\
NTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VH\
ZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlG\
MkhaUSJ9fX0.7oEYwv1H4rBa54xAhDH19DEIy-RRSTdwyJvhbjOKVFyQeM0-gcgpwCq-\
yFCbWj9THEjD9M4yYkAeaWXfuvBS-Q";
    const DISCLOSURE_1: &str = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd";
    const DISCLOSURE_2: &str = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0";
    const KEY_BINDING_JWT: &str = "\
eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY\
3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI\
6IDE3MDIzMTYwMTUsICJzZF9oYXNoIjogIm5ZY09YeVA0M3Y5c3pLcnluX2tfNEdrUnJ\
fajNTVEhoTlNTLWkxRHVhdW8ifQ.12Qymun2geGbkYOwiV-DUVfS-zBBKqNe83yNbxM4\
5J93bno-oM7mph3L1-rPa4lFKQ04wB-T9rU3uAZnBAan5g";

    #[test]
    fn test_from_str_without_disclosures_without_kb_jwt() {
        let sd_jwt_presentation = format!("{JWT}~");

        let sd_jwt: SdJwt = sd_jwt_presentation.parse().unwrap();

        assert!(sd_jwt.disclosures.is_empty());
        assert_eq!(sd_jwt.jwt, JWT);

        // should not parse serialized SdJwt as a SdJwtKB
        let error: Result<SdJwtKB, Error<FormatError>> = sd_jwt_presentation.parse();
        assert_eq!(error.unwrap_err().error, FormatError::InvalidSdJwtFormat);
    }

    #[test]
    fn test_from_str_without_disclosures_with_kb_jwt() {
        let sd_jwt_kb_presentation = format!("{JWT}~{KEY_BINDING_JWT}");

        let sd_jwt_kb: SdJwtKB = sd_jwt_kb_presentation.parse().unwrap();

        assert!(sd_jwt_kb.sd_jwt.disclosures.is_empty());

        assert_eq!(sd_jwt_kb.sd_jwt.jwt, JWT);
        assert_eq!(sd_jwt_kb.key_binding_jwt, KEY_BINDING_JWT);

        // should not parse serialized SdJwtKB as a SdJwt
        let error: Result<SdJwt, Error<FormatError>> = sd_jwt_kb_presentation.parse();
        assert_eq!(error.unwrap_err().error, FormatError::InvalidSdJwtFormat);
    }

    #[test]
    fn test_from_str_with_disclosures_without_kb_jwt() {
        let sd_jwt_presentation = format!("{JWT}~{DISCLOSURE_1}~{DISCLOSURE_2}~");

        let sd_jwt: SdJwt = sd_jwt_presentation.parse().unwrap();

        assert_eq!(sd_jwt.disclosures.len(), 2);

        assert_eq!(sd_jwt.jwt, JWT);
        assert_eq!(sd_jwt.disclosures, &[DISCLOSURE_1, DISCLOSURE_2]);

        // should not parse serialized SdJwt as a SdJwtKB
        let error: Result<SdJwtKB, Error<FormatError>> = sd_jwt_presentation.parse();
        assert_eq!(error.unwrap_err().error, FormatError::InvalidSdJwtFormat);
    }

    #[test]
    fn test_from_str_with_disclosures_with_kb_jwt() {
        let sd_jwt_kb_presentation =
            format!("{JWT}~{DISCLOSURE_1}~{DISCLOSURE_2}~{KEY_BINDING_JWT}");

        let sd_jwt_kb: SdJwtKB = sd_jwt_kb_presentation.parse().unwrap();

        assert_eq!(sd_jwt_kb.sd_jwt.disclosures.len(), 2);

        assert_eq!(sd_jwt_kb.sd_jwt.jwt, JWT);
        assert_eq!(sd_jwt_kb.sd_jwt.disclosures, &[DISCLOSURE_1, DISCLOSURE_2]);
        assert_eq!(sd_jwt_kb.key_binding_jwt, KEY_BINDING_JWT);

        // should not parse serialized SdJwtKB as a SdJwt
        let error: Result<SdJwt, Error<FormatError>> = sd_jwt_kb_presentation.parse();
        assert_eq!(error.unwrap_err().error, FormatError::InvalidSdJwtFormat);
    }

    #[test]
    fn test_from_str_invalid_format() {
        let result = JWT.parse::<SdJwtKB>();
        assert!(result.is_err());
        let result = JWT.parse::<SdJwt>();
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_sd_jwt_kb_empty_key_binding() {
        let sd_jwt_kb_with_empty_key_binding_presentation =
            format!("{JWT}~{DISCLOSURE_1}~{DISCLOSURE_2}~");

        let error: Result<SdJwtKB, Error<FormatError>> =
            sd_jwt_kb_with_empty_key_binding_presentation.parse();

        assert_eq!(error.unwrap_err().error, FormatError::InvalidSdJwtFormat);
    }

    #[test]
    fn test_from_str_empty() {
        let result = "".parse::<SdJwtKB>();
        assert!(result.is_err());
        let result = "".parse::<SdJwt>();
        assert!(result.is_err());
    }

    #[test]
    fn test_display_without_disclosures_without_kb_jwt() {
        let sd_jwt = SdJwt::new(JWT.to_owned(), Vec::new());

        let expected_presentation = format!("{JWT}~");

        assert_eq!(sd_jwt.to_string(), expected_presentation);
    }

    #[test]
    fn test_display_without_disclosures_with_kb_jwt() {
        let sd_jwt = SdJwt {
            jwt: JWT.to_owned(),
            disclosures: Vec::new(),
        };
        let sd_jwt_kb = SdJwtKB::new(sd_jwt, KEY_BINDING_JWT.to_owned());

        let expected_presentation = format!("{JWT}~{KEY_BINDING_JWT}");

        assert_eq!(sd_jwt_kb.unwrap().to_string(), expected_presentation);
    }

    #[test]
    fn test_display_with_disclosures_without_kb_jwt() {
        let sd_jwt = SdJwt::new(
            JWT.to_owned(),
            vec![DISCLOSURE_1.to_owned(), DISCLOSURE_2.to_owned()],
        );

        let expected_presentation = format!("{JWT}~{DISCLOSURE_1}~{DISCLOSURE_2}~");

        assert_eq!(sd_jwt.to_string(), expected_presentation);
    }

    #[test]
    fn test_display_with_disclosures_with_kb_jwt() {
        let sd_jwt = SdJwt {
            jwt: JWT.to_owned(),
            disclosures: vec![DISCLOSURE_1.to_owned(), DISCLOSURE_2.to_owned()],
        };
        let sd_jwt_kb = SdJwtKB::new(sd_jwt, KEY_BINDING_JWT.to_owned());

        let expected_presentation =
            format!("{JWT}~{DISCLOSURE_1}~{DISCLOSURE_2}~{KEY_BINDING_JWT}");

        assert_eq!(sd_jwt_kb.unwrap().to_string(), expected_presentation);
    }
}
