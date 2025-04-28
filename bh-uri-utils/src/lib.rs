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

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! This crate provides utilities for manipulating the path of URIs, enabling the addition of
//! prefixes and suffixes to existing URI paths.
//!
//! The crate ensures robust handling of errors and supports various URI-like types.  This is
//! implemented with [`UriPathExtensions`] trait for the following types:
//!
//! - [`reqwest::Url`]
//! - [`iref::UriBuf`]
//! - `&`[`iref::Uri`]
//!
//! # Example
//!
//! ```rust
//! use bh_uri_utils::UriPathExtensions;
//! use reqwest::Url;
//!
//! let url = Url::parse("https://example.com/path").unwrap();
//! let updated_url = url.add_path_prefix("/prefix").unwrap();
//! assert_eq!(updated_url.as_str(), "https://example.com/prefix/path");
//!
//! let updated_url = updated_url.add_path_suffix("/suffix").unwrap();
//! assert_eq!(updated_url.as_str(), "https://example.com/prefix/path/suffix");
//! ```
//!
//! # Notes
//!
//! The motivation for creating this crate stems from inconsistencies in how various crates handle
//! URI manipulations, as well as certain well-documented but unintuitive behaviors that can lead
//! to bugs.
//!
//! For example, we encountered the following unexpected situations:
//!
//! - `http://localhost:3002/ + /example` resulted in `http://localhost:3002//example`.
//!
//! - `http://localhost:3002/protocol/oid4vci/issuer + /.well-known/openid-credential-issuer`
//!   resulted in `http://localhost:3002/.well-known/openid-credential-issuer`.
//!
//! This crate aims to address and standardize such cases to prevent similar issues in the future.

use bherror::{traits::ForeignError as _, Result};

/// Error type returned by [`UriPathExtensions`] methods.
#[derive(Debug, strum_macros::Display)]
pub enum Error {
    /// Error when we fail to construct the URI.
    #[strum(to_string = "Conversion to UriBuf failed: {0}")]
    ConversionToUri(String),
    /// Error when we've received a URI path that doesn't start with a `/`.
    #[strum(to_string = "Path is not valid: {0}")]
    InvalidPath(String),
    /// Error when we fail to parse the received URI path.
    #[strum(to_string = "Path parsing failed: {0}")]
    PathParsing(String),
}

impl bherror::BhError for Error {}

/// A trait for adding prefixes and suffixes to the path component of a URI.
///
/// This trait provides methods to modify the path of a URI by appending a prefix or a suffix, with
/// strict validation rules for the provided paths.
///
/// # Errors
///
/// The methods return an [`Error`] if the provided prefix or suffix does not meet the validation
/// rules.
pub trait UriPathExtensions {
    /// Resulting type of the URI returned by the methods of this trait.
    type Output;

    /// Adds prefix to the path of the provided URI.
    ///
    /// The function returns an error if the prefix is invalid, empty, ends with the trailing `/`,
    /// does not start with a `/`, or starts with multiple consecutive `/`s.
    fn add_path_prefix(self, path: &str) -> Result<Self::Output, Error>;

    /// Adds suffix to the path of the provided URI.
    ///
    /// The function returns an error if the suffix is invalid, empty, ends with the trailing `/`,
    /// does not start with a `/`, or starts with multiple consecutive `/`s.
    fn add_path_suffix(self, path: &str) -> Result<Self::Output, Error>;
}

impl UriPathExtensions for reqwest::Url {
    type Output = Self;

    fn add_path_prefix(self, path: &str) -> Result<Self::Output, Error> {
        let uri = uri_add_path_prefix(self, path)?;
        reqwest::Url::parse(uri.as_ref()).foreign_err(|| Error::ConversionToUri(uri.to_string()))
    }

    fn add_path_suffix(self, path: &str) -> Result<Self::Output, Error> {
        let uri = uri_add_path_suffix(self, path)?;
        reqwest::Url::parse(uri.as_ref()).foreign_err(|| Error::ConversionToUri(uri.to_string()))
    }
}

impl UriPathExtensions for &iref::Uri {
    type Output = iref::UriBuf;

    fn add_path_prefix(self, path: &str) -> Result<Self::Output, Error> {
        uri_add_path_prefix(self, path)
    }

    fn add_path_suffix(self, path: &str) -> Result<Self::Output, Error> {
        uri_add_path_suffix(self, path)
    }
}

impl UriPathExtensions for iref::UriBuf {
    type Output = iref::UriBuf;

    fn add_path_prefix(self, path: &str) -> Result<Self::Output, Error> {
        uri_add_path_prefix(self, path)
    }

    fn add_path_suffix(self, path: &str) -> Result<Self::Output, Error> {
        uri_add_path_suffix(self, path)
    }
}

fn uri_add_path_suffix<T>(uri: T, path: &str) -> Result<iref::UriBuf, Error>
where
    T: TryIntoUriBuf + ToString,
{
    let (mut uri, path) = convert_uri_and_path(uri, path)?;

    if let Some(last_segment) = uri.path().last() {
        if last_segment.as_str() == "" {
            uri.path_mut().pop();
        }
    }

    if uri.path().is_empty() {
        uri.set_path(&path);
    } else {
        append_segments(uri.path_mut(), path.segments());
    }

    Ok(uri)
}

fn uri_add_path_prefix<T>(uri: T, path: &str) -> Result<iref::UriBuf, Error>
where
    T: TryIntoUriBuf + ToString,
{
    let (mut uri, path) = convert_uri_and_path(uri, path)?;
    let mut path = path.to_owned();

    append_segments(path.as_path_mut(), uri.path().segments());

    uri.set_path(&path);

    Ok(uri)
}

fn append_segments(mut path: iref::uri::PathMut, segments: iref::uri::Segments) {
    for segment in segments {
        path.push(segment);
    }
}

fn convert_uri_and_path<T>(uri: T, path: &str) -> Result<(iref::UriBuf, iref::uri::PathBuf), Error>
where
    T: TryIntoUriBuf + ToString,
{
    if path.is_empty() || !path.starts_with('/') || path.starts_with("//") || path.ends_with('/') {
        return Err(bherror::Error::root(Error::InvalidPath(path.to_owned())));
    }

    let uri_as_string = uri.to_string();

    let uri = uri
        .try_into()
        .foreign_err(|| Error::ConversionToUri(uri_as_string))?;

    // This is `map_err` because `PathBuf::new` returns non std::Error.
    let path = iref::uri::PathBuf::new(path.as_bytes().to_vec())
        .map_err(|_| bherror::Error::root(Error::PathParsing(path.to_owned())))?;

    Ok((uri, path))
}

trait TryIntoUriBuf {
    fn try_into(self) -> Result<iref::UriBuf, self::Error>;
}

impl TryIntoUriBuf for &iref::Uri {
    fn try_into(self) -> Result<iref::UriBuf, self::Error> {
        Ok(self.to_owned())
    }
}

impl TryIntoUriBuf for reqwest::Url {
    fn try_into(self) -> Result<iref::UriBuf, self::Error> {
        let uri = self.to_string().as_bytes().to_vec();

        // This is `map_err` because `UriBuf::new` returns non std::Error.
        let uri = iref::UriBuf::new(uri)
            .map_err(|_| bherror::Error::root(Error::ConversionToUri(self.to_string())))?;
        Ok(uri)
    }
}

impl TryIntoUriBuf for iref::UriBuf {
    fn try_into(self) -> Result<iref::UriBuf, self::Error> {
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_uri_buf(uri: &str) -> iref::UriBuf {
        TryInto::<iref::UriBuf>::try_into(uri.to_owned()).expect("Uri is not valid")
    }

    #[test]
    fn test_uri_add_path_suffix_with_reqwest_url() {
        let uri = reqwest::Url::parse(
            "http://localhost:3002/protocol/oid4vci/issuer/6adf766d-3b29-42d7-8a07-22b32f608a3a",
        )
        .unwrap();

        let new_uri = uri_add_path_suffix(uri, "/.well-known/openid-credential-issuer").unwrap();

        assert_eq!(new_uri, "http://localhost:3002/protocol/oid4vci/issuer/6adf766d-3b29-42d7-8a07-22b32f608a3a/.well-known/openid-credential-issuer");
    }

    #[test]
    fn test_uri_add_path_prefix_with_reqwest_url() {
        let uri = reqwest::Url::parse("http://localhost:3002/protocol/a/b/c").unwrap();

        let new_uri = uri_add_path_prefix(uri, "/d/e/f").unwrap();

        assert_eq!(new_uri, "http://localhost:3002/d/e/f/protocol/a/b/c");
    }

    #[test]
    fn test_uri_add_path_suffix() {
        let uri = to_uri_buf(
            "http://localhost:3002/protocol/oid4vci/issuer/6adf766d-3b29-42d7-8a07-22b32f608a3a",
        );

        let new_uri = uri_add_path_suffix(uri, "/.well-known/openid-credential-issuer").unwrap();

        assert_eq!(new_uri, "http://localhost:3002/protocol/oid4vci/issuer/6adf766d-3b29-42d7-8a07-22b32f608a3a/.well-known/openid-credential-issuer");
    }

    #[test]
    fn test_uri_add_path_suffix_empty_path() {
        let uri = to_uri_buf("http://example.com");

        let new_uri = uri_add_path_suffix(uri, "/a/b/c").unwrap();

        assert_eq!(new_uri, "http://example.com/a/b/c");
    }

    #[test]
    fn test_uri_add_path_suffix_empty_path_trailing_slash() {
        let uri = to_uri_buf("http://example.com/");

        let new_uri = uri_add_path_suffix(uri, "/a").unwrap();

        assert_eq!(new_uri, "http://example.com/a");
    }

    #[test]
    fn test_uri_add_path_suffix_path_trailing_slash() {
        let uri = to_uri_buf("http://example.com/p/");

        let new_uri = uri_add_path_suffix(uri, "/a").unwrap();

        assert_eq!(new_uri, "http://example.com/p/a");
    }

    #[test]
    fn test_uri_add_path_suffix_path_multiple_trailing_slash() {
        let uri = to_uri_buf("http://example.com//////");

        let new_uri = uri_add_path_suffix(uri, "/a").unwrap();

        assert_eq!(new_uri, "http://example.com//////a");
    }

    #[test]
    fn test_uri_add_path_suffix_start_no_slash() {
        let uri = to_uri_buf("http://example.com/p/");

        let err = uri_add_path_suffix(uri, "a").unwrap_err();

        assert!(matches!(err.error, Error::InvalidPath(_)));
    }

    #[test]
    fn test_uri_add_path_suffix_start_multiple_slash() {
        let uri = to_uri_buf("http://example.com/p/");

        let err = uri_add_path_suffix(uri, "//a").unwrap_err();

        assert!(matches!(err.error, Error::InvalidPath(_)));
    }

    #[test]
    fn test_uri_add_path_suffix_empty() {
        let uri = to_uri_buf("http://example.com/p/");

        let err = uri_add_path_suffix(uri, "").unwrap_err();

        assert!(matches!(err.error, Error::InvalidPath(_)));
    }

    #[test]
    fn test_uri_add_path_suffix_end_slash() {
        let uri = to_uri_buf("http://example.com/p/");

        let err = uri_add_path_suffix(uri, "/a/").unwrap_err();

        assert!(matches!(err.error, Error::InvalidPath(_)));
    }

    #[test]
    fn test_uri_add_path_prefix() {
        let uri = to_uri_buf("http://example.com/path");

        let new_uri = uri_add_path_prefix(uri, "/a/b/c").unwrap();

        assert_eq!(new_uri, "http://example.com/a/b/c/path");
    }

    #[test]
    fn test_uri_add_path_prefix_empty_path() {
        let uri = to_uri_buf("http://example.com");

        let new_uri = uri_add_path_prefix(uri, "/a/b/c").unwrap();

        assert_eq!(new_uri, "http://example.com/a/b/c");
    }

    #[test]
    fn test_uri_add_path_prefix_empty_path_trailing_slash() {
        let uri = to_uri_buf("http://example.com/");

        let new_uri = uri_add_path_prefix(uri, "/a").unwrap();

        assert_eq!(new_uri, "http://example.com/a");
    }

    #[test]
    fn test_uri_add_path_prefix_path_multiple_trailing_slash() {
        let uri = to_uri_buf("http://example.com//////");

        let new_uri = uri_add_path_prefix(uri, "/a").unwrap();

        assert_eq!(new_uri, "http://example.com/a//////");
    }

    #[test]
    fn test_uri_add_path_prefix_path_trailing_slash() {
        let uri = to_uri_buf("http://example.com/p/");

        let new_uri = uri_add_path_prefix(uri, "/a").unwrap();

        assert_eq!(new_uri, "http://example.com/a/p/");
    }

    #[test]
    fn test_uri_add_path_prefix_start_no_slash() {
        let uri = to_uri_buf("http://example.com/p/");

        let err = uri_add_path_prefix(uri, "a").unwrap_err();

        assert!(matches!(err.error, Error::InvalidPath(_)));
    }

    #[test]
    fn test_uri_add_path_prefix_start_multiple_slash() {
        let uri = to_uri_buf("http://example.com/p/");

        let err = uri_add_path_prefix(uri, "//a").unwrap_err();

        assert!(matches!(err.error, Error::InvalidPath(_)));
    }

    #[test]
    fn test_uri_add_path_prefix_empty() {
        let uri = to_uri_buf("http://example.com/p/");

        let err = uri_add_path_prefix(uri, "").unwrap_err();

        assert!(matches!(err.error, Error::InvalidPath(_)));
    }

    #[test]
    fn test_uri_add_path_prefix_end_slash() {
        let uri = to_uri_buf("http://example.com/p/");

        let err = uri_add_path_prefix(uri, "/a/").unwrap_err();

        assert!(matches!(err.error, Error::InvalidPath(_)));
    }

    #[test]
    fn test_uri_add_path_prefix_traits_impl() {
        let uri = "http://example.com/p/";
        let expected_uri = "http://example.com/a/p/".to_owned();
        let path = "/a";

        let ref_uri = iref::Uri::new(uri).unwrap();
        let reqwest_url = reqwest::Url::parse(uri).unwrap();
        let uri_buf = TryInto::<iref::UriBuf>::try_into(uri.to_owned()).unwrap();

        assert_eq!(ref_uri.add_path_prefix(path).unwrap(), expected_uri);
        assert_eq!(
            reqwest_url.add_path_prefix(path).unwrap().to_string(),
            expected_uri
        );
        assert_eq!(uri_buf.add_path_prefix(path).unwrap(), expected_uri);
    }

    #[test]
    fn test_uri_add_path_suffix_traits_impl() {
        let uri = "http://example.com/p/";
        let expected_uri = "http://example.com/p/a".to_owned();
        let path = "/a";

        let ref_uri = iref::Uri::new(uri).unwrap();
        let reqwest_url = reqwest::Url::parse(uri).unwrap();
        let uri_buf = TryInto::<iref::UriBuf>::try_into(uri.to_owned()).unwrap();

        assert_eq!(ref_uri.add_path_suffix(path).unwrap(), expected_uri);
        assert_eq!(
            reqwest_url.add_path_suffix(path).unwrap().to_string(),
            expected_uri
        );
        assert_eq!(uri_buf.add_path_suffix(path).unwrap(), expected_uri);
    }
}
