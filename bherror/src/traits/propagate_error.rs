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

/// Trait for propagating received errors within our [`crate::Error`] system.
///
/// This trait is implemented for the [`crate::Result`] type, to provide functionality for
/// converting recieved errors to the return-type errors, by automatically capturing and saving the
/// error source.
///
/// This should always be used when propagating from the errors that are already in our system,
/// i.e. the [`crate::Result`] type.
///
/// To track the source and propagate errors that aren't part of our [`crate::Error`] system, use
/// the [`ForeignError`][crate::traits::ForeignError] trait.
pub trait PropagateError<T, S, E>
where
    S: crate::BhError,
    E: crate::BhError,
{
    /// Maps a `Result<T, Error<S>>` to `Result<T, Error<E>>`.
    ///
    /// The [Ok] variant is left untouched.
    ///
    /// An error `E` is wrapped inside a [crate::Error], with an [Err] value as its source.
    fn with_err<F>(self, f: F) -> crate::Result<T, E>
    where
        F: FnOnce() -> E;

    /// Maps a `Result<T, Error<S>>` to `Result<T, Error<E>>`.
    ///
    /// The [Ok] value is left untouched.
    ///
    /// An error is created by applying a function `F` to the type `S` from the contained [Err]
    /// variant.
    ///
    /// Use this method to return a different error type `E` by matching on the received error
    /// value `S`.
    fn match_err<F>(self, f: F) -> crate::Result<T, E>
    where
        F: FnOnce(&S) -> E;
}

impl<T, S, E> PropagateError<T, S, E> for crate::Result<T, S>
where
    S: crate::BhError,
    E: crate::BhError,
{
    fn with_err<F>(self, f: F) -> crate::Result<T, E>
    where
        F: FnOnce() -> E,
    {
        self.map_err(|source| crate::Error::from_known_source(f(), source))
    }

    fn match_err<F>(self, f: F) -> crate::Result<T, E>
    where
        F: FnOnce(&S) -> E,
    {
        self.map_err(|source| crate::Error::from_known_source(f(&source.error), source))
    }
}

#[cfg(test)]
mod tests {
    use super::PropagateError as _;

    #[derive(Debug, PartialEq)]
    enum SourceError {
        SystemError,
        UsageError,
    }

    impl std::fmt::Display for SourceError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::SystemError => write!(f, "SystemError"),
                Self::UsageError => write!(f, "UsageError"),
            }
        }
    }

    impl crate::BhError for SourceError {}

    #[derive(Debug, PartialEq)]
    enum KnownError {
        SystemError,
        UsageError,
    }

    impl std::fmt::Display for KnownError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::SystemError => write!(f, "SystemError"),
                Self::UsageError => write!(f, "UsageError"),
            }
        }
    }

    impl crate::BhError for KnownError {}

    fn non_failing_function() -> crate::Result<(), SourceError> {
        Ok(())
    }

    fn failing_function(error: SourceError) -> crate::Result<(), SourceError> {
        Err(crate::Error::root(error))
    }

    #[test]
    fn test_with_err() {
        assert!(non_failing_function()
            .with_err(|| KnownError::UsageError)
            .is_ok());

        let error = failing_function(SourceError::UsageError)
            .with_err(|| KnownError::UsageError)
            .unwrap_err();

        assert_eq!(error.error, KnownError::UsageError);
        assert!(matches!(
            error.source,
            Some(crate::ErrorSource::KnownError(_))
        ));

        let error = failing_function(SourceError::SystemError)
            .with_err(|| KnownError::SystemError)
            .unwrap_err();

        assert_eq!(error.error, KnownError::SystemError);
        assert!(matches!(
            error.source,
            Some(crate::ErrorSource::KnownError(_))
        ));
    }

    #[test]
    fn test_match_err() {
        assert!(non_failing_function()
            .match_err(|error| match error {
                SourceError::SystemError => KnownError::SystemError,
                SourceError::UsageError => KnownError::UsageError,
            })
            .is_ok());

        let error = failing_function(SourceError::UsageError)
            .match_err(|error| match error {
                SourceError::SystemError => KnownError::SystemError,
                SourceError::UsageError => KnownError::UsageError,
            })
            .unwrap_err();

        assert_eq!(error.error, KnownError::UsageError);
        assert!(matches!(
            error.source,
            Some(crate::ErrorSource::KnownError(_))
        ));

        let error = failing_function(SourceError::SystemError)
            .match_err(|error| match error {
                SourceError::SystemError => KnownError::SystemError,
                SourceError::UsageError => KnownError::UsageError,
            })
            .unwrap_err();

        assert_eq!(error.error, KnownError::SystemError);
        assert!(matches!(
            error.source,
            Some(crate::ErrorSource::KnownError(_))
        ));
    }
}
