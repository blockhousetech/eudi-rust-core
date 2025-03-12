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

use crate::traits::loggable::Warnable;

/// Trait for converting foreign errors to our [`crate::Error`] types.
///
/// This trait is implemented for the [`std::result::Result`] type, to provide functionality for
/// converting the received error to the [`crate::Error`], by automatically capturing and saving
/// the error source.
///
/// This should only be used when propagating from an error that is outside our system,
/// i.e. foreign.
///
/// Do *not* use this to propagate the errors that are already in our system, i.e. are already
/// [`crate::Error`].  For those, use the [`PropagateError`][crate::traits::PropagateError] trait.
pub trait ForeignError<T, S, E>
where
    S: std::error::Error + Send + Sync + 'static,
    E: crate::BhError,
{
    /// Maps a `Result<T, S>` to `Result<T, crate::Error<E>>`.
    ///
    /// The [Ok] variant is left untouched.
    ///
    /// An error `E` is wrapped inside a [crate::Error], with an [Err] variant value as its source.
    ///
    /// Note that the [Err] value can be any [std::error::Error] type, not only the [crate::Error].
    /// Furthermore, do *not* use this to propagate something that is already `Result<T,
    /// crate::Error<E>>`.  Use [PropagateError][crate::traits::PropagateError] instead.
    fn foreign_err<F>(self, f: F) -> crate::Result<T, E>
    where
        F: FnOnce() -> E;

    /// Maps a `Result<T, S>` to `Result<T, Error<E>>`.
    ///
    /// The [`Ok`] variant is left untouched.
    ///
    /// An error is created by applying a function `F` to the type `S` from the contained [Err]
    /// variant.
    ///
    /// Use this method to return a different error type `E` by matching on the received error
    /// value `S`.
    fn match_foreign_err<F>(self, f: F) -> crate::Result<T, E>
    where
        F: FnOnce(&S) -> E;
}

impl<T, S, E> ForeignError<T, S, E> for std::result::Result<T, S>
where
    S: std::error::Error + Send + Sync + 'static,
    E: crate::BhError,
{
    #[track_caller]
    fn foreign_err<F>(self, f: F) -> crate::Result<T, E>
    where
        F: FnOnce() -> E,
    {
        self.map_err(|source| crate::Error::from_foreign_source(f(), source))
            .log_warn(*std::panic::Location::caller())
    }

    #[track_caller]
    fn match_foreign_err<F>(self, f: F) -> crate::Result<T, E>
    where
        F: FnOnce(&S) -> E,
    {
        self.map_err(|source| crate::Error::from_foreign_source(f(&source), source))
            .log_warn(*std::panic::Location::caller())
    }
}

/// Trait for converting boxed foreign errors to our [`crate::Error`] types.
///
/// This trait is essentially the [`ForeignError`] trait but implemented for
/// `std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>`.
///
/// This should only be used when propagating from an error that is outside our system,
/// i.e. foreign.
///
/// Do *not* use this to propagate the errors that are already in our system, i.e. are already
/// [`crate::Error`].  For those, use the [`PropagateError`][crate::traits::PropagateError] trait.
pub trait ForeignBoxed<T, E>
where
    E: crate::BhError,
{
    /// Maps a `Result<T, Box<dyn std::error::Error + Send + Sync>>>` to `Result<T, Error<E>>`.
    ///
    /// The [Ok] variant is left untouched.
    ///
    /// An error `E` is wrapped inside a [crate::Error], with an [Err] value as its source.
    fn foreign_boxed_err<F>(self, f: F) -> crate::Result<T, E>
    where
        F: FnOnce() -> E;
}

impl<T, E> ForeignBoxed<T, E> for std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>
where
    E: crate::BhError,
{
    #[track_caller]
    fn foreign_boxed_err<F>(self, f: F) -> crate::Result<T, E>
    where
        F: FnOnce() -> E,
    {
        self.map_err(|source| crate::Error::from_foreign_boxed_source(f(), source))
            .log_warn(*std::panic::Location::caller())
    }
}

#[cfg(test)]
mod tests {
    use super::ForeignError as _;
    use crate::traits::ForeignBoxed;

    #[derive(Debug)]
    enum ForeignError {
        SystemError,
        UsageError,
    }

    impl std::error::Error for ForeignError {}

    impl std::fmt::Display for ForeignError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::SystemError => write!(f, "SystemError"),
                Self::UsageError => write!(f, "UsageError"),
            }
        }
    }

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

    fn non_failing_function() -> std::result::Result<(), ForeignError> {
        Ok(())
    }

    fn failing_function(error: ForeignError) -> std::result::Result<(), ForeignError> {
        Err(error)
    }

    fn non_failing_function_boxed(
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn failing_function_boxed(
        error: ForeignError,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err(Box::new(error))
    }

    #[test]
    fn test_foreign_err() {
        assert!(non_failing_function()
            .foreign_err(|| KnownError::UsageError)
            .is_ok());

        let error = failing_function(ForeignError::UsageError)
            .foreign_err(|| KnownError::UsageError)
            .unwrap_err();

        assert_eq!(error.error, KnownError::UsageError);
        assert!(matches!(
            error.source,
            Some(crate::ErrorSource::ForeignError(_))
        ));

        let error = failing_function(ForeignError::SystemError)
            .foreign_err(|| KnownError::SystemError)
            .unwrap_err();

        assert_eq!(error.error, KnownError::SystemError);
        assert!(matches!(
            error.source,
            Some(crate::ErrorSource::ForeignError(_))
        ));
    }

    #[test]
    fn test_match_foreign_err() {
        assert!(non_failing_function()
            .match_foreign_err(|error| match error {
                ForeignError::SystemError => KnownError::SystemError,
                ForeignError::UsageError => KnownError::UsageError,
            })
            .is_ok());

        let error = failing_function(ForeignError::UsageError)
            .match_foreign_err(|error| match error {
                ForeignError::SystemError => KnownError::SystemError,
                ForeignError::UsageError => KnownError::UsageError,
            })
            .unwrap_err();

        assert_eq!(error.error, KnownError::UsageError);
        assert!(matches!(
            error.source,
            Some(crate::ErrorSource::ForeignError(_))
        ));

        let error = failing_function(ForeignError::SystemError)
            .match_foreign_err(|error| match error {
                ForeignError::SystemError => KnownError::SystemError,
                ForeignError::UsageError => KnownError::UsageError,
            })
            .unwrap_err();

        assert_eq!(error.error, KnownError::SystemError);
        assert!(matches!(
            error.source,
            Some(crate::ErrorSource::ForeignError(_))
        ));
    }

    #[test]
    fn test_foreign_boxed_err() {
        assert!(non_failing_function_boxed()
            .foreign_boxed_err(|| KnownError::UsageError)
            .is_ok());

        let error = failing_function_boxed(ForeignError::UsageError)
            .foreign_boxed_err(|| KnownError::UsageError)
            .unwrap_err();

        assert_eq!(error.error, KnownError::UsageError);
        assert!(matches!(
            error.source,
            Some(crate::ErrorSource::ForeignError(_))
        ));

        let error = failing_function_boxed(ForeignError::SystemError)
            .foreign_boxed_err(|| KnownError::SystemError)
            .unwrap_err();

        assert_eq!(error.error, KnownError::SystemError);
        assert!(matches!(
            error.source,
            Some(crate::ErrorSource::ForeignError(_))
        ));
    }
}
