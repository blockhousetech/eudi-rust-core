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

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! This crate provides an error handling system used across all of the TBTL's Rust code.
//!
//! The errors constructed are automatically logged as warnings. Errors also carry the backtrace of
//! source errors with them, along with extra context if any.
//!
//! # Details
//!
//! Use `std::result::Result<T, bherror::Error<E>>`, or equivalently `bherror::Result<T, E>` as the
//! return type for functions which may return an error.
//!
//! The error type `E` in `bherror::Error<E>` must implement the [`BhError`] trait.  Therefore, all
//! of our concrete error types must implement [`BhError`].
//!
//! Constructing the initial, root error is done via the [`Error::root`] method.  This will also
//! log a warning.
//!
//! Error types that are not defined by us, i.e. don't implement [`BhError`] but do implement
//! [`std::error::Error`] we name as "foreign errors".  These errors can be converted & propagated
//! to `bherror::Error<E>` via the [`ForeignError`][traits::ForeignError] trait.
//!
//! Propagating `bherror::Error<E>` types is done via the [`PropagateError`][traits::ForeignError]
//! trait, instead of using `?`.  This way we preserve the trace of source errors.
//!
//! Additional context can be attached to an error using the [`Error::ctx`] method.  As a
//! convenience, we also offer [`ErrorContext`][traits::ErrorContext] trait which extends the
//! [`Result`] type with the same method.
//!
//! The crate also offers some additional features.
//!
//! * [`ErrorDyn`] for cases when you want to type-erase the concrete [`BhError`] type.
//! * [`Loggable`][traits::Loggable] trait which extends the [`Result`] with a method for logging
//!   errors at the error level.  Note, we log all constructed errors as warnings regardless.
//! * [`adapters`] module for easier integration with other libraries & frameworks.
//!
//! # Examples
//!
//! ```
//! use bherror::traits::{ErrorContext, ForeignError, PropagateError};
//!
//! enum MyErrors {
//!     NumberIsNegativeError,
//!     NumberParseError,
//! }
//!
//! impl std::fmt::Display for MyErrors {
//!     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//!         match self {
//!             MyErrors::NumberIsNegativeError => write!(f, "MyErrors::NumberIsNegativeError"),
//!             MyErrors::NumberParseError => write!(f, "MyErrors::NumberParseError"),
//!         }
//!     }
//! }
//!
//! impl bherror::BhError for MyErrors {}
//!
//! fn my_function(s: &str) -> bherror::Result<i32, MyErrors> {
//!     let num = s
//!         .parse()
//!         // Propagate a "foreign error" and log it as a warning.
//!         .foreign_err(|| MyErrors::NumberParseError)
//!         // Add some additional context to the error.
//!         .ctx(|| format!("parsing {s}"))?;
//!     if num < 0 {
//!         // Return the root error and log it as a warning.
//!         Err(bherror::Error::root(MyErrors::NumberIsNegativeError))
//!     } else {
//!         Ok(num)
//!     }
//! }
//!
//! struct AnotherError;
//!
//! impl std::fmt::Display for AnotherError {
//!     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//!         write!(f, "AnotherError")
//!     }
//! }
//!
//! impl bherror::BhError for AnotherError {}
//!
//! fn another_function() -> bherror::Result<(), AnotherError> {
//!     // Propagate `MyErrors` as the source error for `AnotherError`
//!     my_function("blah").with_err(|| AnotherError)?;
//!     Ok(())
//! }
//! ```

use std::{any::Any, ops::Deref};

use crate::traits::loggable::Warnable;

pub mod adapters;
mod display;
pub mod traits;

/// The trait needed for compatibility with the [`Error`] functionality.
pub trait BhError: std::fmt::Display + Send + Sync + 'static {}

/// Hacky trait to enable downcasting from trait objects of it.
///
/// See: <https://lucumr.pocoo.org/2022/1/7/as-any-hack/>
pub trait BhErrorAny: BhError + Any {
    /// Return `self` as [Any] type.
    fn as_any(&self) -> &dyn Any;
}

impl<E: BhError> BhErrorAny for E {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// This impl covers all boxed error types, including `dyn BhError`
impl<E: BhError + ?Sized> BhError for Box<E> {}

/// Error containing type-erased [`BhError`].
///
/// Needs to use the [`BhErrorAny`] subtrait so that [`BhErrorAny::as_any`] would be available on
/// the internal error type.
pub type ErrorDyn = Error<Box<dyn BhErrorAny>>;

trait KnownError: std::error::Error + Send + Sync {
    fn as_err(&self) -> &(dyn std::error::Error + 'static);
}

impl<T> KnownError for Error<T>
where
    T: BhError,
{
    fn as_err(&self) -> &(dyn std::error::Error + 'static) {
        self
    }
}

enum ErrorSource {
    KnownError(Box<dyn KnownError>),
    ForeignError(Box<dyn std::error::Error + Send + Sync>),
}

/// A struct that should be used for all errors in our projects.
///
/// It wraps specific errors created to model different error groups. Those errors should all
/// implement the [`BhError`] trait in order to be compatible. They should not implement the
/// [`std::error::Error`] trait themselves, it will be handled by this [`Error`] struct.
///
/// This [`Error`] struct should be used whenever the [`std::result::Result`] is used as the return
/// type of the function/method, to model the returned error.  For convenience, we provide a type
/// alias [`Result`], so that you don't have to explicitly wrap your [`BhError`] into [`Error`].
///
/// This wrapper automatically keeps track of the whole error chain, as well as the context
/// assigned to the error, which might elaborate on the error specifics. It also handles all the
/// error displays.
pub struct Error<E>
where
    E: BhError,
{
    /// The concrete error variant.
    pub error: E,
    /// The optional context of the error.
    context: Vec<Box<dyn std::fmt::Display + Send + Sync>>,
    /// The error source, to be able to backtrace errors.
    source: Option<ErrorSource>,
}

/// The [`std::result::Result`] wrapper that wraps the error object into [`Error`].
pub type Result<T, E> = std::result::Result<T, Error<E>>;

impl<E> Error<E>
where
    E: BhError,
{
    /// Create a root error (i.e. it does not have a source) and log a warning.
    ///
    /// It should be used in places where an error happened for the first time.  E.g. within `if`
    /// or `if let` constructs.
    ///
    /// Do *not* use this method to propagate another error, because the whole error chain will be
    /// lost.  If you want to propagate an error (i.e. track the source error), use either a method
    /// from the [traits::ForeignError] or the [traits::PropagateError].
    #[track_caller]
    pub fn root(error: E) -> Self {
        Self {
            error,
            context: Vec::new(),
            source: None,
        }
        .log_warn(*std::panic::Location::caller())
    }

    /// Creates an error from its source, which is a foreign (unknown) error.
    ///
    /// The method should stay private, as it should not be used from the library/service code.
    fn from_foreign_source<S>(error: E, source: S) -> Self
    where
        S: std::error::Error + Send + Sync + 'static,
    {
        Self {
            error,
            context: Vec::new(),
            source: Some(ErrorSource::ForeignError(Box::new(source))),
        }
    }

    /// Creates an error from its source, which is a known error.
    ///
    /// The method should stay private, as it should not be used from the library/service code.
    fn from_known_source<S>(error: E, source: S) -> Self
    where
        S: KnownError + 'static,
    {
        Self {
            error,
            context: Vec::new(),
            source: Some(ErrorSource::KnownError(Box::new(source))),
        }
    }

    /// Creates an error from its source, which is a foreign (unknown) error.  Here, a concrete
    /// error type is not known at compile time.
    ///
    /// The method should stay private, as it should not be used from the library/service code.
    fn from_foreign_boxed_source(
        error: E,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self {
            error,
            context: Vec::new(),
            source: Some(ErrorSource::ForeignError(source)),
        }
    }

    /// Adds additional context to the error and returns it. It should be used to enrich the error
    /// with further explanations.
    ///
    /// The method takes ownership of `self` so that the method can be chained.
    ///
    /// Context can be added multiple times and all the contexts will be saved to the error.
    pub fn ctx<C>(mut self, context: C) -> Self
    where
        C: std::fmt::Display + Send + Sync + 'static,
    {
        self.context.push(Box::new(context));
        self
    }

    /// Type-erases the error, making it wrap a `dyn BhError` trait object.
    ///
    /// This is mostly useful when implementing traits which must be object-safe but the type of
    /// possible errors is not statically known; in such cases, [ErrorDyn] can be used instead of
    /// associated error types.
    pub fn erased(self) -> ErrorDyn {
        Error {
            error: Box::new(self.error),
            context: self.context,
            source: self.source,
        }
    }
}

impl ErrorDyn {
    /// Tries downcasting the contained `dyn BhErrorAny` to `E`.
    ///
    /// This is mostly useful when trying to recover the concrete error type to match on after it
    /// had been erased previously.
    pub fn downcast_ref_inner<E: BhError>(&self) -> Option<&E> {
        // The `.deref()` is important, since we want to call `.as_any()` with
        // `&dyn BhErrorAny`, not `&Box<dyn BhErrorAny>`, which would compile
        // but give `None` when downcasting to
        // https://lucumr.pocoo.org/2022/1/7/as-any-hack/
        self.error.deref().as_any().downcast_ref()
    }
}

// Make the Error a std::error::Error type.
impl<E> std::error::Error for Error<E>
where
    E: BhError,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| match source {
            ErrorSource::KnownError(source) => source.as_ref().as_err(),
            // "as _" here denotes casting to the output type, i.e. from
            // (Error + Send + Sync) to (Error + 'static). It is the same as
            // using "as &(dyn std::error::Error + 'static)".
            ErrorSource::ForeignError(source) => source.as_ref() as _,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[derive(Debug, PartialEq)]
    enum DummyError {
        SystemError,
        UsageError,
    }

    impl std::fmt::Display for DummyError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::SystemError => write!(f, "SystemError"),
                Self::UsageError => write!(f, "UsageError"),
            }
        }
    }

    impl BhError for DummyError {}

    #[test]
    fn test_root() {
        let error = Error::root(DummyError::SystemError);

        assert_eq!(error.error, DummyError::SystemError);
        assert!(error.source.is_none());
    }

    #[test]
    fn test_from_foreign_source() {
        let error_sys = Error::root(DummyError::SystemError);
        let error_us = Error::from_foreign_source(DummyError::UsageError, error_sys);

        assert_eq!(error_us.error, DummyError::UsageError);
        assert!(matches!(
            error_us.source,
            Some(ErrorSource::ForeignError(_))
        ));
    }

    #[test]
    fn test_from_known_source() {
        let error_sys = Error::root(DummyError::SystemError);
        let error_us = Error::from_known_source(DummyError::UsageError, error_sys);

        assert_eq!(error_us.error, DummyError::UsageError);
        assert!(matches!(error_us.source, Some(ErrorSource::KnownError(_))));
    }

    #[test]
    fn test_ctx() {
        let error = Error::root(DummyError::UsageError).ctx("Dummy first context");

        assert_eq!(error.error, DummyError::UsageError);
        assert!(error.source.is_none());
        assert!(error
            .context
            .iter()
            .map(ToString::to_string)
            .any(|ctx| &ctx == "Dummy first context"));

        let error = error.ctx("Dummy second context");

        assert_eq!(error.error, DummyError::UsageError);
        assert!(error.source.is_none());
        let ctx_vec: Vec<String> = error.context.iter().map(ToString::to_string).collect();
        assert!(ctx_vec.contains(&String::from("Dummy first context")));
        assert!(ctx_vec.contains(&String::from("Dummy second context")));
    }

    #[test]
    fn test_source() {
        let error = Error {
            error: DummyError::SystemError,
            context: Vec::new(),
            source: None,
        };
        assert!(error.source().is_none());

        let error = Error {
            error: DummyError::UsageError,
            context: Vec::new(),
            source: Some(ErrorSource::ForeignError(Box::new(error))),
        };
        assert!(error.source().is_some());

        let error = Error {
            error: DummyError::SystemError,
            context: Vec::new(),
            source: Some(ErrorSource::KnownError(Box::new(error))),
        };
        assert!(error.source().is_some());
    }

    #[test]
    fn test_downcast_erased() {
        let error = Error {
            error: DummyError::SystemError,
            context: Vec::new(),
            source: None,
        };

        let erased_error = error.erased();
        let downcast_error = erased_error.downcast_ref_inner::<DummyError>();

        assert_eq!(downcast_error, Some(&DummyError::SystemError));
    }
}
