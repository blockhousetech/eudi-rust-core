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

/// Extension trait for providing additional context to errors within [`crate::Result`].
///
/// This trait is implemented for the [`crate::Result`] type, to provide functionality for adding
/// the additional contexts to the [`crate::Error`].  The errors stay the same, but are enriched
/// with additional explanations.
pub trait ErrorContext<T, E>
where
    E: crate::BhError,
{
    /// Additional context is added to the [Err] variant, while the rest remains untouched.
    ///
    /// The context is lazily evaluated.
    fn ctx<C, F>(self, f: F) -> crate::Result<T, E>
    where
        C: std::fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C;
}

impl<T, E> ErrorContext<T, E> for crate::Result<T, E>
where
    E: crate::BhError,
{
    fn ctx<C, F>(self, f: F) -> crate::Result<T, E>
    where
        C: std::fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|error| error.ctx(f()))
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorContext as _;

    #[derive(Debug, PartialEq)]
    struct DummyError;

    impl std::fmt::Display for DummyError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "DummyError")
        }
    }

    impl crate::BhError for DummyError {}

    fn non_failing_function() -> crate::Result<(), DummyError> {
        Ok(())
    }

    fn failing_function(error: DummyError) -> crate::Result<(), DummyError> {
        Err(crate::Error::root(error))
    }

    #[test]
    fn test_ctx() {
        assert!(non_failing_function().ctx(|| "some error context").is_ok());

        assert!(failing_function(DummyError)
            .ctx(|| "some error context")
            .is_err())
    }
}
