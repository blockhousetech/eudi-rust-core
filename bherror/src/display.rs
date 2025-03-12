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

// Writes only the top-level error.
impl<E> std::fmt::Display for crate::Error<E>
where
    E: crate::BhError,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

// Goes through the whole error chain and writes all the errors.
impl<E> std::fmt::Debug for crate::Error<E>
where
    E: crate::BhError,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{")?;

        // Write the error variant
        let error_esc = json_escape(&self.error.to_string());
        write!(f, "\"error\":{}", error_esc)?;

        // Write the current context if present
        if !self.context.is_empty() {
            write!(f, ",\"context\":[")?;

            // Write the first element without the "," in front
            let ctx_esc = json_escape(&self.context[0].to_string());
            write!(f, "{}", ctx_esc)?;

            // Write other elements with the "," in front
            for context in self.context.iter().skip(1) {
                let ctx_esc = json_escape(&context.to_string());
                write!(f, ",{}", ctx_esc)?;
            }

            write!(f, "]")?;
        }

        // Write the source of the error
        if let Some(source) = &self.source {
            write!(f, ",\"source\":")?;

            match source {
                // If it is a known source, use its Debug output
                crate::ErrorSource::KnownError(source) => {
                    write!(f, "{:?}", source)?;
                }
                // If it is a foreign error, use the recursive helper function
                crate::ErrorSource::ForeignError(source) => {
                    debug_foreign_error(source.as_ref(), f)?;
                }
            }
        }

        write!(f, "}}")
    }
}

fn debug_foreign_error(
    error: &dyn std::error::Error,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    write!(f, "{{")?;

    // Write the error debug
    let error_esc = json_escape(&format!(r"{:?}", error));
    write!(f, "\"error\":{}", error_esc)?;

    // Write the source of the error
    if let Some(source) = error.source() {
        write!(f, ",\"source\":")?;

        debug_foreign_error(source, f)?;
    }

    write!(f, "}}")
}

fn json_escape(value: &str) -> String {
    serde_json::json!(value).to_string()
}

#[cfg(test)]
mod tests {
    use crate::{
        display::json_escape,
        traits::{ErrorContext, ForeignError, PropagateError},
    };

    macro_rules! known_error {
        ($name:ident -> $($variant:ident),+) => {
            #[allow(dead_code)]
            #[derive(Debug)]
            enum $name {
                $($variant,)+
            }

            impl std::fmt::Display for $name
            {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    match self {
                        $(Self::$variant => write!(f, "{}", stringify!($variant)),)+
                    }
                }
            }

            impl crate::BhError for $name {}
        };
    }

    macro_rules! foreign_error {
        ($name:ident -> $($variant:ident),*) => {
            #[allow(dead_code)]
            #[derive(Debug)]
            enum $name {
                $($variant(Box<dyn std::error::Error + Send + Sync>),)*
                NoSource,
            }

            impl std::fmt::Display for $name
            {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    match self {
                        $(Self::$variant(_) => write!(f, "{}", stringify!($variant)),)*
                        Self::NoSource => write!(f, "NoSource")
                    }
                }
            }

            impl std::error::Error for $name {
                fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                    match self {
                        $(Self::$variant(source) => Some(source.as_ref() as _),)*
                        Self::NoSource => None
                    }
                }
            }
        };
    }

    known_error!(KnownErrorFirst -> SystemError, UsageError);
    known_error!(KnownErrorSecond -> SecondErrorVariant);

    foreign_error!(ForeignErrorFirst -> ForeignErrorFirstVariant);
    foreign_error!(ForeignErrorSecond -> ForeignErrorSecondVariant);

    #[test]
    fn test_json_escape() {
        assert_eq!(json_escape("Some string"), r#""Some string""#);
        assert_eq!(
            json_escape("String with \"quotes\""),
            r#""String with \"quotes\"""#
        );
        assert_eq!(
            json_escape("{\"key\":\"value\"}"),
            r#""{\"key\":\"value\"}""#
        );
        assert_eq!(
            json_escape("[\"item1\",\"item2\"]"),
            r#""[\"item1\",\"item2\"]""#
        );
        assert_eq!(
            json_escape("{\"list\":[\"item1\",\"item2\"]}"),
            r#""{\"list\":[\"item1\",\"item2\"]}""#
        );
    }

    #[test]
    fn test_display() {
        let err = crate::Error::root(KnownErrorFirst::SystemError);
        assert_eq!(err.to_string(), "SystemError");

        let err = Err::<(), _>(ForeignErrorFirst::NoSource)
            .map_err(|err| ForeignErrorSecond::ForeignErrorSecondVariant(Box::new(err)))
            .foreign_err(|| KnownErrorFirst::UsageError)
            .with_err(|| KnownErrorSecond::SecondErrorVariant)
            .unwrap_err();
        assert_eq!(err.to_string(), "SecondErrorVariant");

        let err = crate::Error::root(KnownErrorFirst::UsageError).ctx("Some error context");
        assert_eq!(err.to_string(), "UsageError");
    }

    #[test]
    fn test_debug() {
        let err = Err::<(), _>(ForeignErrorFirst::NoSource)
            .map_err(|err| ForeignErrorSecond::ForeignErrorSecondVariant(Box::new(err)))
            .foreign_err(|| KnownErrorFirst::UsageError)
            .with_err(|| KnownErrorSecond::SecondErrorVariant)
            .unwrap_err();
        assert_eq!(
            format!("{err:?}"),
            r#"{"error":"SecondErrorVariant","source":{"error":"UsageError","source":{"error":"ForeignErrorSecondVariant(NoSource)","source":{"error":"NoSource"}}}}"#
        );

        let err = Err::<(), _>(ForeignErrorFirst::NoSource)
            .foreign_err(|| KnownErrorFirst::SystemError)
            .ctx(|| "Some error context")
            .ctx(|| "Another error context")
            .with_err(|| KnownErrorSecond::SecondErrorVariant)
            .ctx(|| "Error context")
            .unwrap_err();
        assert_eq!(
            format!("{err:?}"),
            r#"{"error":"SecondErrorVariant","context":["Error context"],"source":{"error":"SystemError","context":["Some error context","Another error context"],"source":{"error":"NoSource"}}}"#
        );
    }

    #[test]
    fn test_quotes() {
        // test quotes in context
        let err = crate::Error::root(KnownErrorFirst::SystemError).ctx("Context with \"quotes\"");
        assert_eq!(
            format!("{err:?}"),
            r#"{"error":"SystemError","context":["Context with \"quotes\""]}"#
        );

        // test JSON structure in context (it should stay String)
        let err = crate::Error::root(KnownErrorFirst::UsageError).ctx("{\"key\":\"value\"}");
        assert_eq!(
            format!("{err:?}"),
            r#"{"error":"UsageError","context":["{\"key\":\"value\"}"]}"#
        );
    }
}
