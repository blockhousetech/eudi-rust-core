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

//! [BhError] adapter for the [axum] web framework.
//!
//! This module provides a trait [`IntoAxumResponse`] for easy conversion from [`Error<BhError>`]
//! types to [`axum::response::Response`].
//!
//! To use this facility, implement [`IntoAxumResponse`] for all concrete [`BhError`] types you
//! wish to return as an [axum] framework [HTTP response][axum::response::Response].

pub use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::{BhError, Error};

/// Trait for converting [`BhError`] types to [`axum::response::Response`].
pub trait IntoAxumResponse: BhError {
    /// Get the [HTTP Status Code][StatusCode] for this instance of [`BhError`].
    fn http_status_code(&self) -> StatusCode;

    /// Convert this instance of [`BhError`] to [`axum::response::Response`].
    ///
    /// The default implementation will do the conversion by using [`Self::http_status_code`] and
    /// the [`std::fmt::Display`] implementation of [`BhError`].
    fn into_axum_response(self) -> axum::response::Response
    where
        Self: Sized,
    {
        (self.http_status_code(), self.to_string()).into_response()
    }
}

impl<E: IntoAxumResponse> axum::response::IntoResponse for Error<E> {
    fn into_response(self) -> axum::response::Response {
        self.error.into_axum_response()
    }
}
