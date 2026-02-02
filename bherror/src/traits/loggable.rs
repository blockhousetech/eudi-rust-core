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

use std::panic::Location;

use crate::Error;

/// Trait making a [`crate::Result<T, BhError>`] error variant loggable.
pub trait Loggable<T, E>
where
    E: crate::BhError,
{
    /// Logs the error if it occured.
    fn log_err(self) -> Self;
}

impl<T, E> Loggable<T, E> for crate::Result<T, E>
where
    E: crate::BhError,
{
    #[track_caller]
    fn log_err(self) -> Self {
        let location = std::panic::Location::caller();

        self.map_err(|error| {
            log::error!(target: &location.to_string(), "{:?}", error);
            error
        })
    }
}

pub(crate) trait Warnable<E>
where
    E: crate::BhError,
{
    /// Logs a warning about an error if it occured.
    fn log_warn(self, location: Location) -> Self;
}

impl<T, E> Warnable<E> for crate::Result<T, E>
where
    E: crate::BhError,
{
    fn log_warn(self, location: Location) -> Self {
        self.map_err(|error| error.log_warn(location))
    }
}

impl<E> Warnable<E> for Error<E>
where
    E: crate::BhError,
{
    fn log_warn(self, location: Location) -> Self {
        log::warn!(target: &location.to_string(), "{:?}", self);
        self
    }
}
