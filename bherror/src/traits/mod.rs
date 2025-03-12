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

//! This module provides various extension traits which provide convenience for working with our
//! error handling system.

mod error_context;
mod foreign_error;
pub(super) mod loggable;
mod propagate_error;

pub use error_context::ErrorContext;
pub use foreign_error::{ForeignBoxed, ForeignError};
pub use loggable::Loggable;
pub use propagate_error::PropagateError;
