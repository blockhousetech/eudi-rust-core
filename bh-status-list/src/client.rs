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

//! Module defining the interface for a Status List client.

use std::future::Future;

use crate::UriBuf;

/// Response from [`StatusListClient::get_status`].
pub enum StatusListResponse {
    /// JWT encoded Status List.
    Jwt(String),
}

/// Trait that defines the interface for a Status List client.
pub trait StatusListClient {
    /// The error type returned by the client.
    type Err;

    /// Fetches a Status List from the given URI.
    fn get_status(
        &self,
        uri: &UriBuf,
    ) -> impl Future<Output = Result<StatusListResponse, Self::Err>>;
}
