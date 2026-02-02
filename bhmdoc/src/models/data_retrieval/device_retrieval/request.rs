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

//! This module defines the data model described in the section "8.3.2.1.2.1 Device retrieval mdoc
//! request" of the [ISO/IEC 18013-5:2021][1] standard.
//!
//! [1]: <https://www.iso.org/standard/69084.html>

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::reader_auth::ReaderAuth;
use crate::models::{
    data_retrieval::common::{DataElementIdentifier, DocType, NameSpace},
    BytesCbor,
};

/// The version of the [`DeviceRequest`] structure.
///
/// The value is currently specified in the section `8.3.2.1.2.1` of the [ISO/IEC 18013-5:2021][1].
///
/// [1]: <https://www.iso.org/standard/69084.html>
const DEVICE_REQUEST_VERSION: &str = "1.0";

/// [`DeviceRequest`] as defined in the section `8.3.2.1.2.1` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRequest {
    version: String,
    doc_requests: Vec<DocRequest>,
}

impl DeviceRequest {
    /// Crate a new [`DeviceRequest`] with given requested documents.
    pub fn new(doc_requests: Vec<DocRequest>) -> Self {
        Self {
            version: DEVICE_REQUEST_VERSION.to_owned(),
            doc_requests,
        }
    }

    pub(crate) fn find_by_doc_type(&self, doc_type: &DocType) -> Option<&DocRequest> {
        self.doc_requests
            .iter()
            .find(|doc_request| &doc_request.items_request.0.inner.doc_type == doc_type)
    }
}

/// [`DocRequest`] as defined in the section `8.3.2.1.2.1` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocRequest {
    items_request: ItemsRequestBytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    reader_auth: Option<ReaderAuth>,
}

impl DocRequest {
    pub(crate) fn name_spaces(&self) -> &NameSpaces {
        &self.items_request.0.inner.name_spaces
    }

    /// Create a builder for a [`DocRequest`] with given [`DocType`].
    pub fn builder(doc_type: DocType) -> DocRequestBuilder {
        DocRequestBuilder::new(doc_type)
    }
}

/// [`ItemsRequestBytes`] as defined in the section `8.3.2.1.2.1` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ItemsRequestBytes(BytesCbor<ItemsRequest>);

/// [`ItemsRequest`] as defined in the section `8.3.2.1.2.1` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemsRequest {
    doc_type: DocType,
    name_spaces: NameSpaces,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_info: Option<HashMap<String, ciborium::Value>>,
}

impl From<ItemsRequest> for ItemsRequestBytes {
    fn from(value: ItemsRequest) -> Self {
        Self(value.into())
    }
}

/// [`NameSpaces`] as defined in the section `8.3.2.1.2.1` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct NameSpaces(pub(crate) HashMap<NameSpace, DataElements>);

/// [`DataElements`] as defined in the section `8.3.2.1.2.1` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DataElements(pub(crate) HashMap<DataElementIdentifier, IntentToRetain>);

/// [`IntentToRetain`] as defined in the section `8.3.2.1.2.1` of the [ISO/IEC 18013-5:2021][1]
/// standard.
///
/// [1]: <https://www.iso.org/standard/69084.html>
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct IntentToRetain(bool);

impl From<bool> for IntentToRetain {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

/// A builder for constructing a [`DocRequest`].
///
/// The [`DocRequestBuilder`] allows for the incremental construction of a [`DocRequest`] by
/// specifying the [`DocType`], [`NameSpace`]s, request information, and [`ReaderAuth`].
#[derive(Debug)]
pub struct DocRequestBuilder {
    doc_type: DocType,
    name_spaces: NameSpaces,
    request_info: Option<HashMap<String, ciborium::Value>>,
    reader_auth: Option<ReaderAuth>,
}

impl DocRequestBuilder {
    /// Create a new builder for a [`DocRequest`] with given [`DocType`].
    pub fn new(doc_type: DocType) -> Self {
        Self {
            doc_type,
            name_spaces: NameSpaces(HashMap::new()),
            request_info: None,
            reader_auth: None,
        }
    }

    /// Add a [`NameSpace`] with given [`DataElements`].
    pub fn add_name_space(
        mut self,
        name_space: NameSpace,
        data_elements: HashMap<DataElementIdentifier, IntentToRetain>,
    ) -> Self {
        self.name_spaces
            .0
            .insert(name_space, DataElements(data_elements));
        self
    }

    /// Add a ([`DataElementIdentifier`], [`IntentToRetain`]) pair to [`DataElements`] of a given
    /// [`NameSpace`].
    ///
    /// If the [`NameSpace`] hasn't already been added with [`DocRequestBuilder::add_name_space`],
    /// it will be added now.
    pub fn add_data_element(
        mut self,
        name_space: NameSpace,
        data_element_identifier: DataElementIdentifier,
        intent_to_retain: IntentToRetain,
    ) -> Self {
        self.name_spaces
            .0
            .entry(name_space)
            .or_insert_with(|| DataElements(HashMap::new()))
            .0
            .insert(data_element_identifier, intent_to_retain);
        self
    }

    /// Set the `requestInfo` for [`ItemsRequest`] of the [`DocRequest`] we are building.
    ///
    /// This will replace the previously set `requestInfo`, if any.
    pub fn add_request_info(mut self, request_info: HashMap<String, ciborium::Value>) -> Self {
        self.request_info = Some(request_info);
        self
    }

    /// Set the [`ReaderAuth`] of the [`DocRequest`] we are building.
    ///
    /// This will replace the previously set [`ReaderAuth`], if any.
    pub fn add_reader_auth(mut self, reader_auth: ReaderAuth) -> Self {
        self.reader_auth = Some(reader_auth);
        self
    }

    /// Finalize the configuration of the [`DocRequestBuilder`] and construct a new [`DocRequest`].
    pub fn build(self) -> DocRequest {
        let items_request = ItemsRequest {
            doc_type: self.doc_type,
            name_spaces: self.name_spaces,
            request_info: self.request_info,
        };

        DocRequest {
            items_request: items_request.into(),
            reader_auth: self.reader_auth,
        }
    }
}
