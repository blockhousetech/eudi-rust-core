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

//! This module provides the [`Verifier`] type which is used to verify issued `mDoc` Credentials.

use bh_jws_utils::{SignatureVerifier, SigningAlgorithm};
use rand::Rng;

use crate::{
    models::{
        data_retrieval::{device_retrieval::response::Document, Claims},
        DeviceResponse,
    },
    utils::rand::generate_nonce,
    MdocError, Result,
};

/// Verifier of issued `mDoc` Credentials.
pub struct Verifier {
    client_id: String,
    response_uri: String,
    nonce: String,
}

impl Verifier {
    /// Creates a new [`Verifier`].
    ///
    /// It will also create a new `nonce` value used by this verifier to later
    /// successfully verify a device signature. The provided `nonce_rng` will be
    /// used to generate that `nonce`.
    ///
    /// If you wish to provide your own `nonce` value, use [`Verifier::from_parts`].
    pub fn new<R: Rng + ?Sized>(
        client_id: String,
        response_uri: String,
        nonce_rng: &mut R,
    ) -> Self {
        let nonce = generate_nonce(nonce_rng);
        Self::from_parts(client_id, response_uri, nonce)
    }

    /// Create a new [`Verifier`] but with the provided `nonce` value.
    ///
    /// If you don't want to explicitly provide the `nonce` value, you may use [`Verifier::new`]
    /// which will generate it.
    pub fn from_parts(client_id: String, response_uri: String, nonce: String) -> Self {
        Self {
            client_id,
            response_uri,
            nonce,
        }
    }

    /// Verifies, extracts and returns the claims from the `mDoc` credential.
    ///
    /// # Error
    ///
    /// An error is returned if the provided [`DeviceResponse`] does not contain
    /// any [`Document`]s or if there was an error during the verification
    /// process.
    pub fn verify<'a>(
        self,
        device_response: DeviceResponse,
        current_time: u64,
        mdoc_generated_nonce: &str,
        get_signature_verifier: impl Fn(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    ) -> Result<Vec<Claims>> {
        device_response
            .into_documents()
            .ok_or_else(|| bherror::Error::root(MdocError::EmptyDeviceResponse))?
            .into_iter()
            .map(|document| {
                document_verify_into_claims(
                    document,
                    &self.client_id,
                    &self.response_uri,
                    &self.nonce,
                    mdoc_generated_nonce,
                    &get_signature_verifier,
                    current_time,
                )
            })
            .collect::<Result<_>>()
    }

    /// Gets the `nonce` value as `&str`.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}

/// Returns the data elements from the provided [`Document`], while performing
/// the necessary verifications.
fn document_verify_into_claims<'a>(
    document: Document,
    client_id: &str,
    response_uri: &str,
    nonce: &str,
    mdoc_generated_nonce: &str,
    get_signature_verifier: impl Fn(SigningAlgorithm) -> Option<&'a dyn SignatureVerifier>,
    current_time: u64,
) -> Result<Claims> {
    document.verify(
        client_id,
        response_uri,
        nonce,
        mdoc_generated_nonce,
        get_signature_verifier,
    )?;

    document.validate(current_time)?;

    Ok(document.into_claims())
}
