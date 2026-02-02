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

//! Contains implementations for public key lookup strategies.
//!
//! * [`HttpsIssuerPublicKeyLookup`] for lookup via HTTPS.
//! * [`X5ChainIssuerPublicKeyLookup`] for lookup from a X.509 certificate chain.
//!
//! <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-09#name-issuer-signed-jwt-verificat>

use std::future::Future;

use bh_jws_utils::public_jwk_from_x5chain_leaf;
pub use bh_jws_utils::{JwkPublic, JwkSet};
use bh_uri_utils::UriPathExtensions;
use bherror::{
    traits::{ForeignError, PropagateError},
    BhError, Error,
};
use bhx5chain::X509Trust;
use iref::{Uri, UriBuf};
use reqwest::{Client, ClientBuilder, StatusCode};
use serde::{Deserialize, Serialize};

use crate::{IssuerJwtHeader, IssuerPublicKeyLookup, JsonObject};

/// Models JWT Issuer Metadata, specified [here], contains:
///
/// - `issuer` : The Issuer identifier, which MUST be identical to the `iss` value in the JWT
///
/// exactly one of:
/// - `jwks`   : Issuer's JSON Web Key Set which contains the Issuer's public keys.
/// - `jwks_uri` : HTTPS URL to an endpoint serving the former.
///
/// and:
/// - `params` : All other additional configuration parameters which MAY be used [2].
///
/// [here]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#name-jwt-vc-issuer-metadata
/// [2]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.2-11
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(try_from = "JwtVcIssuerMetadataUnverified")]
pub struct JwtVcIssuerMetadata {
    /// The Issuer Identifier (`iss`).
    pub issuer: String,
    /// Either `jwks` or `jwks_uri`.
    #[serde(flatten)]
    pub jwks_param: JwksParam,
    /// Other optional configuration parameters.
    #[serde(flatten)]
    pub params: JsonObject,
}

/// Represents either the `jwks` or `jwks_uri`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwksParam {
    /// `jwks` variant.
    Jwks(JwkSet),
    /// `jwks_uri` variant.
    JwksUri(UriBuf),
}

impl JwksParam {
    async fn resolve(self, client: &impl HttpGetClient) -> Result<JwkSet, Error<LookupError>> {
        match self {
            JwksParam::Jwks(jwk_set) => Ok(jwk_set),
            JwksParam::JwksUri(jwks_uri) => {
                let jwk_set = client
                    .get(&jwks_uri)
                    .await
                    .foreign_err(|| {
                        LookupError(format!("failed to resolve `jwks_uri`: {}", jwks_uri))
                    })?
                    .json()
                    .await
                    .foreign_err(|| {
                        LookupError("failed to parse response from `jwks_uri` as a JWKS".to_owned())
                    })?;
                Ok(jwk_set)
            }
        }
    }

    #[cfg(test)]
    fn to_jwks(&self) -> &JwkSet {
        if let Self::Jwks(jwk_set) = self {
            jwk_set
        } else {
            panic!("`JwksParam` was `JwksUri`");
        }
    }

    #[cfg(test)]
    fn to_jwks_uri(&self) -> &Uri {
        if let Self::JwksUri(jwks_uri) = self {
            jwks_uri
        } else {
            panic!("`JwksParam` was `Jwks`");
        }
    }
}

/// This is a "shadow" type whose sole purpose of existence is to be able to verify validity of deserialized
/// [JwtVcIssuerMetadata] without writing deserialization manually. This is achieved with misusage of
/// `TryFrom` trait. For more info see this [github issue].
///
/// [github issue]: https://github.com/serde-rs/serde/issues/642
#[derive(Deserialize, Debug)]
struct JwtVcIssuerMetadataUnverified {
    issuer: String,
    #[serde(flatten)]
    jwks_param: JwksParam,
    #[serde(flatten)]
    params: JsonObject,
}

// Rejects a deserialization when deserialized metadata would jwks_uri parameter
impl TryFrom<JwtVcIssuerMetadataUnverified> for JwtVcIssuerMetadata {
    type Error = &'static str;

    fn try_from(value: JwtVcIssuerMetadataUnverified) -> Result<Self, Self::Error> {
        // Due to how serde implements Deserialize, the other (2nd in the
        // processing order) variant will (if present) actually end up in `params`
        if value.params.contains_key("jwks_uri") || value.params.contains_key("jwks") {
            return Err("`jwks` and `jwks_uri` are mutually exclusive");
        }

        Ok(JwtVcIssuerMetadata {
            issuer: value.issuer,
            jwks_param: value.jwks_param,
            params: value.params,
        })
    }
}

/// Interface providing functionality of sending HTTP GET request.
/// Motivation for introducing this abstraction is to allow an implementation of a more secure
/// HTTP Client which could prevent malicious URL injections (e.g. by whitelisting hosts).
///
// See TODO(issues/53)
pub trait HttpGetClient: Sync {
    /// Error type used by this trait.
    type Err: std::error::Error + Send + Sync + 'static;
    /// Performs a HTTP GET request with provided `url`.
    ///
    /// Note: Return type of request is currently hardcoded. This is subject to change in the future.
    // TODO(issues/53)
    fn get(
        &self,
        url: &str,
    ) -> impl Future<Output = std::result::Result<reqwest::Response, Self::Err>> + Send;
}

/// [`HttpGetClient`] implementation using the [`reqwest`] crate.
pub struct ReqwestGetClient(Client);

impl ReqwestGetClient {
    /// Construct [`ReqwestGetClient`] from [`Client`].
    pub fn new(client: Client) -> Self {
        Self(client)
    }
    /// Construct [`ReqwestGetClient`] from [`ClientBuilder`].
    pub fn from_builder(builder: ClientBuilder) -> reqwest::Result<Self> {
        Ok(ReqwestGetClient(builder.build()?))
    }
}

impl HttpGetClient for ReqwestGetClient {
    type Err = reqwest::Error;

    fn get(&self, url: &str) -> impl Future<Output = reqwest::Result<reqwest::Response>> {
        self.0.get(url).send()
    }
}

/// Implementation of Issuer Public Key lookup using HTTPS according to [spec]. Lookup requires
/// a [HttpGetClient] that provides the functionality of sending HTTP GET request to retrieve the key.
///
/// [spec]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#name-jwt-vc-issuer-metadata
pub struct HttpsIssuerPublicKeyLookup<C: HttpGetClient> {
    // TODO(issues/53)
    client: C,
}

impl<C: HttpGetClient> HttpsIssuerPublicKeyLookup<C> {
    /// Construct [`HttpsIssuerPublicKeyLookup`] from a [`HttpGetClient`].
    pub fn new(client: C) -> Self {
        HttpsIssuerPublicKeyLookup { client }
    }
}

/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5-2>
pub const ISSUER_METADATA_URL_SUFFIX: &str = "/.well-known/jwt-vc-issuer";

/// Error type for reporting issues during the lookup of the Issuer Public Key.
#[derive(PartialEq, Debug)]
pub struct LookupError(pub String);

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Lookup error: {}", self.0)
    }
}

impl BhError for LookupError {}

impl<C: HttpGetClient> IssuerPublicKeyLookup for HttpsIssuerPublicKeyLookup<C>
where
    <C as HttpGetClient>::Err: 'static, // because lookup receives &self
{
    type Err = LookupError;
    /// Retrieves the Issuer Public Key from the provided `alleged_iss` and a `kid` value
    /// as provided in the [IssuerJwtHeader] `header`.
    ///
    /// Arguments:
    ///
    /// - `alleged_iss` : `URI` which represents the Issuer of the Verifiable Credential.
    ///   URL for HTTP GET request is made by inserting the `WELL_KNOWN` string between
    ///   host and the path component of this value.
    ///   Should not contain query or fragment components.
    ///
    /// - `header`      : JWT header which contains a `kid` parameter that is used to look
    ///   up the public key in the [JwkSet] from the retrieved metadata.
    ///
    async fn lookup(
        &self,
        alleged_iss: &str,
        header: &IssuerJwtHeader,
    ) -> Result<JwkPublic, Error<Self::Err>> {
        let Ok(alleged_iss) = alleged_iss.try_into() else {
            return Err(Error::root(LookupError(format!(
                "Invalid `iss` URL: {}",
                alleged_iss
            ))));
        };

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.1-1
        check_valid_iss(alleged_iss)?;
        let url = url_from_iss(alleged_iss)?;

        let Some(header_kid) = &header.kid else {
            return Err(Error::root(LookupError(
                "JWT header `kid` field missing".to_owned(),
            )));
        };

        let response = self
            .client
            .get(url.as_str())
            .await
            .foreign_err(|| LookupError("could not get issuer metadata".to_string()))?;

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.2-1
        check_successful_response(&response)?;

        let metadata: JwtVcIssuerMetadata = response
            .json()
            .await
            .foreign_err(|| LookupError("response content invalid format".to_string()))?;

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.3-1
        if metadata.issuer != alleged_iss.as_str() {
            return Err(Error::root(LookupError(
                "response issuer value was not identical to iss value of JWT".to_string(),
            )));
        }

        let jwks = metadata.jwks_param.resolve(&self.client).await?;

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.2-6
        for jwk in jwks.keys {
            if jwk
                .get("kid")
                .and_then(|value| value.as_str())
                .is_some_and(|kid| kid == header_kid)
            {
                return Ok(jwk);
            };
        }
        Err(Error::root(LookupError(
            "JWK with kid from JWT header was not found".to_string(),
        )))
    }
}

// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.2-1
fn check_successful_response(response: &reqwest::Response) -> Result<(), Error<LookupError>> {
    if response.status() != StatusCode::OK {
        return Err(Error::root(LookupError(format!(
            "response status code was {}, expected 200 OK",
            response.status()
        ))));
    }
    let content_type = response
        .headers()
        .get("Content-type")
        .ok_or_else(|| Error::root(LookupError("response content type was empty".to_string())))?
        .to_str()
        .foreign_err(|| {
            LookupError("response content type is not able to be represented as string".to_string())
        })?;

    if content_type != "application/json" {
        return Err(Error::root(LookupError(format!(
            "response content type was {}, expected application/json",
            content_type
        ))));
    }
    Ok(())
}

/// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5-2
fn check_valid_iss(alleged_iss: &Uri) -> Result<(), Error<LookupError>> {
    if alleged_iss.scheme().as_str() != "https" {
        return Err(Error::root(LookupError(
            "iss uri scheme should be https".to_string(),
        )));
    }

    if alleged_iss.query().is_some() || alleged_iss.fragment().is_some() {
        return Err(Error::root(LookupError(
            "iss uri should not contain query or fragment parts".to_string(),
        )));
    }

    Ok(())
}

/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5-2>
pub fn metadata_uri_from_iss(alleged_iss: &Uri) -> iref::uri::UriBuf {
    alleged_iss
        .add_path_prefix(ISSUER_METADATA_URL_SUFFIX)
        .expect("`ISSUER_METADATA_URL_SUFFIX` must be valid")
}

/// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5-2>
pub fn url_from_iss(alleged_iss: &Uri) -> Result<reqwest::Url, Error<LookupError>> {
    let url = metadata_uri_from_iss(alleged_iss);

    reqwest::Url::parse(&url)
        .foreign_err(|| LookupError("error while parsing iss as url".to_string()))
}

/// The [`IssuerPublicKeyLookup`] implementation that retrieves the Issuer's
/// public key from the X.509 certificate chain.
///
/// It can be configured with trusted root certificates, in which case the
/// authenticity of the X.509 certificate chain will be verified against those
/// certificates, returning an error if the verification fails.
pub struct X5ChainIssuerPublicKeyLookup {
    trust: Option<X509Trust>,
}

impl X5ChainIssuerPublicKeyLookup {
    /// Create a new instance of the [`X5ChainIssuerPublicKeyLookup`], that will
    /// **TRUST ALL** Issuers, i.e. the authenticity of the X.509 certificate
    /// chain will not be verified.
    pub fn trust_all() -> Self {
        tracing::warn!("Issuer's authenticity will not be verified");

        Self { trust: None }
    }

    /// Create a new instance of the [`X5ChainIssuerPublicKeyLookup`], that will
    /// verify the authenticity of the X.509 certificate chain against the
    /// provided trusted roots.
    pub fn with_trust(trust: X509Trust) -> Self {
        Self { trust: Some(trust) }
    }
}

impl IssuerPublicKeyLookup for X5ChainIssuerPublicKeyLookup {
    type Err = LookupError;

    /// Retrieve and check the Issuer public key from the x5chain field in the JWT header.
    async fn lookup(
        &self,
        _alleged_iss: &str,
        header: &IssuerJwtHeader,
    ) -> Result<JwkPublic, Error<Self::Err>> {
        let Some(jwt_x5chain) = &header.x5c else {
            return Err(Error::root(LookupError(
                "missing 'x5c' jwt header".to_owned(),
            )));
        };

        let x5chain: bhx5chain::X5Chain = jwt_x5chain
            .clone()
            .try_into()
            .with_err(|| LookupError("failed to convert `JwtX5Chain` to `X5Chain`".to_owned()))?;

        if let Some(trust) = &self.trust {
            x5chain.verify_against_trusted_roots(trust).with_err(|| {
                LookupError("x5chain does not verify against trusted roots".to_owned())
            })?;
        }

        let public_jwk = public_jwk_from_x5chain_leaf(&x5chain, &header.alg, header.kid.as_deref())
            .foreign_err(|| LookupError("failed to get jwk from x5chain leaf".to_owned()))?;

        Ok(public_jwk)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use bh_jws_utils::{jwt::claims::SecondsSinceEpoch, Es256Verifier, SigningAlgorithm};
    use openssl::x509::X509;
    use serde_json::{json, Value};

    use super::*;
    use crate::{holder::Holder, issuer::TYP_VC_SD_JWT, HashingAlgorithm, Sha256};

    const HOLDER_ACCEPT_TIME: SecondsSinceEpoch = 1783000000;

    struct StubClient {
        expected_url: Option<String>,
        response: http::Response<String>,
    }

    impl HttpGetClient for StubClient {
        type Err = reqwest::Error;

        async fn get(&self, url: &str) -> reqwest::Result<reqwest::Response> {
            if self.expected_url.is_none() || url != self.expected_url.as_ref().unwrap() {
                panic!("Unexpected url: {}", url);
            }
            Ok(reqwest::Response::from(self.response.clone()))
        }
    }

    struct StubClient2Step {
        // The trait bounds + signature require this mutex
        first: Mutex<Option<StubClient>>,
        second: StubClient,
    }

    impl HttpGetClient for StubClient2Step {
        type Err = reqwest::Error;

        async fn get(&self, url: &str) -> reqwest::Result<reqwest::Response> {
            let first = self.first.lock().unwrap().take();
            if let Some(first) = first {
                first.get(url).await
            } else {
                self.second.get(url).await
            }
        }
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.2-8
    fn example_metadata() -> Value {
        json!({
           "issuer":"https://example.com",
           "jwks":{
              "keys":[
                 {
                    "kid":"doc-signer-05-25-2022",
                    "e":"AQAB",
                    "n":"nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfG
             HrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyk
             lBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70p
             RM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe
             2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKve
             qXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ",
                    "kty":"RSA"
                 }
              ]
           }
        })
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.2-10
    fn example_metadata_with_jwks_uri() -> Value {
        json!({
           "issuer": "https://example.com",
           "jwks_uri": "https://jwt-vc-issuer.example.org/my_public_keys.jwks"
        })
    }

    fn example_header() -> IssuerJwtHeader {
        IssuerJwtHeader {
            typ: TYP_VC_SD_JWT.to_string(),
            alg: SigningAlgorithm::Es256,
            kid: Some("doc-signer-05-25-2022".to_string()),
            x5c: None,
        }
    }

    fn example_header_with_x5c(jwt_x5chain: bhx5chain::JwtX5Chain) -> IssuerJwtHeader {
        IssuerJwtHeader {
            typ: TYP_VC_SD_JWT.to_string(),
            alg: SigningAlgorithm::Es256,
            kid: None,
            x5c: Some(jwt_x5chain),
        }
    }

    fn response_with_metadata(metadata: Value) -> http::Response<String> {
        http::Response::builder()
            .status(200)
            .header("Content-type", "application/json")
            .body(metadata.to_string())
            .unwrap()
    }

    /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.2-7
    #[tokio::test]
    async fn public_key_example_from_specification() {
        let alleged_iss = "https://example.com";

        let client = StubClient {
            expected_url: Some("https://example.com/.well-known/jwt-vc-issuer".to_string()),
            response: response_with_metadata(example_metadata()),
        };

        let header = example_header();

        let response = HttpsIssuerPublicKeyLookup { client }
            .lookup(Uri::new(alleged_iss).unwrap(), &header)
            .await
            .unwrap();

        assert_eq!(
            response.get("kid").unwrap().as_str().unwrap(),
            header.kid.unwrap()
        );
    }

    /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.2-10
    #[tokio::test]
    async fn public_key_example_with_jwks_uri_from_specification() {
        let alleged_iss = "https://example.com";

        let client = StubClient2Step {
            first: Mutex::new(Some(StubClient {
                expected_url: Some("https://example.com/.well-known/jwt-vc-issuer".to_owned()),
                response: response_with_metadata(example_metadata_with_jwks_uri()),
            })),
            second: StubClient {
                expected_url: Some(
                    "https://jwt-vc-issuer.example.org/my_public_keys.jwks".to_owned(),
                ),
                response: response_with_metadata(example_metadata()["jwks"].take()),
            },
        };

        let header = example_header();

        let response = HttpsIssuerPublicKeyLookup { client }
            .lookup(Uri::new(alleged_iss).unwrap(), &header)
            .await
            .unwrap();

        assert_eq!(
            response.get("kid").unwrap().as_str().unwrap(),
            header.kid.unwrap()
        );
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.1-5
    #[tokio::test]
    async fn iss_with_more_complex_path() {
        let alleged_iss = "https://example.com/tenant/1234";

        let metadata = json!({
           "issuer": alleged_iss,
           "jwks":{
              "keys":[
                 {"kid":"doc-signer-05-25-2022"}
              ]
           }
        });

        let client = StubClient {
            expected_url: Some(
                "https://example.com/.well-known/jwt-vc-issuer/tenant/1234".to_string(),
            ),
            response: response_with_metadata(metadata),
        };

        let header = example_header();

        let response = HttpsIssuerPublicKeyLookup { client }
            .lookup(Uri::new(alleged_iss).unwrap(), &header)
            .await
            .unwrap();

        assert_eq!(
            response.get("kid").unwrap().as_str().unwrap(),
            header.kid.unwrap()
        );
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.1-1
    #[tokio::test]
    async fn iss_scheme_not_http() {
        let alleged_iss = "git://example.com";

        let client = StubClient {
            expected_url: None,
            response: response_with_metadata(example_metadata()),
        };

        let response = HttpsIssuerPublicKeyLookup { client }
            .lookup(Uri::new(alleged_iss).unwrap(), &example_header())
            .await;

        assert_eq!(
            response.unwrap_err().error,
            LookupError("iss uri scheme should be https".to_string())
        );
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5-2
    #[tokio::test]
    async fn iss_contains_query() {
        let alleged_iss = "https://example.com/issuer?name=issue";

        let client = StubClient {
            expected_url: None,
            response: response_with_metadata(example_metadata()),
        };

        let response = HttpsIssuerPublicKeyLookup { client }
            .lookup(Uri::new(alleged_iss).unwrap(), &example_header())
            .await;

        assert_eq!(
            response.unwrap_err().error,
            LookupError("iss uri should not contain query or fragment parts".to_string())
        );
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5-2
    #[tokio::test]
    async fn iss_contains_fragment() {
        let alleged_iss = "https://example.com/issuer#nose";

        let client = StubClient {
            expected_url: None,
            response: response_with_metadata(example_metadata()),
        };

        let response = HttpsIssuerPublicKeyLookup { client }
            .lookup(Uri::new(alleged_iss).unwrap(), &example_header())
            .await;

        assert_eq!(
            response.unwrap_err().error,
            LookupError("iss uri should not contain query or fragment parts".to_string())
        );
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.2-1
    #[tokio::test]
    async fn response_wrong_status_code() {
        let alleged_iss = "https://example.com";

        let client = StubClient {
            expected_url: Some("https://example.com/.well-known/jwt-vc-issuer".to_string()),
            response: http::Response::builder()
                .status(201)
                .body("".to_string())
                .unwrap(),
        };

        let response = HttpsIssuerPublicKeyLookup { client }
            .lookup(Uri::new(alleged_iss).unwrap(), &example_header())
            .await;

        assert_eq!(
            response.unwrap_err().error,
            LookupError("response status code was 201 Created, expected 200 OK".to_string())
        );
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.2-1
    #[tokio::test]
    async fn response_wrong_content_type() {
        let alleged_iss = "https://example.com";

        let client = StubClient {
            expected_url: Some("https://example.com/.well-known/jwt-vc-issuer".to_string()),
            response: http::Response::builder()
                .status(200)
                .header("Content-type", "text/html")
                .body("".to_string())
                .unwrap(),
        };

        let response = HttpsIssuerPublicKeyLookup { client }
            .lookup(Uri::new(alleged_iss).unwrap(), &example_header())
            .await;

        assert_eq!(
            response.unwrap_err().error,
            LookupError(
                "response content type was text/html, expected application/json".to_string()
            )
        );
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.3-1
    #[tokio::test]
    async fn metadata_issuer_value_not_identical_to_iss() {
        let alleged_iss = "https://example.com/tenant";

        let client = StubClient {
            expected_url: Some("https://example.com/.well-known/jwt-vc-issuer/tenant".to_string()),
            response: response_with_metadata(example_metadata()),
        };

        let response = HttpsIssuerPublicKeyLookup { client }
            .lookup(Uri::new(alleged_iss).unwrap(), &example_header())
            .await;

        assert_eq!(
            response.unwrap_err().error,
            LookupError("response issuer value was not identical to iss value of JWT".to_string())
        );
    }

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-03#section-5.2-6
    #[tokio::test]
    async fn multiple_jwks_in_metadata() {
        let alleged_iss = "https://example.com";

        let metadata = json!({
           "issuer": alleged_iss,
           "jwks":{
              "keys":[
                 {"kid": "kid1"},
                 {"kid": "kid2"},
                 {"kid": "kid3"}
              ],
           }
        });

        let client = StubClient {
            expected_url: Some("https://example.com/.well-known/jwt-vc-issuer".to_string()),
            response: response_with_metadata(metadata),
        };
        let mut header = example_header();
        header.kid = Some("kid2".to_string());

        let response = HttpsIssuerPublicKeyLookup { client }
            .lookup(Uri::new(alleged_iss).unwrap(), &header)
            .await
            .unwrap();

        assert_eq!(
            response.get("kid").unwrap().as_str().unwrap(),
            header.kid.unwrap()
        );
    }

    #[test]
    fn issuer_metadata_contains_both_jwks_and_jwks_uri() {
        let metadata = json!({
           "issuer": "issuer",
           "jwks":{
              "keys":[
                 {"kid": "kid1"},
              ],
           },
           "jwks_uri": "https://jwt-vc-issuer.example.org/my_public_keys.jwks"
        });

        let err = serde_json::from_str::<JwtVcIssuerMetadata>(metadata.to_string().as_str());

        assert_eq!(
            err.unwrap_err().to_string(),
            "`jwks` and `jwks_uri` are mutually exclusive"
        );
    }

    #[test]
    fn issuer_metadata_serialization() {
        let metadata = example_metadata();

        let deserialized =
            serde_json::from_str::<JwtVcIssuerMetadata>(metadata.to_string().as_str()).unwrap();

        assert_eq!(deserialized.issuer, "https://example.com".to_string());
        assert_eq!(
            deserialized
                .jwks_param
                .to_jwks()
                .keys
                .first()
                .unwrap()
                .get("kid")
                .unwrap(),
            &Value::String("doc-signer-05-25-2022".to_string())
        );
        assert_eq!(
            serde_json::to_string(&deserialized).unwrap(),
            example_metadata().to_string()
        );
    }

    #[test]
    fn issuer_metadata_serialization_jwks_uri() {
        let metadata = example_metadata_with_jwks_uri();

        let deserialized =
            serde_json::from_str::<JwtVcIssuerMetadata>(metadata.to_string().as_str()).unwrap();

        assert_eq!(deserialized.issuer, "https://example.com".to_string());
        assert_eq!(
            deserialized.jwks_param.to_jwks_uri(),
            "https://jwt-vc-issuer.example.org/my_public_keys.jwks"
        );
        assert_eq!(
            serde_json::to_string(&deserialized).unwrap(),
            example_metadata_with_jwks_uri().to_string()
        );
    }

    #[test]
    fn test_metadata_uri_from_iss() {
        let iss = Uri::new("http://example.com/path").unwrap();

        let url = metadata_uri_from_iss(iss);

        assert_eq!(url, "http://example.com/.well-known/jwt-vc-issuer/path");
    }

    #[test]
    fn test_metadata_uri_from_iss_trailing_slash() {
        let iss = Uri::new("http://example.com/path/").unwrap();

        let url = metadata_uri_from_iss(iss);

        assert_eq!(url, "http://example.com/.well-known/jwt-vc-issuer/path/");
    }

    #[test]
    fn test_metadata_uri_from_iss_no_path() {
        let iss = Uri::new("http://example.com").unwrap();

        let url = metadata_uri_from_iss(iss);

        assert_eq!(url, "http://example.com/.well-known/jwt-vc-issuer");
    }

    #[test]
    fn test_metadata_uri_from_iss_no_path_trailing_slash() {
        let iss = Uri::new("http://example.com/").unwrap();

        let url = metadata_uri_from_iss(iss);

        assert_eq!(url, "http://example.com/.well-known/jwt-vc-issuer");
    }

    /// Returns a dummy [`bhx5chain::X5Chain`] for testing purposes.
    fn dummy_x5chain() -> bhx5chain::X5Chain {
        let cert = "-----BEGIN CERTIFICATE-----
MIIBqDCCAU+gAwIBAgIUa3Ph3O2ChLkG2WGly2OlOA2oB/gwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGJ0bDAeFw0yNTEwMTQxMTI3NDhaFw0zNTEwMTIxMTI3NDha
MA8xDTALBgNVBAMMBHRidGwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARh62Ff
2AR3vJQJFb1N/N5qQwUCIcYpc82B5wckfSlYTD9Z7or8/DHS8fl0Tx84QUSCq1j5
EoXAsa6WyWwH/Oo9o4GIMIGFMB0GA1UdDgQWBBQcHDN+Jn8uxxWyWsvidMXsxux7
ZTAfBgNVHSMEGDAWgBQcHDN+Jn8uxxWyWsvidMXsxux7ZTAPBgNVHRMBAf8EBTAD
AQH/MDIGA1UdEQQrMCmCC2V4YW1wbGUuY29thwQKAAABhhRodHRwczovL3d3dy50
YnRsLm5ldDAKBggqhkjOPQQDAgNHADBEAiAo1LhKVWisYrzCR02qweeOQaJOaEAZ
UGok7hT15f+X6wIgHQ5uUck3v4W0PxZyVL1dd6tZM3gPcmD/yR25VcbrADY=
-----END CERTIFICATE-----";

        let cert = X509::from_pem(cert.as_bytes()).unwrap();
        bhx5chain::X5Chain::new(vec![cert]).unwrap()
    }

    /// Returns a dummy [`bhx5chain::JwtX5Chain`] for testing purposes.
    fn dummy_jwt_x5chain() -> bhx5chain::JwtX5Chain {
        dummy_x5chain().try_into().unwrap()
    }

    /// Returns a root certificate for the dummy X.509 certificate chain.
    ///
    /// This will serve as a root for the certificate chains returned by the
    /// [`dummy_x5chain`] and [`dummy_jwt_x5chain`] functions.
    fn dummy_root_certificate() -> X509 {
        dummy_x5chain().leaf_certificate().to_owned()
    }

    #[tokio::test]
    async fn test_public_key_from_x5chain() {
        let x5chain = dummy_x5chain();
        let jwt_x5chain = dummy_jwt_x5chain();

        // NB: `iss` does not matter for `x5c`-based public key lookup anymore
        let alleged_iss = "https://example.com";
        let header = example_header_with_x5c(jwt_x5chain.clone());

        let public_jwk = X5ChainIssuerPublicKeyLookup::trust_all()
            .lookup(alleged_iss, &header)
            .await
            .unwrap();

        assert_eq!(
            public_jwk_from_x5chain_leaf(&x5chain, &header.alg, header.kid.as_deref()).unwrap(),
            public_jwk
        );
    }

    #[tokio::test]
    async fn test_public_key_from_x5chain_missing_header_field() {
        let alleged_iss = "https://example.com";
        let header = example_header();

        let err = X5ChainIssuerPublicKeyLookup::trust_all()
            .lookup(alleged_iss, &header)
            .await
            .unwrap_err()
            .error;

        assert!(matches!(err, LookupError(msg) if msg == "missing 'x5c' jwt header"));
    }

    #[tokio::test]
    async fn test_public_key_from_x5chain_verify_authenticity() {
        let x5chain = dummy_x5chain();
        let jwt_x5chain = dummy_jwt_x5chain();

        let alleged_iss = "https://example.com";
        let header = example_header_with_x5c(jwt_x5chain.clone());

        // Issuer authenticity verified
        let trust = X509Trust::new(vec![dummy_root_certificate()]);
        let public_jwk = X5ChainIssuerPublicKeyLookup::with_trust(trust)
            .lookup(alleged_iss, &header)
            .await
            .unwrap();
        assert_eq!(
            public_jwk_from_x5chain_leaf(&x5chain, &header.alg, header.kid.as_deref()).unwrap(),
            public_jwk
        );

        // no Issuer is trusted (empty `trust`)
        let trust = X509Trust::new(vec![]);
        let err = X5ChainIssuerPublicKeyLookup::with_trust(trust)
            .lookup(alleged_iss, &header)
            .await
            .unwrap_err();
        assert!(
            matches!(err.error, LookupError(msg) if msg == "x5chain does not verify against trusted roots")
        );

        // every Issuer is trusted (`trust` not provided)
        let public_jwk = X5ChainIssuerPublicKeyLookup::trust_all()
            .lookup(alleged_iss, &header)
            .await
            .unwrap();
        assert_eq!(
            public_jwk_from_x5chain_leaf(&x5chain, &header.alg, header.kid.as_deref()).unwrap(),
            public_jwk
        );
    }

    #[tokio::test]
    async fn test_verify_issued_sd_jwt_happy_path() {
        let issued_sd_jwt = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6Imlzc3VlciBraWQiLCJ4NWMiOlsiTUlJQjlEQ0NBWnFnQXdJQkFnSVVXZmFXV0FtK2kvbWRQR2luY25RQjR4NHROb013Q2dZSUtvWkl6ajBFQXdJd2F6RUxNQWtHQTFVRUJoTUNTRkl4RkRBU0JnTlZCQWdNQzBkeVlXUWdXbUZuY21WaU1ROHdEUVlEVlFRSERBWmFZV2R5WldJeERUQUxCZ05WQkFvTUJGUkNWRXd4RVRBUEJnTlZCQXNNQ0ZSbFlXMGdRbVZsTVJNd0VRWURWUVFEREFwamIyTnZiblYwTFdOaE1CNFhEVEkxTURNd05ERXpNekV4TmxvWERUTTFNRE13TWpFek16RXhObG93RWpFUU1BNEdBMVVFQXd3SFkyOWpiMjUxZERCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQkREamhLOVlHc1ZvWmpxZlRYbldYTnFneCt6NlZTUkJnU3RUb1dFZ3N4R2V3UWhVMkNaYXBqK0ZwempLY1phd0RIRlovaHY5NUMxQnEwTW02U2V3RitxamRUQnpNQWtHQTFVZEV3UUNNQUF3RGdZRFZSMFBBUUgvQkFRREFnYkFNQjBHQTFVZERnUVdCQlE5Z1NxNEdxekVISTlVbTRFbitndDVYNkYxdERBZkJnTlZIU01FR0RBV2dCVFZIYjlKV25iMmR4Q2ZDME16b21tckxndEdlVEFXQmdOVkhSRUVEekFOZ2d0bGVHRnRjR3hsTG1OdmJUQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpRUE5QXhoeTRTVFJQUmNSY2w1eVRxYXp6QU1WaU0wbUhHWVg0YWUvZjJTY3FvQ0lCTkR5R3lsMTJ1Z2hpaStZdkt5VUt2dTdYVUR1cllWQjJIY0pMUTNuem5YIiwiTUlJQ09qQ0NBZUNnQXdJQkFnSVVON295UHd4cUxlMnhETUxqRHZhMEhxcUtEWHd3Q2dZSUtvWkl6ajBFQXdJd1pURUxNQWtHQTFVRUJoTUNTRkl4RkRBU0JnTlZCQWdNQzBkeVlXUWdXbUZuY21WaU1ROHdEUVlEVlFRSERBWmFZV2R5WldJeERUQUxCZ05WQkFvTUJGUkNWRXd4RVRBUEJnTlZCQXNNQ0ZSbFlXMGdRbVZsTVEwd0N3WURWUVFEREFSeWIyOTBNQ0FYRFRJME1USXhNREV5TWpRek5Wb1lEekl4TWpReE1URTJNVEl5TkRNMVdqQnJNUXN3Q1FZRFZRUUdFd0pJVWpFVU1CSUdBMVVFQ0F3TFIzSmhaQ0JhWVdkeVpXSXhEekFOQmdOVkJBY01CbHBoWjNKbFlqRU5NQXNHQTFVRUNnd0VWRUpVVERFUk1BOEdBMVVFQ3d3SVZHVmhiU0JDWldVeEV6QVJCZ05WQkFNTUNtTnZZMjl1ZFhRdFkyRXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBUWRSR2ErMk9IaWFXYVIzK1JKNjNoR0VZV0I0aWpVdTdGcGhpSUNETjBKL2Z4QkJOOEUzVS9jdFQzZU1TcTVTeVBZTXZFbXMyS01PeER5a3ZnNkloRmdvMll3WkRBZEJnTlZIUTRFRmdRVTFSMi9TVnAyOW5jUW53dERNNkpwcXk0TFJua3dId1lEVlIwakJCZ3dGb0FVSm5iemROUERKVFd3SURCLzJsYmw3ampYazkwd0VnWURWUjBUQVFIL0JBZ3dCZ0VCL3dJQkFEQU9CZ05WSFE4QkFmOEVCQU1DQVlZd0NnWUlLb1pJemowRUF3SURTQUF3UlFJaEFOYTJ1V3VhV0wvZGZ0QkZSM3ArWldKaDdYNWpXRUFhNlZ0TXBtRWE2ZlRiQWlCNU45Nk4yckNJYjRnaUdPODZZUUJQb1dTUkE2UWovYmFiS25pQVlzSkxxUT09Il19.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsImV4cCI6MTg4MzAwMDAwMCwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImFsZyI6IkVTMjU2IiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiT3d2dDhKUEpPRHFfRG9zVkRUQllsR2RGOUk1UGM0TENNOERvLVlCd0xjUSIsInkiOiIyM3V6VVlrZlh4RV95M3hybFQyM1ZCSUNyUmczOVQ3N1dHQUVvLXB5ZE1JIiwia2lkIjoiaG9sZGVyIGtpZCJ9fSwidmN0IjoiaHR0cHM6Ly9ibWkuYnVuZC5leGFtcGxlL2NyZWRlbnRpYWwvcGlkLzEuMCIsIl9zZF9hbGciOiJzaGEtMjU2IiwiaWF0IjoxNjgzMDAwMDAwLCJhZ2VfZXF1YWxfb3Jfb3ZlciI6eyJfc2QiOlsiem5VT0NOdUM1SDZJcWt1SnhJa2FIZ2JOU1NTVXhXczk4MmZFeW1iNGFtWSIsIldVb194ZUhpQTk1aE1jMHZSUXdLbThCM1Z3bHEyVUJkRHZBOTNpWDBLeDQiLCJOVXFjekZpYVdNbGtTWWNCVmNqSHNhR2Q1dTVRc3d4cWEwQjhiS0diMTZVIiwiUEhERWhucXZTQ3FvMlRITXoyS0pTLXdnYkRteWIwVHRYaUlfb0I0Y1ZwZyIsImRmbXdNTDJCdHVycDJBdmFXYmh1ME5hZ1E4eXJ2c3J1XzJpYXIzYVp5b1EiLCJaVlMtdDNHWm5ETVhJUm0yZmdWU1RaNDhlMGZ4OWxldVZvQTB5RElGcHcwIl19LCJfc2QiOlsiU1I3X0hvYi1zR216cFBlMDAtSXFSclYzUC1OeWVHaTl4d3ZTU2JnQ2RDSSIsImE3cmdNVHRSaWVvT0xYWGVGbWdnT25XSS1VQnhCUDVKVXlHTW85ZW14eUUiLCJ6MjAtckZIVmpvOXEySWtZZFZGUzdCTlpTeDJkZzRiSVRaYWdXYWk3Y1AwIiwiNWZmRXFZZUtvOENpUVh1Q0NPQWRwNno4X3c4MXdjWnp4MW94Ym1yRzZ5USIsIkJ4cUtpdG9UZjVQNDF1X1Y1OEdCcjR0Q1FhSGZjLUh1dDJWb0VENUlEVGciLCJ4NUZjVWIwYnFTZkNsWGo0b1BuUmxXMHRqemh4dkRNNk9sNGs3VWotQzc4IiwiT2g1Q3ZUbmFaRVFqSTE4Z0dRLXZKeFZXQW9wXzdwMnd0NTZtNTRydFYzNCIsImZhTTNERUFCNml5OVJyTnJjNmFXQ25tSENjZkt0aWh3RHY3MWZYUzA4ZDgiLCJfUWxnUERQSkdsY1ZpQXNlY0lYV0JheTB4bGE5MTN1X3U3R0RSWEowZEJrIiwiRVQxUmlFc2xvci1ab1dGS2hrYmpnX2dRdFprZmhQbThNTTJyT1VJLV9DWSJdfQ.yJfwSCKETHZy740Mg2Yk2qDW-rQcqmbdMfUYq8c9wvBAj_d2cssuxBiYA_Fl9tkX33J3UL9JzwdqCm3pq3pjAA~WyIwUDAwV2RhVmx3NHFuY0l3V0tiYTNRIiwgIjY1IiwgZmFsc2Vd~WyJhdGhfRkFMTDVqbEFrX3p2R2lxUGNnIiwgIjIxIiwgdHJ1ZV0~WyJOcEpwM1Q1RlR4SGR5MTk2UnBuUWh3IiwgIjE4IiwgdHJ1ZV0~WyJybW9OQ0NSSGZ3UUNxNmpfcHVpRE5nIiwgIjE2IiwgdHJ1ZV0~WyJGbTJyYkxrVlRoQTFlb2UwZFdxclpnIiwgIjE0IiwgdHJ1ZV0~WyJSbGdndGZyUTBoNHVtSmpKd1B2ekhnIiwgIjEyIiwgdHJ1ZV0~WyJBQk9yWkNIUGxXdlFDMFVQNkdISEp3IiwgImxvY2FsaXR5IiwgIkJlcmxpbiJd~WyI2bE1PME1QMVFsMG5RU2JJU2hRcVBnIiwgImNvdW50cnkiLCAiREUiXQ~WyJfWVNmbWRZZWdyR1R5aTVBc2ZjYXJBIiwgInBvc3RhbF9jb2RlIiwgIjUxMTQ3Il0~WyJvVC1rVFZMWm1aejk4Q1RvdnBsOTdBIiwgImxvY2FsaXR5IiwgIkvDtmxuIl0~WyJzdVJQRWNQdm5ha25vRldJdTdDNFp3IiwgInN0cmVldF9hZGRyZXNzIiwgIkhlaWRlc3RyYcOfZSAxNyJd~WyJVRlJSMmZ3OURia01McUQ2Q3VibGJBIiwgImFsc29fa25vd25fYXMiLCAiU2Nod2VzdGVyIEFnbmVzIl0~WyJTaWczZXJmX191aGo3WnJEcTdhM0VBIiwgInBsYWNlX29mX2JpcnRoIiwgeyJjb3VudHJ5IjoiREUiLCJfc2QiOlsib1ZZNWgxbDZpR0hpb1h0Z3NLV29UTTFtSEU5TDY3dzFqWmNuZXZYbi1hTSJdfV0~WyJyektQOXVsZWExS2M4MUhZdG5Nb1JnIiwgImJpcnRoX2ZhbWlseV9uYW1lIiwgIkdhYmxlciJd~WyJkejRoM1YyVzJGY1RmWllIMHo2aGdRIiwgImdlbmRlciIsICJmZW1hbGUiXQ~WyJNdFdkMXRHc2VYaEVhN1NscDJ0U1B3IiwgIm5hdGlvbmFsaXRpZXMiLCBbIkRFIl1d~WyJVOWNfeGVONFk3bURrZUdlM2c5UV9RIiwgImFkZHJlc3MiLCB7Il9zZCI6WyJJT0NvUGRCekljNGEzZFBRN0d5SjN3cjRSSjhVZjUtMzhPNWJaclZlbGhrIiwiNkI5WUNRc18xY25HaXNPQVJsNUVrZXRLZUxSZFpPd3MwZzM0OEdfYnRKWSIsIlVaUjVXQ0RHcU1VTG9OZElxVWlLWkptMTVfTUVZekZQTGNlLTB3c1hfR1UiLCJKdlVuRHpIM210SDVrZVhKMXBXVnFVdGplREh1YVNXdF9kU3ZXTmw4SUFrIl19XQ~WyJRWFAtalFtRFZyNlc2aWM5MENOeml3IiwgInNvdXJjZV9kb2N1bWVudF90eXBlIiwgImlkX2NhcmQiXQ~WyJDOU5vN1RNVXpOVjdFSGJXQjV1NW5RIiwgImJpcnRoZGF0ZSIsICIxOTYzLTA4LTEyIl0~WyJGUXpIN3ExczROSUVydWFEaHNmc2xnIiwgImZhbWlseV9uYW1lIiwgIk11c3Rlcm1hbm4iXQ~WyJrUEdPcHRuTkt1QkZSSEpaMXZsMGhnIiwgImdpdmVuX25hbWUiLCAiRXJpa2EiXQ~";

        Holder::verify_issued(
            issued_sd_jwt,
            &X5ChainIssuerPublicKeyLookup::trust_all(),
            |alg| (alg == HashingAlgorithm::Sha256).then_some(Box::new(Sha256)),
            |alg| (alg == SigningAlgorithm::Es256).then_some(&Es256Verifier),
            HOLDER_ACCEPT_TIME,
        )
        .await
        .unwrap();
    }
}
