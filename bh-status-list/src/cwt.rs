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

use std::collections::BTreeMap;

use bh_jws_utils::{JwkPublic, SignatureVerifier, SigningAlgorithm};
use bherror::traits::{ForeignBoxed as _, ForeignError as _};
use coset::{
    cbor::value::Value,
    iana::{self, CwtClaimName, EnumI64 as _},
    Algorithm, AsCborValue as _, CborSerializable as _, CoseSign1, Header, Label,
    TaggedCborSerializable as _,
};
use iref::Uri;

use crate::{
    verified::{validate_numeric_dates, validate_optional_claims, validate_subject},
    Error, Result, StatusBits, StatusList, UriBuf, VerifiedStatusList, STATUS_LIST_CWT_MEDIA_TYPE,
};

const TYPE_HEADER: Label = Label::Int(16);
const X5CHAIN_HEADER: Label = Label::Int(iana::HeaderParameter::X5Chain as i64);
const COAP_CONTENT_FORMAT: i128 = 279;
const STATUS_LIST_CLAIM: Label = Label::Int(65533);
const TTL_CLAIM: Label = Label::Int(65534);

/// A parsed, unverified CWT Status List Token using tagged COSE_Sign1.
///
/// Header values can be used as hints to resolve a signing key. Verify with a
/// public key authorized for the credential's Status List before using any claims.
pub struct CwtStatusListToken {
    message: CoseSign1,
    algorithm: SigningAlgorithm,
}

impl CwtStatusListToken {
    /// Parses a tagged COSE_Sign1 and validates its protected type and algorithm.
    ///
    /// Use the parsed header for key resolution, then call [`Self::verify`]
    /// on this value once the signing key is authorized.
    pub fn parse(token: &[u8]) -> Result<Self> {
        let message =
            CoseSign1::from_tagged_slice(token).foreign_err(|| Error::TokenParsingFailed)?;
        if message.payload.is_none() {
            return Err(bherror::Error::root(Error::TokenParsingFailed).ctx("missing CWT payload"));
        }
        let protected = &message.protected.header;
        let unprotected = &message.unprotected;
        validate_headers(protected, unprotected)?;
        let algorithm = match protected.alg {
            Some(Algorithm::Assigned(iana::Algorithm::ES256)) => SigningAlgorithm::Es256,
            Some(Algorithm::Assigned(iana::Algorithm::ES384)) => SigningAlgorithm::Es384,
            Some(Algorithm::Assigned(iana::Algorithm::ES512)) => SigningAlgorithm::Es512,
            Some(Algorithm::Assigned(iana::Algorithm::PS256)) => SigningAlgorithm::Ps256,
            Some(Algorithm::Assigned(iana::Algorithm::PS384)) => SigningAlgorithm::Ps384,
            Some(Algorithm::Assigned(iana::Algorithm::PS512)) => SigningAlgorithm::Ps512,
            _ => return Err(invalid_header("missing or unsupported protected algorithm")),
        };

        Ok(Self { message, algorithm })
    }

    /// The signature algorithm advertised in the protected header.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// The optional key identifier advertised by the token as bytes.
    pub fn key_id(&self) -> Option<&[u8]> {
        let id = &self.message.protected.header.key_id;
        let id = if id.is_empty() {
            &self.message.unprotected.key_id
        } else {
            id
        };
        (!id.is_empty()).then_some(id.as_slice())
    }

    /// Returns the optional COSE `x5chain` certificate bytes in wire order.
    ///
    /// The caller must establish chain trust and authorize the leaf for the
    /// Status List. An unprotected chain is a key hint.
    pub fn x5chain(&self) -> Result<Option<Vec<&[u8]>>> {
        let value = header_value(&self.message.protected.header, &X5CHAIN_HEADER)
            .or_else(|| header_value(&self.message.unprotected, &X5CHAIN_HEADER));
        let Some(value) = value else {
            return Ok(None);
        };
        let certs = match value {
            Value::Bytes(cert) => vec![cert.as_slice()],
            Value::Array(certs) if certs.len() > 1 => certs
                .iter()
                .map(|cert| {
                    cert.as_bytes()
                        .map(Vec::as_slice)
                        .ok_or_else(|| invalid_header("x5chain must contain byte strings"))
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(invalid_header("invalid COSE x5chain")),
        };
        Ok(Some(certs))
    }

    /// Verifies the signature and claims against the expected Status List URI.
    ///
    /// The caller supplies an authorized public key and a verifier for the
    /// allowed algorithm. Pass Unix time in seconds and the URI from the
    /// verified credential. The signature is checked before decoding the list
    /// claims and decompressing the list.
    pub fn verify(
        &self,
        verifier: &(impl SignatureVerifier + ?Sized),
        public_key: &JwkPublic,
        current_time: u64,
        sub: &Uri,
    ) -> Result<VerifiedStatusList> {
        if verifier.algorithm() != self.algorithm {
            return Err(
                bherror::Error::root(Error::TokenSignatureVerificationFailed)
                    .ctx("COSE signature algorithm does not match the verifier"),
            );
        }
        self.message.verify_signature(&[], |signature, message| {
            if verifier
                .verify(message, signature, public_key)
                .foreign_boxed_err(|| Error::TokenSignatureVerificationFailed)?
            {
                Ok(())
            } else {
                Err(bherror::Error::root(
                    Error::TokenSignatureVerificationFailed,
                ))
            }
        })?;
        let payload = self
            .message
            .payload
            .as_deref()
            .ok_or_else(|| bherror::Error::root(Error::TokenParsingFailed))?;
        verify_claims(payload, current_time, sub)
    }
}

fn validate_headers(protected: &Header, unprotected: &Header) -> Result<()> {
    let valid_type = match header_value(protected, &TYPE_HEADER) {
        Some(Value::Text(typ)) => typ == STATUS_LIST_CWT_MEDIA_TYPE,
        Some(Value::Integer(typ)) => i128::from(*typ) == COAP_CONTENT_FORMAT,
        _ => false,
    };
    if !valid_type || header_value(unprotected, &TYPE_HEADER).is_some() {
        return Err(invalid_header("expected a protected COSE Status List type"));
    }

    if !unprotected.crit.is_empty()
        || protected
            .crit
            .iter()
            .any(|label| *label != coset::RegisteredLabel::Assigned(iana::HeaderParameter::Alg))
    {
        return Err(invalid_header("unsupported COSE critical header"));
    }

    // Compare complete label sets, including registered headers represented
    // as fields by coset and extension headers stored in Header::rest.
    let protected = header_map(protected)?;
    let unprotected = header_map(unprotected)?;
    if protected
        .keys()
        .any(|label| unprotected.contains_key(label))
    {
        return Err(invalid_header("COSE header occurs in both header buckets"));
    }
    Ok(())
}

fn invalid_header(context: &'static str) -> bherror::Error<Error> {
    bherror::Error::root(Error::InvalidTokenHeader).ctx(context)
}

fn header_value<'a>(header: &'a Header, label: &Label) -> Option<&'a Value> {
    header
        .rest
        .iter()
        .find_map(|(key, value)| (key == label).then_some(value))
}

fn header_map(header: &Header) -> Result<BTreeMap<Label, Value>> {
    let value = header
        .clone()
        .to_cbor_value()
        .foreign_err(|| Error::InvalidTokenHeader)?;
    cbor_map(value)
}

fn verify_claims(
    payload: &[u8],
    current_time: u64,
    expected_sub: &Uri,
) -> Result<VerifiedStatusList> {
    let mut claims =
        cbor_map(Value::from_slice(payload).foreign_err(|| Error::InvalidTokenClaims)?)?;
    let iss = claims
        .remove(&claim_label(CwtClaimName::Iss))
        .map(text)
        .transpose()?;
    let sub = required(claims.remove(&claim_label(CwtClaimName::Sub)), "sub").and_then(uri)?;
    let exp = claims
        .remove(&claim_label(CwtClaimName::Exp))
        .map(numeric_date)
        .transpose()?;
    let nbf = claims
        .remove(&claim_label(CwtClaimName::Nbf))
        .map(numeric_date)
        .transpose()?;
    let iat =
        required(claims.remove(&claim_label(CwtClaimName::Iat)), "iat").and_then(numeric_date)?;
    if claims
        .remove(&claim_label(CwtClaimName::Cti))
        .is_some_and(|id| !id.is_bytes())
    {
        return Err(invalid_claim("cti must be a byte string"));
    }
    let ttl = claims.remove(&TTL_CLAIM).map(unsigned).transpose()?;
    validate_subject(&sub, expected_sub)?;
    validate_optional_claims(
        iss.as_deref(),
        ttl,
        claims.contains_key(&claim_label(CwtClaimName::Aud)),
    )?;
    validate_numeric_dates(current_time, iat, exp, nbf)?;

    let mut list = cbor_map(required(claims.remove(&STATUS_LIST_CLAIM), "status_list")?)?;
    let bits = required(list.remove(&Label::Text("bits".into())), "bits").and_then(unsigned)?;
    let bits = u8::try_from(bits)
        .ok()
        .and_then(StatusBits::from_u8)
        .ok_or_else(|| invalid_claim("invalid bits"))?;
    let lst = required(list.remove(&Label::Text("lst".into())), "lst")?
        .into_bytes()
        .map_err(|_| invalid_claim("lst must be a byte string"))?;
    let aggregation_uri = list
        .remove(&Label::Text("aggregation_uri".into()))
        .map(uri)
        .transpose()?;
    Ok(VerifiedStatusList {
        iss,
        sub,
        iat,
        exp,
        ttl,
        status_list: StatusList::from_compressed(bits, lst, aggregation_uri)?,
    })
}

fn claim_label(name: CwtClaimName) -> Label {
    Label::Int(name.to_i64())
}

fn cbor_map(value: Value) -> Result<BTreeMap<Label, Value>> {
    let entries = value
        .into_map()
        .map_err(|_| invalid_claim("expected a CBOR map"))?;
    let mut map = BTreeMap::new();
    for (label, value) in entries {
        let label = Label::from_cbor_value(label).foreign_err(|| Error::InvalidTokenClaims)?;
        if map.insert(label, value).is_some() {
            return Err(invalid_claim("duplicate CBOR map key"));
        }
    }
    Ok(map)
}

fn invalid_claim(context: &'static str) -> bherror::Error<Error> {
    bherror::Error::root(Error::InvalidTokenClaims).ctx(context)
}

fn required(value: Option<Value>, name: &'static str) -> Result<Value> {
    value.ok_or_else(|| {
        bherror::Error::root(Error::InvalidTokenClaims).ctx(format!("missing {name}"))
    })
}

fn text(value: Value) -> Result<String> {
    value
        .into_text()
        .map_err(|_| invalid_claim("expected a CBOR text string"))
}

fn uri(value: Value) -> Result<UriBuf> {
    text(value)?
        .parse()
        .foreign_err(|| Error::InvalidTokenClaims)
}

fn unsigned(value: Value) -> Result<u64> {
    value
        .as_integer()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| invalid_claim("expected a CBOR unsigned integer"))
}

fn numeric_date(value: Value) -> Result<f64> {
    match value {
        Value::Integer(value) => Ok(i128::from(value) as f64),
        Value::Float(value) => Ok(value),
        _ => Err(invalid_claim("expected a NumericDate")),
    }
}

#[cfg(test)]
mod tests {
    use bh_jws_utils::{Es256Signer, Es256Verifier, Signer as _};
    use coset::{CoseSign1Builder, HeaderBuilder};

    use super::*;
    use crate::{StatusClaim, StatusListResponse};

    const URI: &str = "https://example.com/statuslists/1";

    fn claims() -> Vec<(Value, Value)> {
        vec![
            (2.into(), Value::Text(URI.into())),
            (4.into(), 200.into()),
            (6.into(), Value::Float(100.25)),
            (65534.into(), 300.into()),
            (
                65533.into(),
                Value::Map(vec![
                    (Value::Text("bits".into()), 1.into()),
                    (
                        Value::Text("lst".into()),
                        Value::Bytes(vec![0x78, 0xda, 0xdb, 0xb9, 0x18, 0, 2, 0x17, 1, 0x5d]),
                    ),
                ]),
            ),
        ]
    }

    fn token(
        signer: &Es256Signer,
        claims: Vec<(Value, Value)>,
        protected_type: Option<Value>,
        unprotected_type: Option<Value>,
    ) -> CoseSign1 {
        let mut protected = HeaderBuilder::new().algorithm(iana::Algorithm::ES256);
        let mut unprotected = HeaderBuilder::new().key_id(b"12".to_vec());
        if let Some(typ) = protected_type {
            protected = protected.value(16, typ);
        }
        if let Some(typ) = unprotected_type {
            unprotected = unprotected.value(16, typ);
        }
        CoseSign1Builder::new()
            .protected(protected.build())
            .unprotected(unprotected.build())
            .payload(Value::Map(claims).to_vec().unwrap())
            .create_signature(&[], |message| signer.sign(message).unwrap())
            .build()
    }

    #[test]
    fn verifies_signed_cwt_for_both_protected_types() {
        let signer = Es256Signer::generate("12".into()).unwrap();
        let key = signer.public_jwk().unwrap();
        let uri = URI.parse::<UriBuf>().unwrap();
        for typ in [
            Value::Text(STATUS_LIST_CWT_MEDIA_TYPE.into()),
            Value::from(COAP_CONTENT_FORMAT as u16),
        ] {
            let encoded = token(&signer, claims(), Some(typ), None)
                .to_tagged_vec()
                .unwrap();
            let response = StatusListResponse::Cwt(encoded);
            let parsed = response.parse().unwrap();
            assert_eq!(parsed.algorithm(), SigningAlgorithm::Es256);
            assert_eq!(parsed.key_id(), Some(b"12".as_slice()));
            assert!(parsed.jwt_header().is_none());
            assert!(parsed.cwt_token().is_some());

            let verified = parsed.verify(&Es256Verifier, &key, 100, &uri).unwrap();
            assert_eq!(verified.issuer(), None);
            assert_eq!(verified.issued_at(), 100.25);
            assert_eq!(verified.expires_at(), Some(200.0));
            assert_eq!(verified.ttl(), Some(300));
            assert_eq!(
                verified.status(&StatusClaim::new(uri.clone(), 0)).unwrap(),
                1
            );
            assert_eq!(
                verified.status(&StatusClaim::new(uri.clone(), 1)).unwrap(),
                0
            );
            let error = verified
                .status(&StatusClaim::new(uri.clone(), 16))
                .unwrap_err();
            assert!(matches!(error.error, Error::IndexOutOfBounds(16, 16)));
        }
    }

    #[test]
    fn exposes_x5chain_bytes_in_wire_order() {
        let signer = Es256Signer::generate("12".into()).unwrap();
        let typ = Value::Text(STATUS_LIST_CWT_MEDIA_TYPE.into());
        let mut message = token(&signer, claims(), Some(typ), None);
        message.unprotected.rest.push((
            X5CHAIN_HEADER,
            Value::Array(vec![Value::Bytes(vec![0x01]), Value::Bytes(vec![0x02])]),
        ));
        let encoded = message.to_tagged_vec().unwrap();
        let parsed = CwtStatusListToken::parse(&encoded).unwrap();
        assert_eq!(
            parsed.x5chain().unwrap(),
            Some(vec![&[0x01][..], &[0x02][..]])
        );
    }

    #[test]
    fn rejects_invalid_cwt_envelopes_and_signatures() {
        let signer = Es256Signer::generate("12".into()).unwrap();
        let key = signer.public_jwk().unwrap();
        let uri = URI.parse::<UriBuf>().unwrap();
        let typ = Value::Text(STATUS_LIST_CWT_MEDIA_TYPE.into());
        let signed = token(&signer, claims(), Some(typ.clone()), None);
        let untagged = signed.clone().to_vec().unwrap();
        let wrong_tag = Value::Tag(61, Box::new(signed.clone().to_cbor_value().unwrap()))
            .to_vec()
            .unwrap();
        let unprotected_type = token(&signer, claims(), None, Some(typ.clone()))
            .to_tagged_vec()
            .unwrap();
        let duplicate_type = token(&signer, claims(), Some(typ.clone()), Some(typ))
            .to_tagged_vec()
            .unwrap();
        for invalid in [untagged, wrong_tag, unprotected_type, duplicate_type] {
            assert!(CwtStatusListToken::parse(&invalid).is_err());
        }

        let mut tampered = signed.to_tagged_vec().unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        let error = StatusListResponse::Cwt(tampered)
            .verify(&Es256Verifier, &key, 100, &uri)
            .unwrap_err();
        assert!(matches!(
            error.error,
            Error::TokenSignatureVerificationFailed
        ));
    }

    #[test]
    fn rejects_invalid_signed_cwt_claims() {
        let signer = Es256Signer::generate("12".into()).unwrap();
        let key = signer.public_jwk().unwrap();
        let uri = URI.parse::<UriBuf>().unwrap();
        let verify = |claims, now, uri: &Uri| {
            let token = token(
                &signer,
                claims,
                Some(Value::Text(STATUS_LIST_CWT_MEDIA_TYPE.into())),
                None,
            );
            StatusListResponse::Cwt(token.to_tagged_vec().unwrap()).verify(
                &Es256Verifier,
                &key,
                now,
                uri,
            )
        };

        let error = verify(claims(), 200, &uri).unwrap_err();
        assert!(matches!(error.error, Error::TokenExpired(200, 200)));
        let other_uri = "https://example.com/statuslists/2"
            .parse::<UriBuf>()
            .unwrap();
        let error = verify(claims(), 100, &other_uri).unwrap_err();
        assert!(matches!(error.error, Error::InvalidTokenSub(_, _)));

        let mut not_yet_valid = claims();
        not_yet_valid.push((5.into(), 110.into()));
        let error = verify(not_yet_valid, 100, &uri).unwrap_err();
        assert!(matches!(error.error, Error::TokenNotYetValid));

        for name in [2, 6, 65533] {
            let mut missing = claims();
            missing.retain(|(key, _)| key != &Value::from(name));
            assert!(verify(missing, 100, &uri).is_err(), "missing claim {name}");
        }
        let mut duplicate = claims();
        duplicate.push((6.into(), 101.into()));
        assert!(verify(duplicate, 100, &uri).is_err());
        let mut zero_ttl = claims();
        zero_ttl
            .iter_mut()
            .find(|(key, _)| key == &Value::from(65534))
            .unwrap()
            .1 = 0.into();
        assert!(verify(zero_ttl, 100, &uri).is_err());
    }
}
