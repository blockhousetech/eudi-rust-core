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

//! This module defines the [`IssuedDocument`] struct, which represents an issued `mso_mdoc` Credential.

use bherror::traits::ForeignError as _;
use serde::{Deserialize, Serialize};

use super::data_retrieval::{common::DocType, device_retrieval::response::IssuerSigned};
use crate::{utils::base64::base64_url_encode, MdocError, Result};

/// Represents an issued `mso_mdoc` Credential.
///
/// This type is typically obtained from the [`Issuer`][crate::issuer::Issuer] struct,
/// which is responsible for issuing Credentials.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedDocument {
    doc_type: DocType,
    issuer_signed: IssuerSigned,
}

impl IssuedDocument {
    /// Serialize [`IssuerSigned`] using CBOR, encoded using base64url based on [OpenID4VCI ISO
    /// mDL][1].
    ///
    /// [1]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response-5>
    pub fn serialize_issuer_signed(&self) -> Result<String> {
        let mut bytes = vec![];

        ciborium::into_writer(&self.issuer_signed, &mut bytes)
            .foreign_err(|| MdocError::IssuerAuth)?;

        Ok(base64_url_encode(bytes))
    }

    pub(crate) fn new(doc_type: DocType, issuer_signed: IssuerSigned) -> Self {
        Self {
            doc_type,
            issuer_signed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::IssuedDocument;
    use crate::models::data_retrieval::device_retrieval::response::IssuerSigned;

    #[test]
    fn serialize_issuer_signed_static() {
        const EXAMPLE_DOCUMENT: &str = "a267646f6354797065782a37356330383961662d336232322d34613634\
2d393430332d63623137373930316264346420312e302e306c6973737565725369676e6564a26a6e616d65537061636573\
a1716f72675f69736f5f31383031335f355f3182d8185852a4686469676573744944006672616e646f6d50e0b38dfd324c\
3dda9618da5e505aea0471656c656d656e744964656e7469666965726b66616d696c795f6e616d656c656c656d656e7456\
616c756563446f65d8185858a4686469676573744944016672616e646f6d50a8835b25df75feb82ae89a077df69ff87165\
6c656d656e744964656e7469666965726a62697274685f646174656c656c656d656e7456616c75656a313938302d30312d\
30326a697373756572417574688443a10126a11821825901e2308201de30820184a0030201020214204f294b804d443fd7\
b3b448e299a8e4069f81a1300a06082a8648ce3d040302306d310b30090603550406130248523114301206035504080c0b\
47726164205a6167726562310f300d06035504070c065a6167726562310d300b060355040a0c045442544c3111300f0603\
55040b0c085465616d204265653115301306035504030c0c696e7465726d656469617279301e170d323431323138313133\
3833335a170d3334313231363131333833335a30123110300e06035504030c07636f636f6e75743059301306072a8648ce\
3d020106082a8648ce3d030107034200049818a730e5711b7ef6cab5c661b3f5e0da7c0bfec634d5a4da760269cc562806\
c08c33397099dd3c393eb9d3c208d8d5fe183ec263fea79bb74a2b1369e5c84ca35d305b30090603551d1304023000300e\
0603551d0f0101ff0404030206c0301d0603551d0e04160414af5f081c8e49ef4bb974495192cd1fd849f13c4b301f0603\
551d2304183016801441ddbe3b030bcd539f9737223341351b39f0324b300a06082a8648ce3d0403020348003045022076\
67fac465a5eb7cad6cb91a0de8d93020662689ad83af692b3187fbfdb3e2b102210085a24bee3d93b6f8568ece562da655\
0d3b612226af8787fa0a4def20e481508f5902403082023c308201e2a003020102021407c5cc81cec83d6d0b759424fb15\
9765c03007e2300a06082a8648ce3d0403023065310b30090603550406130248523114301206035504080c0b4772616420\
5a6167726562310f300d06035504070c065a6167726562310d300b060355040a0c045442544c3111300f060355040b0c08\
5465616d20426565310d300b06035504030c04726f6f743020170d3234313231323132333634335a180f32313234313131\
383132333634335a306d310b30090603550406130248523114301206035504080c0b47726164205a6167726562310f300d\
06035504070c065a6167726562310d300b060355040a0c045442544c3111300f060355040b0c085465616d204265653115\
301306035504030c0c696e7465726d6564696172793059301306072a8648ce3d020106082a8648ce3d03010703420004d2\
878bbcdc2546093e40259fda903952fe34d6ebf02e7d097873921f47fdf30100ff4df1f2bfb965350bbd36a4c616d46328\
f007dc6d94c3bbf1fc2fafb662b6a3663064301d0603551d0e0416041441ddbe3b030bcd539f9737223341351b39f0324b\
301f0603551d23041830168014b294ed573a841e84c686f8cdb4f37b9373ce0f2930120603551d130101ff040830060101\
ff020100300e0603551d0f0101ff040403020186300a06082a8648ce3d0403020348003045022048f661c5235012dc0202\
674ce31eeb04bda002dd607b875f43137b0867fe105d022100d0f4bc52ebb3018a35050d92258c455e6cccc72de8168b8a\
4b768c6da9c849775901bed8185901b9a66776657273696f6e63312e306f646967657374416c676f726974686d67534841\
2d3235366c76616c756544696765737473a1716f72675f69736f5f31383031335f355f31a20158203fc425a81eda3652d8\
3a1a1f2e250a64d18b5b6130ce95de95058327e32471ec0058207fc17f5ac45240ededc95fdf6dced60424913b793ad049\
cf044de0c132dc9c316d6465766963654b6579496e666fa3696465766963654b6579a40102200121582049f1925be14192\
431066339ba5f4f3fe797cfb3094923210fef358df57840fb6225820803ff24f40a5e3dfaf98166bcf2e8b86e5a140e187\
ebf0506b8e950dc4259118716b6579417574686f72697a6174696f6e73f6676b6579496e666ff667646f6354797065782a\
37356330383961662d336232322d346136342d393430332d63623137373930316264346420312e302e306c76616c696469\
7479496e666fa4667369676e656474323032362d30372d30325431333a34363a34305a6976616c696446726f6d74323032\
362d30372d30325431333a34363a34305a6a76616c6964556e74696c74323032392d30392d30315432333a33333a32305a\
6e6578706563746564557064617465f65840d10d114600966ba90c3f120b074ca1b557acaaab9524a6cd3bc3c7317818df\
060c77c9c37aa0ca132d7afab6e13d6d46e7f51af8876f0c55a8b7a9c7f5679dbd";

        const EXPECTED_ISSUER_SIGNED: &str = "ompuYW1lU3BhY2VzoXFvcmdfaXNvXzE4MDEzXzVfMYLYGFhSpGhk\
aWdlc3RJRABmcmFuZG9tUOCzjf0yTD3alhjaXlBa6gRxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVsZWxlbWVudFZhbH\
VlY0RvZdgYWFikaGRpZ2VzdElEAWZyYW5kb21QqINbJd91_rgq6JoHffaf-HFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRl\
bGVsZW1lbnRWYWx1ZWoxOTgwLTAxLTAyamlzc3VlckF1dGiEQ6EBJqEYIYJZAeIwggHeMIIBhKADAgECAhQgTylLgE1EP9eztE\
jimajkBp-BoTAKBggqhkjOPQQDAjBtMQswCQYDVQQGEwJIUjEUMBIGA1UECAwLR3JhZCBaYWdyZWIxDzANBgNVBAcMBlphZ3Jl\
YjENMAsGA1UECgwEVEJUTDERMA8GA1UECwwIVGVhbSBCZWUxFTATBgNVBAMMDGludGVybWVkaWFyeTAeFw0yNDEyMTgxMTM4Mz\
NaFw0zNDEyMTYxMTM4MzNaMBIxEDAOBgNVBAMMB2NvY29udXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASYGKcw5XEbfvbK\
tcZhs_Xg2nwL_sY01aTadgJpzFYoBsCMMzlwmd08OT6508II2NX-GD7CY_6nm7dKKxNp5chMo10wWzAJBgNVHRMEAjAAMA4GA1\
UdDwEB_wQEAwIGwDAdBgNVHQ4EFgQUr18IHI5J70u5dElRks0f2EnxPEswHwYDVR0jBBgwFoAUQd2-OwMLzVOflzciM0E1Gznw\
MkswCgYIKoZIzj0EAwIDSAAwRQIgdmf6xGWl63ytbLkaDejZMCBmJomtg69pKzGH-_2z4rECIQCFokvuPZO2-FaOzlYtplUNO2\
EiJq-Hh_oKTe8g5IFQj1kCQDCCAjwwggHioAMCAQICFAfFzIHOyD1tC3WUJPsVl2XAMAfiMAoGCCqGSM49BAMCMGUxCzAJBgNV\
BAYTAkhSMRQwEgYDVQQIDAtHcmFkIFphZ3JlYjEPMA0GA1UEBwwGWmFncmViMQ0wCwYDVQQKDARUQlRMMREwDwYDVQQLDAhUZW\
FtIEJlZTENMAsGA1UEAwwEcm9vdDAgFw0yNDEyMTIxMjM2NDNaGA8yMTI0MTExODEyMzY0M1owbTELMAkGA1UEBhMCSFIxFDAS\
BgNVBAgMC0dyYWQgWmFncmViMQ8wDQYDVQQHDAZaYWdyZWIxDTALBgNVBAoMBFRCVEwxETAPBgNVBAsMCFRlYW0gQmVlMRUwEw\
YDVQQDDAxpbnRlcm1lZGlhcnkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATSh4u83CVGCT5AJZ_akDlS_jTW6_AufQl4c5If\
R_3zAQD_TfHyv7llNQu9NqTGFtRjKPAH3G2Uw7vx_C-vtmK2o2YwZDAdBgNVHQ4EFgQUQd2-OwMLzVOflzciM0E1GznwMkswHw\
YDVR0jBBgwFoAUspTtVzqEHoTGhvjNtPN7k3PODykwEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZI\
zj0EAwIDSAAwRQIgSPZhxSNQEtwCAmdM4x7rBL2gAt1ge4dfQxN7CGf-EF0CIQDQ9LxS67MBijUFDZIljEVebMzHLegWi4pLdo\
xtqchJd1kBvtgYWQG5pmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOhcW9yZ19pc29f\
MTgwMTNfNV8xogFYID_EJage2jZS2DoaHy4lCmTRi1thMM6V3pUFgyfjJHHsAFggf8F_WsRSQO3tyV_fbc7WBCSRO3k60EnPBE\
3gwTLcnDFtZGV2aWNlS2V5SW5mb6NpZGV2aWNlS2V5pAECIAEhWCBJ8ZJb4UGSQxBmM5ul9PP-eXz7MJSSMhD-81jfV4QPtiJY\
IIA_8k9ApePfr5gWa88ui4bloUDhh-vwUGuOlQ3EJZEYcWtleUF1dGhvcml6YXRpb25z9mdrZXlJbmZv9mdkb2NUeXBleCo3NW\
MwODlhZi0zYjIyLTRhNjQtOTQwMy1jYjE3NzkwMWJkNGQgMS4wLjBsdmFsaWRpdHlJbmZvpGZzaWduZWR0MjAyNi0wNy0wMlQx\
Mzo0Njo0MFppdmFsaWRGcm9tdDIwMjYtMDctMDJUMTM6NDY6NDBaanZhbGlkVW50aWx0MjAyOS0wOS0wMVQyMzozMzoyMFpuZX\
hwZWN0ZWRVcGRhdGX2WEDRDRFGAJZrqQw_EgsHTKG1V6yqq5Ukps07w8cxeBjfBgx3ycN6oMoTLXr6tuE9bUbn9Rr4h28MVai3\
qcf1Z529";

        let document: IssuedDocument =
            ciborium::from_reader(hex::decode(EXAMPLE_DOCUMENT).unwrap().as_slice()).unwrap();

        assert_eq!(
            document.serialize_issuer_signed().unwrap(),
            EXPECTED_ISSUER_SIGNED
        );

        let deserialized = IssuerSigned::from_base64_url(EXPECTED_ISSUER_SIGNED).unwrap();

        assert_eq!(document.issuer_signed, deserialized);
    }
}
