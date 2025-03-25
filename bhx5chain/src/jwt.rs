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

use openssl::base64;
use serde::{Deserialize, Serialize};

use crate::X5Chain;

/// [`X5Chain`] helper struct for working with JSON Web Token (JWT).
///
/// The inner certificates are in base64-DER format.  This struct does not contain the usual PEM
/// begin/end header/footer!
///
/// Base64-DER format certificates are needed for JWT serialization/deserialization.  See [JWS RFC
/// 7515][1] for details on `x5c`.  An example of X.509 certificate chain can be found in [JWS RFC
/// 7515: Appendix B][2].
///
/// NOTE: All `x5chain` manipulation should be done through [`X5Chain`]!  There are [`From`] and
/// [`TryFrom`] implementations to convert between the two structures.
///
/// [1]: <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6>
/// [2]: <https://datatracker.ietf.org/doc/html/rfc7515#appendix-B>
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwtX5Chain(Vec<String>);

impl JwtX5Chain {
    /// Convert the chain to a list of base64-DER certificates.
    pub fn into_base64_ders(self) -> Vec<String> {
        self.0
    }

    /// Constructor of test [`JwtX5Chain`] instance.
    ///
    /// Do NOT use this method for production code, but only tests.
    #[cfg(any(feature = "test-utils", test))]
    pub fn dummy() -> Self {
        use openssl::x509::X509;

        let cert = "-----BEGIN CERTIFICATE-----
MIICVDCCAfmgAwIBAgIUPdJpjMqO4Bls4WZx2+BcORTjlJswCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDEyMDMxMTM0NTJaFw0yNTEyMDMx
MTM0NTJaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQUlhlvcCeMLmKr98zpjwL+vFPXFGTqulzZrNfxR0OG3RkjRJ2CM4xk
emDfzwBi/44InVtwa0qOT7J/n4A9H3T2o4HGMIHDMA8GA1UdEwEB/wQFMAMBAf8w
HQYDVR0OBBYEFHqUBkBqqW11hmwTeE3dmAoa5NDEMIGABgNVHSMEeTB3gBR6lAZA
aqltdYZsE3hN3ZgKGuTQxKFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNv
bWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIUPdJp
jMqO4Bls4WZx2+BcORTjlJswDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0kA
MEYCIQDmYbg42vFmrqwp9b1Z2MQYBdE2PBuQL/thL4PHrajW4gIhAOIfUVucqEzT
tGhGJX/ipfAuxvVB4dSElUM+tMOXPqtj
-----END CERTIFICATE-----";

        let cert = X509::from_pem(cert.as_bytes()).unwrap();

        JwtX5Chain(vec![base64::encode_block(&cert.to_der().unwrap())])
    }
}

impl From<X5Chain> for JwtX5Chain {
    fn from(x5chain: X5Chain) -> Self {
        let der_certs = x5chain.into_bytes();

        let base64_ders = der_certs
            .iter()
            .map(|der| base64::encode_block(der))
            .collect();

        JwtX5Chain(base64_ders)
    }
}

#[cfg(test)]
mod tests {
    use super::JwtX5Chain;
    use crate::X5Chain;

    #[test]
    fn test_from_x5chain_to_jwtx5chain() {
        let x5chain = X5Chain::dummy();

        assert_eq!(JwtX5Chain::from(x5chain), JwtX5Chain::dummy());
    }
}
