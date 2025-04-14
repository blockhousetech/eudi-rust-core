# bhmdoc Example

This directory contains an example of using `bhmdoc` to perform a full flow,
going from issuing an mDL document, to presenting and verifying it.

In practice the `Issuer`, `Device` and `Verifier` would probably not all be
instantiated and used in one project but would rather be used as separate
components within a larger system that implements the `openid4vc` protocols.
However, this example is written this way to demonstrate the full range of crate
functionality.

## Files
- [`full_flow.rs`](full_flow.rs): Contains the code for the example
- [`certs/intermediary.crt`](certs/intermediary.crt),
  [`certs/intermediary.crt`](certs/intermediary.crt),
  [`certs/intermediary.key`](certs/intermediary.key),
  [`certs/root.crt`](certs/root.crt): Used to instantiate the `x5chain` used for
  the `Issuer`
- [`certs/generate_certs_and_key.sh`](certs/generate_certs_and_key.sh): Used to
  generate the key and certificates mentioned above. The key and certificates
  are already checked in the repo for easy usage but can be regenerated using
  this script
- [`certs/root.config`](certs/root.config),
  [`certs/mid.config`](certs/mid.config): Configuration files for the `openssl`
  calls used in the script mentioned above
