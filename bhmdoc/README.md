# bhmdoc

This library provides functionality for working with the mDL/mdoc specification
as defined in [ISO/IEC 18013-5][1] and expanded on in [ISO/IEC TS
18013-7:2024][2] to include integration with [openid4vc][3].

## Details

The primary way to use this library is to use the `Issuer`, `Device` and
`Verifier` structs to issue, present and verify issued mdoc documents as defined
in the [openid4vc][3] specifications.

For additional documentation & examples, take a look at the [crate
documentation][4].

## Changelog

The changelog can be found [here](CHANGELOG.md).

## License

<sup> Licensed under <a href="../COPYING">GNU Affero General Public License,
Version 3</a>. </sup>

[1]: https://www.iso.org/obp/ui/en/#iso:std:iso-iec:18013:-5:ed-1:v1:en
[2]: https://www.iso.org/obp/ui/en/#iso:std:iso-iec:ts:18013:-7:ed-1:v1:en
[3]: https://openid.net/sg/openid4vc/specifications/
[4]: https://docs.rs/bhmdoc