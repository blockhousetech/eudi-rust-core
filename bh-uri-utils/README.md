# bh-uri-utils

This library provides functionality for working with URIs for use in other The
Blockhouse Technology Limited (TBTL) projects.

NOTE: If you are working outside of TBTL, you probably don't want to use this.
Pick a popular URI implementation like [iref](https://crates.io/crates/iref) or
stick with the one that your web framework of choice uses.

## Details

This crate is a collection of utility functions for working with URIs from
different popular Rust crates in a consistent manner.

This is necessary because different URI implementations handle certain cases
like appending an URI prefix differently which can lead to unexpected bugs and
this crate is meant to harmonize these behaviors.

For additional documentation & examples, take a look at the [crate
documentation](https://docs.rs/bh-uri-utils).

## Changelog

The changelog can be found [here](CHANGELOG.md).

## License

<sup> Licensed under <a href="../COPYING">GNU Affero General Public License,
Version 3</a>. </sup>