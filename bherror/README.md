# bherror

This library provides an error handling mechanism in Rust for use across all of
The Blockhouse Technology Limited (TBTL) code.

NOTE: If you are working outside of TBTL, you probably don't want to use this.
Take a look at [anyhow](https://crates.io/crates/anyhow) or
[thiserror](https://crates.io/crates/thiserror) instead.

## Details

The library provides a couple of error types.

  * `Error` which carries the type information of the concrete error.
  * `ErrorDyn` which type-erases the concrete error, similar to `anyhow::Error`.

All of the above are backed by a `BhError` trait which must be implemented by
your own error types.

Anytime you construct a `bherror` error, it will be logged as a warning using
the [log](https://crates.io/crates/log) crate.

For additional documentation & examples, take a look at the [crate
documentation](https://docs.rs/bherror).

## Changelog

The changelog can be found [here](CHANGELOG.md).

## License

<sup>
Licensed under <a href="../COPYING">GNU Affero General Public License, Version 3</a>.
</sup>
