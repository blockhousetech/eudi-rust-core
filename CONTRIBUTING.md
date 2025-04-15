# Contributing to `eudi-rust-core`

Thank you for your interest in contributing!  We welcome contributions of any
size and from contributors of all experience levels.  Whether you’re just
getting started with Rust or are a seasoned veteran, your help is invaluable.

  - No contribution is too small.
  - Every improvement, bug fix, or suggestion counts.

## Getting Started

If you’re new to contributing take a look at issues labeled with [good first
issue](https://github.com/blockhousetech/eudi-rust-core/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22).
These should be a good starting point for you to solve.

Feel free to ask for help or clarifications if needed.

## How to Contribute

There are several ways you can contribute.

### Reporting Bugs

When submitting a bug report, please include the following information.

  - The affected crate name and version.
  - A clear description of the issue.
  - Steps to reproduce the bug.
  - The expected vs. actual behavior.
  - Environment details (OS, Rust version, etc.).
  - Any relevant error messages, logs, or code snippets (ensure sensitive data
    is redacted).

### Requesting Enhancements

For enhancement suggestions you should do the following.

  - Explain the rationale behind your idea.
  - Detail how the change should work.
  - Reference any related issues or discussions.

### Discussion

Help by commenting on open issues, providing additional context, testing out
edge cases, or suggesting potential fixes.

### Pull Requests

Fork the repository, make your changes, and submit a pull request.  Small
improvements—like fixing typos or updating documentation—are also very welcome.

For significant changes, consider opening an issue first to discuss your ideas.

This repository has multiple crates (libraries), therefore each PR should only
make changes to one crate.  Strongly avoid PRs which introduce changes across
multiple open-source libraries.

Pull requests will be reviewed by maintainers and community members.  During
code reviews you should do the following.

  - Provide constructive feedback and be responsive to reviewer comments.
  - Be open to explanations and adjustments.
  - Maintain a positive and supportive tone in your communications.

#### Commit Message Guidelines

Your commit messages should help reviewers understand the change.  Please
adhere to the guidelines described in [How to Write a Git Commit
Message](https://cbea.ms/git-commit/).

Additionally, if your commit addresses an issue, include
`Fixes: #<issue-number>` or `Refs: #<issue-number>` in the message body.

#### Rust Code Guidelines

When writing Rust code, you should try to follow [Rust API
Guidelines](https://rust-lang.github.io/api-guidelines/).

Besides the above, you should keep the following principle in mind.

> The public API (i.e. public modules, types, functions, etc.) should be *easy
> to use, but hard to misuse*.

Following this principle is obviously easier said than done, but [Rusty's API
Design
Manifesto](https://gist.github.com/mjball/9cd028ac793ae8b351df1379f1e721f9)
should point you in a right direction.

Another rule of thumb is to keep the public API to a minimum.  If we have a
small amount of publicly exported items in the code, we have less things to
worry about.

Note, as in all of the API Design, this area is not an exact science.  Try to
apply common sense instead of blindly following rules.

#### Testing, Linting & Formatting

Our CI will produce a report whether:

  - all tests passed
  - code is formatted with `rustfmt`
  - `cargo clippy` produced no warnings nor errors
  - `cargo doc` successfully completed
  - `cargo deny` checked & allowed dependencies
  - Rust source files have the copyright & license notices

If your change introduces new functionality or fixes a bug, include
corresponding tests to confirm that it works as intended.

#### Code Documentation

Special attention should be given to code documentation.  All public items of a
crate *must* be documented.  To enforce this during compilation, each crate
should have `#![deny(missing_docs)]` at the top of its `lib.rs` file.

The links within the documentation should all be valid.  To enforce this, put
`#![deny(rustdoc::broken_intra_doc_links)]` at the top of `lib.rs`.

When writing the documentation, try to make an extra effort on spelling &
sentence structure, as well as providing code examples.

#### CHANGELOG.md

The PR should also update the `CHANGELOG.md` of the affected crate(s).  The
changes written there should target end-users and as such a PR should update
the `CHANGELOG.md` only to give a high-level overview of end-user relevant
changes.  This implies that there may be some PRs which need not update the
`CHANGELOG.md`.  For example, reformatting the code with the new version of a
format tool is something that will not be visible to the users of the library,
so it need not be noted in the `CHANGELOG.md`.  Additionally, even if the PR
updates the `CHANGELOG.md` it should only make updates to the "Unreleased"
section.

When we decide to release something, a new PR should be made which only updates
the version, dates & links in the `CHANGELOG.md`, as well as in the manifest
files (i.e. Cargo.toml for Rust code).  This way we allow for multiple PRs to
be included in a single release.

Naturally, if a PR has to be immediately released (e.g. an emergency fix) it
can do everything in one go.

## Code of Conduct

This project adheres to the [Rust Code of
Conduct](https://github.com/rust-lang/rust/blob/master/CODE_OF_CONDUCT.md).
Please review it to ensure your contributions align with our community
standards.  We expect everyone to follow these guidelines to maintain a
welcoming and collaborative environment.
