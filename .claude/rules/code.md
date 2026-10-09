# Code

Safety over performance over convenience. The compiler and clippy enforce most of this;
`Cargo.toml` `[workspace.lints]` and `clippy.toml` are the mechanical layer. What they
cannot see, a reviewer rejects.

- Every loop has a fixed upper bound or walks a finite collection. No recursion.
- Every external input has a declared maximum: message size, item count, string length,
  file size. Exceeding it is an error, never a truncation.
- Allocate up front where the size is known. No growth without a cap.
- Functions do one thing and fit in sixty lines (clippy `too_many_lines`).
- Assertions at boundaries: public entry, parsing, network and process ingress,
  persistence, external services. Not at every internal step. A positive assertion in
  code pairs with a negative test.
- Every decoder of external output enumerates its states with an explicit unrecognised
  state that is never usable. Unmapped input coerces to it.
- Every `Result` is handled. No `unwrap`, `expect`, `panic`, `todo`, `unimplemented`,
  no slice indexing, no `unsafe`. An `allow` states its reason.
- Names are specific and unabbreviated. `tmp`, `ctx`, `obj`, `arr`, `cfg` are defects
  unless a framework imposes them.
- A passing check reports how many things it examined; zero examined is a failure.
- A probe that could not run is a failure, never not applicable.
- New behaviour ships with a test; a bug fix ships with the test that failed before it.
- Shallow call graphs; three levels of indirection is a smell.
