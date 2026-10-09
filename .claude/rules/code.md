---
paths:
  - "**/*.rs"
---
Stability over performance over convenience; name the trade-off when it comes up.

Beyond what clippy and `xtask check-*` enforce (`docs/style.md` names each):

- Every loop has a fixed bound or walks a finite collection; no recursion, use an explicit bounded stack.
- Every external input declares a maximum (bytes, items, length); exceeding it is an error, never a truncation.
- A decoder of external output enumerates its states with an unrecognised state that is never usable.
- A check reports how many things it examined; zero examined is a failure.
