# Documentation and comments

Terse and correct. The reader is an engineer who did not watch the work.

- No comments that say what the code does. A comment exists only for a non-obvious why:
  a hidden constraint, an invariant, a workaround for a named bug.
- No history in code or docs: no "previously", "used to", "replaced", no ticket or PR
  numbers, no commit hashes, no names of people.
- No narration: no "let me", "we tried", "it is important to note", "in summary".
- No filler emphasis: no bold sprinkles, no emdashes as default punctuation, no
  horizontal rules inside a document, no emoji.
- Docstrings only where the signature does not state the contract. One short line.
- Documents say what the system does, atemporally. Trade-offs as bullets, not paragraphs.
- Match the density of the surrounding text. A file without docstrings does not grow
  them because a change felt large.
