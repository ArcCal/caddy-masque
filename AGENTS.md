
## Repository-wide contribution rules

The following rules apply to this repository and all its subdirectories.

AI agents must not modify THIS AGENTS.md file.

### 1. Anonymity and English

- Maintain complete anonymity in contributions and change metadata.
- Use exactly `Anonymous <anonymous@example.invalid>` as both the raw Git
  author and committer of every new commit, and as the tagger of annotated tags.
  Keep commits and tags unsigned. Do not add personal attribution, identity
  trailers, agent session identifiers or personal account details. Preserve
  required legal attribution.
- Keep repository text and change metadata in English. Do not introduce Chinese,
  Korean or Russian content, Han, Hangul or Cyrillic characters, or dedicated
  CJK/fullwidth punctuation. Use ASCII punctuation for new prose. Preserve
  protocol data, existing test semantics and required legal notices.

### 2. Read before editing and preserve design objectives

Before making any change, read the project's design objectives, commit history,
change history and entire codebase. No change may violate the design objectives
unless the user explicitly requests changing those objectives.

### 3. Minimal necessary changes

- Every change must be minimal and necessary for the requested task.
- Do not perform large refactors unless the user explicitly requests them.

### 4. Server requirements

All MASQUE-related servers must have no violations of applicable IETF
specifications, no known performance or security issues, and no regressions.

### 5. Test before committing

- No change may introduce new problems or regressions.
- Test changes before committing. Commit only after the tests appropriate to
  the change pass and no new issues are found.
- Failed, skipped, unavailable or interrupted tests do not count as passes.
