# Agent instructions for caddy-masque

## Project context

- This is a Caddy CONNECT-IP server module, not an Apple Network Relay plugin.
  Its Linux host networking creates TUN, forwarding and NAT state.
- Start with `docs/USER_GUIDE.md`, `app.go`, `caddyfile.go` and `go.mod`.
  Preserve the local patched QUIC/x/net dependency replacements when building.
- Maintain client interoperability, authentication, certificate handling and
  the protocol-specific distinctions between H3 Datagrams and Capsules.
- Preserve ownership and cleanup boundaries for listeners, sessions, routing
  and firewall objects; do not reset unrelated host networking.
- Protect Caddy's administration endpoint separately from tunnel credentials.
  Check actual release attachments and published tags before promising binaries.
- Separate local protocol/client fixtures from native systemd, WAN and actual
  client-device acceptance. Use the retained validation records accurately.

## Repository-wide contribution rules

These rules apply to the entire repository, including subprojects, generated
files, tests, documentation, filenames and change metadata. Read any more
specific `AGENTS.md` before editing its directory. Preserve project-specific
instructions and follow the user's authorized task scope.

### Anonymous Git identity

- Every new commit must have exactly `Anonymous <anonymous@example.invalid>`
  as both its raw Git author and committer. An author override or local Git
  configuration alone is insufficient: inherited environment variables,
  amendments, cherry-picks, rebases and merge tools can retain other identities.
- Use the same identity for annotated taggers. Keep new commits and tags
  unsigned; do not attach a personal GPG/SSH signature or identity certificate.
- Do not add personal attribution trailers, including `Co-authored-by`,
  `Signed-off-by`, `Reviewed-by` or similar attestations. Do not invent anonymous
  attestations. Omit agent session IDs, session URLs and personal account details
  from change metadata. Preserve required license and copyright notices in files.
- Use real creation times with `America/Los_Angeles` timezone offsets, including
  daylight-saving changes. Do not fabricate dates or hard-code a year-round offset.
- Apply the same rules to automated/generated commits and merge results. Do not
  use a web merge or squash workflow that introduces a different author or
  committer; verify the actual resulting objects.

For an ordinary new commit, after staging only the intended paths:

```sh
env -u GIT_AUTHOR_DATE -u GIT_COMMITTER_DATE \
  GIT_AUTHOR_NAME=Anonymous \
  GIT_AUTHOR_EMAIL=anonymous@example.invalid \
  GIT_COMMITTER_NAME=Anonymous \
  GIT_COMMITTER_EMAIL=anonymous@example.invalid \
  TZ=America/Los_Angeles \
  git -c commit.gpgsign=false commit --no-gpg-sign \
  -m "Describe the change in English"
```

Inspect the raw author and committer after creation and again before pushing:

```sh
git show -s --format=fuller HEAD
git cat-file -p HEAD
```

Check every commit introduced by the operation, not only `HEAD`. Do not import
noncompliant upstream history or silently rewrite existing published history.
GitHub push actors, PR authors and platform records are separate from Git
identity; these headers do not hide the GitHub account performing an action.

### English-only repository content

- Write new repository text in English. Do not add Chinese, Korean or Russian
  content, literal Han ideographs, Hangul or Cyrillic characters, or dedicated
  CJK/fullwidth punctuation. Use ASCII punctuation for new prose.
- Cover source strings, comments, UI text, documentation, examples, configuration,
  filenames, directory names, commit messages, annotated-tag messages and any
  PR/release text you create. User conversation may follow the user's language.
- Review generated text and text packaged in any archives/assets you introduce.
  Do not hide prohibited prose in encoded data, Unicode escapes or binary files.
- Preserve protocol bytes, public interfaces, existing test semantics, user data
  and legal attribution. When existing protocol/test data needs a prohibited
  literal, use an equivalent ASCII escape representation where semantics are
  unchanged. This permits preserving existing behavior, not adding encoded
  non-English prose. Report an unresolved conflict rather than damaging behavior
  or removing required attribution to satisfy a character check.
- Use a Unicode-aware scan covering Han extensions, Hangul, Cyrillic and the
  prohibited punctuation. Searching a few words or just the basic blocks is
  insufficient. Check added/modified text, paths and messages in every newly
  introduced commit, including content later deleted by another commit.
- Existing historical content is not permission to add more. Removing or
  translating existing content must preserve business behavior and compatibility.

### Work scope and verification

- Read `docs/USER_GUIDE.md`, relevant source, configuration and validation records
  before changing behavior. If documentation conflicts with committed code,
  resolve the discrepancy explicitly; do not treat an uncommitted candidate or
  historical result as a current feature or current passing test.
- Inspect `git status` first and preserve unrelated uncommitted work. Stage
  explicit paths. For documentation/policy tasks, keep changes within the
  requested documentation/policy scope; do not bundle functional changes.
- Keep changes targeted and preserve service interoperability, authentication,
  certificate validation, resource ownership and documented network behavior.
  Do not weaken security checks or add direct fallback merely to pass a test.
- Run checks appropriate to the change and retain honest evidence. Distinguish
  local fixtures, real peers, native platform tests and live service acceptance.
  A skipped test, checklist or CI workflow definition is not a passing run.
  Documentation-only changes do not require unrelated privileged network tests.
- Before delivery, review the complete diff, scan new content and inspect every
  new commit's identity, message and changed paths. State material limitations
  and tests that were not run.
- Do not delete, weaken or bypass these instructions or existing checks to make
  a change pass. Do not change guardrails incidentally; follow explicit user
  instructions and the actual scope of the requested work.
