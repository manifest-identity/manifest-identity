These standards originate from the build-doctrine repository at
github.com/tltaylor1/build-doctrine, which holds the canonical and
current version, its enforcement mappings, and the reasoning behind each
rule. This file is a point-in-time copy adopted at project start.

# Standards

The doctrine. Each rule states what to do; [ENFORCEMENT.md](https://github.com/tltaylor1/build-doctrine/blob/main/ENFORCEMENT.md)
states what checks it, and [DECISIONS.md](DECISIONS.md) states which failure
produced it.

**Contents:** [Principles](#principles) · [Writing](#writing) · [Code](#code) · [Security](#security) · [Secrets and configuration](#secrets-and-configuration) · [Dependencies](#dependencies) · [Containers](#containers) · [Git practice](#git-practice) · [Working with an AI agent](#working-with-an-ai-agent) · [Definition of done](#definition-of-done) · [Not yet covered, and why](#not-yet-covered-and-why)

-------------------------------------------------------------------------------

## Principles

The principles that decide the rest. When a rule below is ambiguous, resolve it
against these.

1. **A rule that depends on remembering is not a control.** Prefer the enforced
   version of anything, and label the unenforced remainder honestly.
2. **Secure by accident and secure on purpose look identical in code.** Only the
   decision record distinguishes them, which is why the record is not optional.
3. **The value is in what was left out.** A small correct system with documented
   reasoning is worth more than a large one without it.
4. **Verify rather than assert.** A claim about a system is checked against the
   running system before it goes in a document.
5. **Better not working than shipping a real security issue.** Gates block.
6. **The standards are not fixed.** Every incident that review catches becomes a
   rule, and every rule records the incident that produced it. A standard that
   never changes is not stable, it is unmaintained. The mechanism is
   [DECISIONS.md](DECISIONS.md), where each entry names its cause, and the
   promotion path in [ENFORCEMENT.md](https://github.com/tltaylor1/build-doctrine/blob/main/ENFORCEMENT.md), where a human check that
   catches the same problem twice becomes an automated one. Treating the
   standards as final is the failure this baseline is built to avoid.

### The properties these rules protect

These four properties are what the rules below exist to protect. They are named
because a missing feature is obvious and a missing property is not: nobody
notices that nothing in the system protects availability until something takes
it down.

- **Confidentiality.** Data reaches only those entitled to it. Object-level
  authorization, output models, encryption at rest, and masking serve this.
- **Integrity.** Data changes only through intended paths. Parameterized
  queries, input models, immutable decisions, and attribution serve this.
- **Availability.** The system stays usable under load and abuse. Bounded
  inputs, resource caps, and rate limiting serve this. It is the property most
  often forgotten when thinking only about disclosure.
- **Accountability and non-repudiation.** An actor cannot credibly deny what
  the record shows. Audit rows written in the same transaction as the action,
  attribution columns on changed records, and audited sensitive reads serve
  this.

### The design principles behind the rules

- **Least privilege.** Every identity, process, and container gets the minimum
  access required. Applied to people through roles, to workloads through
  non-root users and dropped capabilities, and to databases through restricted
  accounts.
- **Defense in depth.** Any single control can fail or be bypassed, so
  important rules get more than one. Secrets are kept out of the repository by
  architecture, caught at commit by a scanner, and caught again in the pipeline.
  Each layer fails in a different way, so the layers do not fail together.
- **Complete mediation.** Every request is checked, not the first one. A token
  is validated on each request and authority is read fresh rather than cached
  in a credential.
- **Fail secure.** When something is missing or wrong, stop rather than
  continue with a weaker assumption. Missing configuration halts startup;
  failing gates block rather than warn.
- **Economy of mechanism.** The smallest system that satisfies the requirement
  is the one that can be reviewed. Injection is removed as a class rather than
  defended case by case, because a structural answer needs no vigilance.
- **Open design.** Security rests on the controls and the secrets, never on the
  code being unread. These documents describe every control precisely, on the
  assumption a reader has the source.
- **Weakest link.** An attacker uses the easiest path in, so the security of a
  system is the security of its weakest part. Hardening one endpoint while a
  second endpoint exposes the same data protects nothing, because the data is
  still reachable through the second one.
- **Separation of duties.** No actor completes a sensitive transaction alone.

-------------------------------------------------------------------------------

## Writing

- Plain language, following the Federal Plain Language Guidelines: common words,
  short sentences, present tense, no idioms, no figurative phrasing. Developer
  idiom counts as jargon.
- Complete sentences. Define every acronym at its first use, even common ones.
- No em dashes, no en dashes, no arrows, no smart quotes, anywhere. This covers
  documents, code comments, and commit messages.
- Separate major sections with horizontal rules, and open long documents with a
  contents line, so a reader looking for one section can find it without reading
  the whole document.
- Answer a likely question at the place it would be asked, rather than in a
  separate section the reader has to go find.
- Prefer fewer words when they carry the same meaning, and re-read documents as
  a project matures to remove what is no longer needed. Clarity comes first: a
  shorter document that is harder to understand is worse.
- When a design question is answered during a build, the answer goes into the
  document at that moment, not into the conversation only.

-------------------------------------------------------------------------------

## Code

- Human-readable over clever. Clever code is faster to write and slower to
  verify, and it has to be re-understood every time it is read.
- Intent comments explain why, never what. No comment restates the code.
- Every module opens with a short docstring saying what the file is and where it
  sits in the request flow, so the code can be walked through aloud.
- Security decision points carry their reason at the line.
- No placeholders, no stub functions, no dead code, no debug output, no
  commented-out credentials in any committed state.
- Larger files are acceptable. Code is read far more often than written.

-------------------------------------------------------------------------------

## Security

These controls are built in from the first commit rather than added later:

- **Authentication** is validated on every request, not trusted once. Tokens
  expire. Token verification pins its accepted algorithms explicitly.
  Authentication failures return one generic error for every cause, so accounts
  cannot be enumerated. Failed and successful logins are both audited.
- **Object-level authorization** on every owned record: this user owns this
  record. A valid identifier is never sufficient. For list endpoints the filter
  is the authorization, so other users' rows cannot appear in the result at all.
- **Separation of duties**: no actor completes a sensitive transaction alone,
  and nobody approves their own record whatever their role.
- **Input validation** is server side, typed, and bounded: maximum lengths on
  strings, ranges on numbers, enforced maximum page sizes on lists. Client-side
  validation is a usability feature, not a control.
- **Separate input and output models.** Input models accept only fields a client
  may set, never role or ownership fields. Every response declares its model, so
  internal fields cannot leak.
- **Audit logging** of sensitive actions, denials, and sensitive reads. The
  action and its audit row commit in one transaction, so a change cannot exist
  without its trail. Records that change state also carry attribution as columns.
  Never log passwords, tokens, or full request bodies.
- **Uploads** are validated on the declared type, on the file's own leading
  bytes, and on size, before anything touches disk. Stored files use
  server-generated names; a client filename is display data and never a path.
- **Sensitive downloads** pass the same object check as the record, are audited
  on every successful read, and serve a server-generated filename with
  `X-Content-Type-Options: nosniff`.
- **Exports** neutralize spreadsheet formula injection: any text cell beginning
  with an equals sign, plus, minus, or at sign is prefixed so it renders as text.
- **Injection** is removed as a class rather than defended case by case: all
  database access goes through an object-relational mapper or parameterized
  queries, and all user-supplied values render into pages as text, never markup.
- **Tokens travel in a request header**, never a cookie, which keeps cross-site
  request forgery out of scope by design.
- **Error responses to clients are generic.** Stack traces and internal detail
  go to server logs only.
- **Every framework default in the serving path** is walked before release and
  either changed deliberately or recorded as accepted.
- **Threats are ranked** by likelihood and impact. What is out of scope is
  written down with the reason.

### Cryptography

- **Data is encrypted in transit.** Transport security terminates at the edge in
  a real deployment; a local build states where it would terminate rather than
  leaving the question open.
- **Sensitive values are encrypted at rest with authenticated encryption**, so
  tampering is detectable rather than only unreadable. The key comes from the
  environment and the application refuses to start without it.
- **Identity and lookup never require decryption.** Where a stored value must be
  compared or deduplicated, use a keyed fingerprint rather than the ciphertext
  or a bare hash. A bare hash of a low-entropy value lets anyone with database
  read access confirm guesses offline; keying removes that.
- **Passwords are hashed with a deliberately slow algorithm** that salts
  automatically. Hashing is not encryption and the two are never confused.
- **Key rotation is a written procedure, not an aspiration.** Every key
  documents how it rotates and what must be re-encrypted. Supporting rotation
  and having a tested procedure are different things.
- **Nothing invents cryptography.** Use the maintained library primitive.

### Operations and incident response

- **Security-relevant events are logged as structured data.** Structured means a
  machine can parse and query it without guessing. Each record carries
  identifiers and short factual detail, and never carries credentials, tokens,
  or request bodies.
- **The events are designed by asking what an investigation would need.** At
  minimum the log must be able to answer who failed to authenticate, who was
  denied access, and who read sensitive data. If it cannot answer those, the
  logging is incomplete regardless of how much of it there is.
- **Detection queries are written while the events are being designed**, not
  after an incident. Writing the query is what proves the event contains enough
  to detect anything.
- **A query becomes a control when it has a threshold and an owner.** Until
  someone is told when it fires, it is documentation.
- **A response procedure is written before it is needed**, naming what to revoke
  or rotate, in what order, and how to reconstruct what the actor did. What
  belongs in it is specific to the system and is recorded in that system's own
  documents. As an example, a system with stateless sessions has no way to
  revoke one credential, so its procedure starts by rotating the signing secret,
  which ends every session at once.
- **The procedure is exercised at least once.** A response plan that has never
  been run is an assumption about how the system behaves under conditions nobody
  has tested.

-------------------------------------------------------------------------------

## Secrets and configuration

- No secrets in the repository, ever. Configuration lives in an ignored `.env`,
  with a committed `.env.example` documenting each variable without containing
  one.
- **No credential-shaped string in any tracked file or commit**, including demo,
  sample, and test passwords. Demo credentials come from the environment and
  fail fast when missing; test suites generate their own per run. A reader must
  never have to decide whether a password-looking string matters.
- The application fails at startup when a required secret is missing, and the
  error message contains the command that produces a valid one. A default secret
  becomes the real one the day somebody forgets.
- Every credential the system issues documents both halves: how it expires, and
  how it is revoked. If individual revocation does not exist, the document says
  so and states the accepted trade.

-------------------------------------------------------------------------------

## Dependencies

- Declared in a `.in` file, compiled with hashes, installed with hash
  enforcement. Nothing is installed directly into a project environment, because
  a package installed by hand is absent from the lockfile and therefore absent
  from the next build.
- Every package is verified against the public registry before adoption: the
  name resolves to the canonical project, not a lookalike. Record it with
  version, source, and role.
- After any dependency change: recompile, regenerate the software bill of
  materials, and run the audit.
- Updates arrive as pull requests tested by the same gates as code. A
  vulnerability finding forces an update immediately rather than waiting for the
  schedule.
- Dependencies resolve at pin time, install at build time, and never change at
  deploy time.

-------------------------------------------------------------------------------

## Containers

- The image is the deployable artifact. What was tested is what runs.
- Base images are pinned by digest, with a comment naming the release the digest
  came from. A tag can be moved to different code; a digest cannot.
- The process runs as a non-root user.
- The root filesystem is read only, with named volumes for the paths that must
  persist.
- All Linux capabilities are dropped, and no-new-privileges is set.
- Memory and processor use are capped.
- Databases publish no host port, and the application binds to loopback in local
  configurations.
- The build context excludes the environment file, tests, local state, and the
  git directory, so none of it can reach a layer.
- Documentation states how to stop the stack and how to discard its data, and
  names the values that only take effect when a data directory is first created.
  A reader who cannot reset to a clean state will hit a stale-state failure and
  have no way to interpret it.

-------------------------------------------------------------------------------

## Git practice

- The ignore rules and the secret-scanning hook exist before the first commit.
- Commit each working unit as it is finished, not batched at milestones. Many
  small commits with clear messages; the history should explain the build.
- Commit messages follow the writing rules and state why, not only what.
- Never push without explicit approval. Never force push, rewrite history, or
  delete a branch without asking first.
- Repository visibility is decided before the first commit, and everything is
  written to the public standard from that commit onward regardless. History is
  permanent, and scrubbing it later is unreliable.

-------------------------------------------------------------------------------

## Working with an AI agent

- The agent works against these standards, which are copied into the project as
  `AGENTS.md`, with a one-line `CLAUDE.md` pointing to it, so they are in force
  from the first session across whichever agent reads them.
- Plan before code. State the approach in a few sentences and get agreement.
- Small reviewable diffs, one concern at a time. Every change is read before it
  is committed.
- Commits the agent co-authors carry a trailer naming the exact model, so
  provenance is readable from history.
- When generated output is corrected for a security reason, record the catch.
  Real catches only.
- The agent works from primary sources, not from its own summaries. When a past
  effort is the reference, read that effort's artifacts and transcripts rather
  than recalling them.
- Final architecture diagrams are drawn by a human. The agent specifies what a
  diagram must show and reviews drafts against the threat model.
- When a gate refuses, quote the refused line before changing anything. The
  gate names what it rejected; a theory about why it rejected it is not a
  reading of that line.
- A script that pushes stops at the first failed step. Every command whose
  result the push depends on is checked, not assumed.

-------------------------------------------------------------------------------

## Definition of done

- A stranger runs it from a fresh clone using only the README.
- Every control is a mechanism, and the claims are verifiable by commands
  written down in the documents.
- Security paths have tests, and the tests are proven by mutation to notice a
  control disappearing.
- Every non-obvious choice carries its reason, including what was left out.
- The dependency tree is hash-pinned and inventoried, the gates pass, and no
  credential-shaped string exists anywhere in the repository or its history.
- Documents are accurate and current. Where a document can be shorter without
  losing clarity, it should be; brevity that costs clarity is not an
  improvement.

-------------------------------------------------------------------------------

## Not yet covered, and why

A standard with no mechanism behind it is the failure this baseline exists to
prevent, so these are recorded as gaps rather than written as rules. Each names
what would trigger it. An undocumented gap and a considered exclusion look
identical from outside; only this section distinguishes them.

- **Requirements traceability.** No project here has had a formal requirement
  set to trace controls back to. Triggered by work delivered against a written
  specification or a compliance baseline, where a matrix mapping each
  requirement to its control and its test becomes the deliverable.
- **Misuse and abuse cases.** Threat modeling here has been informal and
  component-driven. Triggered by any system where an attacker has a business
  motive rather than only a technical one, such as fraud or benefit abuse.
- **Data classification.** These systems have held one sensitivity level, and
  the answer has been to minimize what is stored. Triggered by a system holding
  mixed sensitivity, where handling rules must differ by class.
- **Backup, recovery, and retention.** Nothing here is a system of record whose
  loss would matter, and local data is disposable by design. Triggered by the
  first system whose history has value, where retention limits also bound what
  a future breach exposes.
- **Decommissioning and secure disposal.** No system here has been retired.
  Triggered by the first one, and the interesting part is proving data is
  unrecoverable rather than merely deleted.
- **Security metrics.** Tracking measures such as time to patch or percentage
  of findings resolved is useful when a system is too large to inspect directly.
  These projects are small enough to read end to end, so a measure would report
  what a direct look already shows. Triggered by work spanning multiple teams or
  systems, where no one person can hold the whole picture.
- **Availability engineering beyond resource caps.** Rate limiting, request
  timeout budgets, and load protection are named in project roadmaps but have no
  standard here. Triggered by anything reachable from the public internet.

Adding a rule here without a project that exercises it would produce exactly the
unenforceable doctrine [ENFORCEMENT.md](https://github.com/tltaylor1/build-doctrine/blob/main/ENFORCEMENT.md) exists to expose.
