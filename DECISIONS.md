# Decisions

What was chosen, what was rejected, and why. Risk acceptance lives here.
Decisions are numbered in the order they were made and are never renumbered.

The project was named role-call through D-063. Entries before D-064
say role-call where they describe the past, and stay as written.

-------------------------------------------------------------------------------

## D-001: AWS identity first, then possibly Okta, then Entra

The first supported identity provider is Amazon Web Services (AWS):
Identity and Access Management (IAM) users and their access keys, roles and
their trust relationships, instance profiles, federated principals, and
Identity Center assignments.

Entra was rejected as the starting provider despite being the author's
deepest platform. The AWS identity model is where the largest population of
ungoverned non-human identities lives in practice, the enrichment sources
are unusually good (the credential report, access advisor data, Access
Analyzer findings, CloudTrail history), and building against AWS exercises
the platform this project is meant to deepen. Additional providers join
behind a common identity model rather than as separate code paths, which is
why the order is a roadmap entry and not a rewrite.

## D-002: TruffleHog for secret scanning, in two modes

This repository uses TruffleHog as its secret scanner: as a pre-commit hook
with verification disabled, so the commit-time check is fast and fully
offline, and in continuous integration with verification enabled, where a
finding is checked against the credential's provider to learn whether it is
live.

gitleaks was rejected for this repository, though it remains in use
elsewhere. The difference that decides it: this project is developed against
live cloud accounts, so a credential that reaches a commit here could be a
real one, and the question that matters in that moment is whether it still
works. Verification answers that; detection alone does not. One tool in two
modes also means one configuration and one allowlist format instead of two.

The accepted cost: verification in continuous integration makes outbound
calls to credential providers, and testing a candidate can appear in the
provider's logs as a failed authentication. That trade is taken knowingly,
because the answer it buys ("rotate now" versus "stale example") is the
whole point.

## D-003: The repository starts private, with the public flip as a gate

The repository is private during design and early build, and goes public
only after a full read of every file and the whole history, while the
history is still small enough to read completely. Before the flip, two
things must exist: a LICENSE file chosen deliberately (Apache License 2.0
is the working intent, recorded as final only at the flip), and a
SECURITY.md with a private vulnerability reporting path.

Building in public from the first commit was rejected because early design
documents churn, and a public history of half-formed decisions serves no
reader. Staying private indefinitely was rejected because the finished
design is meant to be read.

## D-004: Design before code

Phase 0 produces architecture, a threat model, a roadmap, and this decision
record, and no application code. Writing code first was rejected for the
same reason it always is: design is the cheapest place to fix anything, and
a schema chosen well makes the hard requirements structural instead of
procedural.

## D-005: Enrichment over automation

The product amplifies a human decision; it does not act on its own. Version
one holds a read-only credential and writes nothing to the cloud account.
Human-triggered actions arrive only in a late phase, each reversible where
the platform allows, shown as a diff before it happens, and verified
against the provider afterward. Automated remediation was rejected
permanently: a tool that revokes on its own gets disabled the first time it
breaks something, and a tool that never asks for trust it has not earned
keeps its own threat model small.

## D-006: Ingestion is append-only and state is derived, never stored

Each sync records what was observed. An identity's state is computed from
the observations at read time, so re-imports are harmless, out-of-order
syncs self-correct, and there is no stored status column to drift from
reality. Mutate-on-ingest designs were rejected because a stored security
status that can drift is worse than none: people trust it. This structure
was proven in an earlier build and is the core of this one.

## D-007: The stack is Python, FastAPI, and PostgreSQL under Docker Compose

Typed request validation at the boundary, a real database service
matching the shape the deliverable runs as, and database access only through
the object-relational mapper (ORM), which parameterizes every query and
removes injection as a class rather than defending it query by query.
SQLite was rejected for the deliverable because the runnable stack is the
product. Raw SQL anywhere was rejected outright.

## D-008: The ingestion surface distrusts even its own preconditions

Imported snapshots are bounded on every axis, parsed in memory, and never
written to disk. The file's content is authoritative and its name is not,
because a filename is client-supplied. A file claiming to cover one account
is verified to cover one account rather than trusted. A timestamp with an
unrecognised timezone is rejected rather than guessed, because sync
timestamps order the history and therefore decide what counts as current.
Each of these rules exists because the assumption it replaces is exactly
what a malicious file would exploit.

## D-009: Keys and startup are strict

Two keys with two lifetimes, the session signer and the data encryption
key, generated independently and never derived from each other, so rotating
one never silently changes the other. No defaults ship for either: the
application refuses to start with a missing or malformed key and prints the
command that generates a valid one. Bootstrap is idempotent with the
environment as the source of truth, so changing the configured credential
and restarting always converges instead of locking an operator out.

## D-010: Output is an allowlist at every exit

Every response declares a response model, so what a client can see is
defined by schema rather than by what a row contains. Sensitive
identifiers are masked in list views, and any full reveal is a dedicated,
audited event. Client errors are generic, including a custom validation
handler so a rejected value is never echoed back. Logs serialize an
explicit field allowlist carrying identifiers, never values. Exports
escape formula-leading cells so a spreadsheet cannot execute
attacker-influenced content. There is no cross-origin configuration on
purpose, and the interactive documentation page is a recorded decision
either way, because concealing an API's shape is not a control.

## D-011: The audit row commits with the action, and records who

Any action that changes governance state writes its audit row in the same
transaction, so no action can exist without its record; an audit write
failure fails the action, integrity chosen over availability for the
trail. Records that change state also carry their own attribution columns,
so a row answers who did this without a join. Best-effort trails were
rejected: a gap between action and record is exactly where an investigation
dies.

## D-012: Sessions are revocable from day one

Whatever the session mechanism, one stolen credential can be ended without
ending every session. Stateless-only tokens were rejected because expiry
without revocation leaves only the option of rotating the signing key and
logging everyone out, which in practice means nobody does it.

## D-013: Migrations from the first table, data rights only for the app

The schema is created and changed by versioned migrations run as a
privileged role, never by the application at startup. The application's
database role has data rights only, so an injection flaw, however
unlikely the ORM makes one, could not modify the schema. Create-all at
startup was rejected because it cannot evolve a database that already
holds data, and because it forces the application to hold schema rights it
should never have. These two decisions come as a pair.

## D-014: The interface is REST, not GraphQL

Each endpoint is one operation with one explicit authorization check, so
the authorization surface stays countable and testable. GraphQL was
rejected because it spreads authorization across a query graph, which is
where authorization mistakes hide.

## D-015: Version one scope is four operations, files in, reports out

Confirmed scope: an operator authenticates; a snapshot file is imported,
append-only; the enriched inventory is viewed and can produce a
self-contained risk report plus escaped CSV and JSON exports; governance
(owner, flag, attestation) is recorded in role-call only.

Two sub-decisions carry the reasoning. Ingestion is file import only in
version one, because the fresh-clone demo must run with Docker alone and
nothing else, and everything runs locally before it runs in the cloud; the
live read-only pull joins in the cloud phases as an adapter behind the
same ingestion. The report ships in version one rather than later because
a self-contained risk artifact is how this class of findings actually
travels between people, a pattern proven publicly by Cloudsplaining, and
the fields it needs already exist in the inventory view. A live pull in
version one was rejected; a view-only version one was rejected.

## D-016: An identity is keyed by the provider's immutable identifier

In AWS, a deleted principal can be recreated under its old name, and the
new principal carries the old name and Amazon Resource Name (ARN) with a
fresh immutable unique identifier underneath. Keying identities by name or
ARN would therefore let a recreated principal inherit a dead identity's
governance standing: its owner, its flags, its attestation history, its
reviewed-last-quarter credibility. So an identity is keyed by the account
plus the provider's immutable identifier; names and ARNs are display
attributes. A recreated principal is a new identity, and the reuse of a
governed name is itself surfaced as a finding, because resurrection is
exactly the move an attacker inside the account would make. Keying by ARN
was rejected for that reason.

## D-017: Three roles from the first commit

Version one ships three roles: a viewer reads the inventory and reports,
an operator imports snapshots and performs governance actions, and an
administrator manages accounts and users. A single role was rejected
because a governance tool's audit trail is only meaningful when the person
who views a finding and the person who attests it can differ, and because
an earlier build documented the one-role gap rather than fixing it;
this build starts past it. Authorization failures return 403 and are
distinct from authentication failures from the first commit. Sample users
for each role ship with the demo data.

## D-018: Local sign-in first, single sign-on at the cloud phases

Version one authenticates against local credentials: passwords hashed with
bcrypt, verification that costs the same whether the account exists or not
(a dummy comparison for unknown names, so response timing cannot enumerate
accounts), and a stated byte-length cap ahead of the hash. Local-first
follows the same reasoning as file-first ingestion: a stranger with only
Docker must be able to run the demo, and single sign-on requires an
identity provider the fresh clone does not have. Single sign-on (OpenID
Connect) joins at the cloud phases, and the local login then becomes a
break-glass path. A single-sign-on-only version one was rejected.

## D-019: Identities act, privilege sources grant, and both are governed

The model holds two governable kinds. Identities (users, roles, the root
account) can act: they authenticate, hold credentials, and carry liveness
enrichment. Privilege sources (groups now, and policies as they earn it)
cannot act but grant: they carry membership, policy, and privilege
enrichment instead. Governance records, meaning owners, flags, and
attestations, attach to both, because access review in practice certifies
group memberships as much as it certifies actors, and the remediation for
an over-privileged member is usually a change to the group, so the
group must be first class for the fix to be trackable.

Consequences built in from the start: every privilege in an identity's
summary names its source, direct or through which group; membership is
observed per snapshot, so a member appearing in a privileged group
between snapshots is a finding; an empty privileged group and an unowned
privileged group are both findings on the group itself; and groups never
appear in the identity inventory pretending to be actors.

Two alternatives were rejected. Treating groups as identities blurs what
acting means and hangs liveness questions on things that cannot log in.
Treating groups as mere policy carriers, attributable but not governable,
was this decision's own first draft, rejected because it could not hold
an owner or an attestation for the object where real access reviews
actually happen.

## D-020: Encryption at rest is the deployment layer's job, stated

role-call stores no secrets: no credential values, no tokens, nothing
whose disclosure is worse than the inventory itself. Field-level
encryption of the stored policy documents was considered and rejected: it
adds key management and rotation burden to protect documents that any
reader of the target account can already fetch, which is cost without
commensurate gain. The inventory's confidentiality controls are
authentication and authorization on every request, the egress allowlists,
and encrypted storage at the deployment layer (the disk and the database
service), which the runbook states as a deployment requirement rather
than assuming. If a future field ever carries a secret, this decision is
revisited before that field exists.

## D-021: Version one gains the review campaign, shaped by the reviewer

The published codifications of this work (PCI DSS 4.0 requirements 7.2.4
and 7.2.5, ISO/IEC 27002 5.18, NIST AC-2 and AC-6(7), CIS Control 5, and
the audit practice around SOX and SOC 2; see the compliance section of README.md) all define
the unit of governance as a periodic, scoped, evidenced review. Version
one therefore adds, on top of the four confirmed operations: review
campaigns (a scope of identities and groups, assigned reviewers, a due
date, item-level progress, and a close); a purpose governance record,
answering the reviewer's first question, what is this for; the delta
view, what changed since the last certification, computed from snapshot
differences; a recommended disposition per item with its evidence stated;
and a per-campaign evidence export carrying the population statement,
every decision, its actor, and its time.

Review dispositions include "insufficient evidence," with the reviewer
saying what was missing. That is a first-class outcome, not a skipped
row: it appears in the campaign report, and the rollup of what reviewers
found missing steers what the product adds next.

On scheduling, considered rather than assumed: real programs run
quarterly and semiannual big-bang campaigns under SOX and PCI, annual
recertification under federal regimes, and risk-based frequencies for
system accounts. Version one gives a campaign a due date and an optional
recurrence preset (quarterly, twice yearly, yearly), and completion over
time is inherent because items are decided individually while the
campaign tracks progress. Rejected for version one: arbitrary schedule
configuration, which is maintenance surface without a named user, and
rolling event-triggered micro-reviews, which are a real modern practice
that deserves its own later decision once campaigns exist to hang it on.
Auto-applied decisions are rejected permanently here as they were in
D-005.

This decision also names the method it came from: the design phase takes
the reviewer's and the auditor's itemized needs as first-class inputs
beside the threat model, user first and security first together, and the
framework references run in both directions through the README's compliance section.
## D-022: Ruff is the linter, and commented-out code is a finding

Ruff was vetted at build time as subphase 1.1 planned: one binary, no
plugin tree to audit, active maintenance, and rule families that cover
correctness, import order, known bug patterns, outdated idioms, and
security checks. The deciding rule family is ERA, which flags
commented-out code. The standards already forbid deferred-work markers;
commented-out code is the same debt in another form, and now a gate
catches it instead of a human eye. The alternative, flake8 with
plugins, spreads the same coverage across a half-dozen separately
maintained packages, which is more supply chain for the same result.
Formatting is not enforced in version one: a formatter is a one-line
addition later, and the linter is the part with security value.

## D-023: One tool audits the tree and writes the bill of materials

pip-audit both checks the pinned dependency tree against known
vulnerability databases and emits the software bill of materials in
CycloneDX form. One vetted tool, two supply-chain artifacts. The bill of
materials is generated fresh by continuous integration on every run and
published as a build artifact rather than committed, so it can never
drift from the requirements file it describes; the requirements file
with its hashes remains the single tracked source of truth. The
alternative, a dedicated generator beside a dedicated auditor, is a
second tool to vet and pin for no additional information.

## D-024: The machine never decides

The automation doctrine, named after living implicitly in D-005 and
D-021. Automation in role-call carries out what a person already
decided, inside bounds that person set: a review window that closes on
its own schedule, an approved re-elevation the clock takes back, a
drafted right-sizing change waiting as a diff for an owner to approve.
Automation prepares, schedules, executes, and verifies. It does not
grant, revoke, or certify on its own judgment, and every automated
action traces to the person who decided it and the bounds they chose.

This replaces the blanket phrase "never automation," which was both
stronger than the recorded decisions and contradicted by the design
itself, whose re-elevation expiry is a machine revoking access
legitimately. The line that matters is not whether the machine acts
but whether it decides. D-005's choice of enrichment over automation
and D-021's permanent rejection of auto-applied certification
decisions both stand; this decision names the boundary they were
circling.

## D-025: The pipeline guards itself

One deliberate batch, five tools, each doing for the pipeline and the
documents what the earlier gates do for the code. CodeQL runs deep
static analysis on the application and on the workflows themselves,
weekly as well as per push, so a new query pack finds old code.
actionlint lints the workflow files; zizmor audits them for the
security mistakes workflows invite, and both ran against this
repository before they were adopted, which is the vetting. The OpenSSF
Scorecard rates the repository's own posture and publishes the result,
so the score is checkable rather than claimed, and its check list is a
standing audit of practices not yet adopted. lychee checks the
cross-references between documents, offline, fetching nothing.

Provenance, stated: CodeQL and Scorecard run as actions pinned by
commit hash, from GitHub and the OpenSSF respectively. actionlint and
lychee are single binaries verified against their published checksums.
zizmor publishes no checksum, so its pin is the hash of the artifact
inspected at adoption; a changed artifact fails the pipeline. Every
binary added to the pipeline widens the set of pins nothing watches
for staleness, which is a recorded cost, carried knowingly.

## D-026: Sessions are opaque rows, and the database never holds a token

A signed stateless token (a JSON Web Token) was considered and
rejected for version one: statelessness buys horizontal scale this
deployment does not have, and it costs the one property a governance
tool cannot give up, the ability to revoke one session now and know it
is dead. Sessions are rows: an opaque 256-bit random token goes to the
client, and the database stores only its SHA-256, so a database leak
yields nothing a client can present. Plain hashing is correct here
where it would be wrong for passwords, because the values are random
and cannot be guessed offline. Expiry is absolute from sign-in rather
than sliding: a stolen token dies on schedule no matter how actively
it is used. The cost, one database read per authenticated request, is
the right trade at this scale.

## D-027: The sign-in rate limiter is forty lines owned here

The library route (slowapi wrapping limits) was vetted and declined:
two more supply-chain entries, storage backends and decorators this
application does not need, for one policy on one route. The limiter
written here counts failures per username and per client address over a
sliding window; success clears the username key so a user who finally
types the right password is not locked behind their own mistakes, and
deliberately does not clear the address key, so a valid login cannot
refill an attacker's allowance. Failures are limited, accounts are
never locked, because lockout hands an attacker denial of service
against any username they can spell. State lives in process memory,
which is stated plainly: version one deploys as one process, a restart
clears the counters, and the control's job is slowing online guessing,
not surviving restarts. Forwarded-for headers are not consulted; they
are attacker-writable, and the deployment layer owns address
translation when it arrives.

## D-028: Every change lands through a pull request

The method change, adopted at the start of subphase 1.3: work happens
on a branch, the subphase's pull request carries the review evidence,
the required checks must pass, and the merge is the review's public
receipt. Main now refuses direct pushes outright, alongside the
existing force-push and deletion blocks, so the review gate that
previously ran invisibly on one machine is enforced by the server and
visible to any reader.

What is deliberately absent: required approvals. One person cannot
review their own work in any meaningful sense, and a self-approval
dressed up as review would be the exact theater this project refuses.
The controls are the checks and the deliberate merge; the accepted
risk in the threat model narrows from "direct pushes on trust" to
"no second review of changes," with the first collaborator as the
exit condition. Merges are plain merge commits, never squashes, because
the small-commit history is the record and flattening it would
destroy what review reads.

Dependabot's update pull requests flow through the same gate, which
also means the update path is now check-gated by construction.

## D-029: What the credential report cannot say, and what stands in

Verified against the provider's documentation at build time, the
credential report's content carries neither a generation timestamp nor
any immutable unique identifier. Two rules follow.

Capture time is operator-attested. The enumeration wanted it from file
content, and for this file that is impossible; inferring it from the
newest timestamp inside the report was rejected because a quiet account
would date its snapshot days early and staleness math would lie.
The operator supplies the capture time at import, it must carry a
timezone and must not be in the future, and it is content-authoritative
wherever content exists: the account number still comes only from the
rows themselves.

Identity keys from this file are provisional. D-016 forbids keying by
name or ARN because a recreated principal inherits both; the only
immutable content available is the ARN paired with the user's creation
time, which a recreated principal cannot reproduce. The provisional key
hashes that pair, the identity row says provisional plainly, and the
authorization details import upgrades it to the provider's real
identifier by matching the same pair. Resurrection still mints a new
identity, which is the property D-016 exists to keep.

## D-031: Status claims are gated, with the journey diagram as the source

A session review found the public documents materially stale: the
roadmap still said the design phase was in progress and no application
code existed, the security document said the application did not exist
while listing five built controls as planned, and the README
undercounted the merged subphases. The failure was structural: the
subphase-close ritual covered the diagrams and the repository
description but never the document set, and a figure that lives in
several files drifts, which is the same disease the derive-don't-store
rule treats in data.

The mechanism: the journey diagram is the single source for the build
status figure, because the close ritual already moves it. A pipeline
and pre-commit check reads the figure there and fails when the front
door or the roadmap disagree, and it forbids outright the specific
claims that sat false in public, so those sentences can never return.
Prose accuracy beyond the figures stays with the close ritual, which
now names the document set explicitly; the gate holds the numbers, the
ritual holds the words.
## D-030: The authorization details file, taken at its word and no further

Four rules from the build-time verification of the provider's
documentation. A true IsTruncated flag rejects the whole file: a
truncated export is an incomplete snapshot, and importing it would
record absences that are artifacts of pagination, the exact false
comfort D-006 exists to prevent. Policy documents arrive URL-encoded
and are decoded before parsing, bounded, with pre-decoded objects
accepted from exporters that already did the work. A user's group list
carries names, not identifiers, so membership resolves against the
groups named in the same file and is recorded as observed identifiers
on the group's observation. Provider-managed policies carry the
literal account "aws" in their identifiers and are exempt from the
one-account claim, recorded with an aws-managed flag; every other
identifier in the file must agree on one account or the file is
rejected whole.

The stored take: only the default version of each managed policy's
document is kept per snapshot, because that is the version in force,
and the findings this feeds (1.6) judge what is in force, not what is
drafted.

## D-032: Findings explain themselves, in three tiers, on a watched clock

The credential findings arrive with the derivation engine, and three
choices shape them. Tiers are the triage order a human works in,
critical, warning, notice, because severity taxonomies with more
levels than a person has attention produce sorting, not action. The
minimum observation age gates the unused finding: an identity is not
flaggable as unused until it has been watched fourteen days, because a
new key that has not been used yet is new, not stale, and a false positive on day one costs the tool its credibility
(the eligibility lesson from the prior art, credited in
the acknowledgements in README.md). Staleness is always computed against the
account's newest snapshot capture time, never the wall clock, so an
old import shows its age instead of silently accruing findings.

Every finding carries its OWASP Non-Human Identities Top 10 identifier
and an explanation containing the numbers that triggered it, because a
finding that cannot explain itself is an accusation, and the review
these findings feed runs on evidence.

## D-033: Privilege read by capability, attributed, with limits stated

The hardest-call subphase, and three choices carry it.

Detection is capability-shaped, never name-shaped. A policy called
ReadOnly that can rewrite its own default version is administrator
access; a policy called FullAdminLegacy granting three read actions is
not. The heuristics read what a document permits: every action on every
resource, the wildcard breadth underneath that, identity-mutating
operations, and the escalation combinations from the published research
credited in the README's acknowledgements, including the pair where passing a role
into a compute service is ordinary on either side and an escalation
together. The escalation finding is reported only for identities that
are not already administrators, because an administrator reaches every
path by definition and listing them there buries the finding that
matters: the principal nobody calls an administrator that can become
one.

Every capability names its source. "This account is over-privileged" is
an accusation; "this account holds administrator access through the
automation group, and can rewrite its own policy through an inline
policy it holds directly" is something a human can act on. Inline
policies are stored and attributed by the provider's immutable
identifier rather than by name or address (D-016), because two
identities share an address during a resurrection window and the dead
one must not inherit the live one's privilege.

The limits ride with the claims rather than living in a footnote.
Version one reads grants, not effective permissions: an explicit deny
is noticed and not evaluated against the allow it narrows, a condition
is noticed and not interpreted, and privilege reachable by assuming
another role is not computed at all. Each finding that rests on a
document carrying a deny or a condition says so in its own text. The
consequence is stated once here and inherited everywhere: this reading
can overstate a grant that a deny or condition narrows, and it
understates anything reachable through a chain.

Tuning is part of the design, not a later polish. Wildcards over read
operations are separated from wildcards that can change things, because
the provider's own read-only policies grant read wildcards on every
resource, and scoring those like write access is exactly how a tool
earns the reputation that gets it muted.

## D-034: The plan mixes three methods, and one of them was misapplied

The subphase decomposition was never written against a single named
method, and the question of which one it followed is fair, so the
answer is recorded rather than left implied.

Three methods are in the plan, deliberately. The first subphase is a
walking skeleton: the thinnest end-to-end thread through container,
database, migrations, configuration, logging, and a served route, so
the architecture is proven before anything is built on it. Everything
after it is dependency-ordered layering: identity before data because
every route needs the role checks, parsers before the engine because
reading real data before designing against it is the lesson this
project inherited, credential findings before privilege findings
because the second carries the hardest calls. Two constraints ride on top:
every subphase must end in something that runs and can be shown, and
controls arrive with the thing they protect, which is why there is no
hardening phase.

Vertical slicing, the dominant modern prescription, was not used, and
the cost is real: five consecutive subphases produced no surface a
person could click. The reasons for the choice are that the record is
the deliverable here rather than a shippable increment, that a solo
build has none of the cross-team integration risk vertical slicing
exists to reduce, and that layered order produces cleaner review
boundaries and cleaner decision entries. The mitigation is that every
subphase ends demonstrable through the interface that exists at the
time, which for the middle subphases meant the documented API rather
than a screen. An engineer who prefers slices would push
here, and the push would be fair.

Risk-driven sequencing was also inverted on purpose. The hardest-call
work sat sixth rather than first, because the risk retired earliest was
the shape of the real data, and heuristics designed against imagined
data would have been rewritten anyway.

Where the ordering was wrong: sample data. The synthetic generator
sat eleventh while every subphase from the first parser onward needed
demo input; the incident record in AI-USAGE.md carries what that cost
and what caught it. The correction decided here: the generator moves
to seventh, ahead of the frontend, so the remaining subphases
demonstrate against realistic data; the stranger drill stays at the
end, inside the proof, because a fresh-clone run of the finished demo
cannot happen before the demo is finished; and the count stays at
twelve, so the status figures and their gate stay valid and the
earlier subphases keep the numbers their transcripts already cite.

## D-035: The sample account is generated, committed, and checked

The demonstration data is produced by code in the repository, shipped
as files beside it, and guarded by a test that regenerates and compares.
Each of those three exists for a reason.

Generated, because input made by hand was wrong three times in three
subphases: an invented creation time, a false finding produced by that
same mismatch, and a capture time dated in the future. The system
caught all three and the author caught none, which is the argument for
deriving fixtures rather than typing them.

Committed, because a stranger with only Docker should not have to run a
generator before seeing anything, and because files in the repository
are readable in a browser by someone deciding whether to clone.

Checked, because those two choices together are exactly the drift the
derive-don't-store rule exists to prevent, and the answer is the
one-source pattern the role matrix already uses: the generator is the
source, the files are its output, and a test fails the build if they
disagree.

The generator is deterministic and refers to no clock: three fixed
snapshot generations a month apart, every date a literal. That is only
possible because staleness is measured against a snapshot's capture
time rather than the wall clock (D-006), so the sample stays meaningful
without maintenance, and it is what lets the comparison test exist at
all.

Completeness is the property that matters most and is asserted rather
than hoped: a test imports the shipped files and fails unless every
finding the engine can produce appears, because a demonstration that
exercises half the rules teaches a reader that the other half are
decorative. Two identities are deliberately quiet for the same reason:
a tool that finds something everywhere has found nothing.

## D-036: The page renders text, holds its token in memory, and ships plain

Three choices, and the first is the security control this subphase
exists to install.

Every value the page displays is written through the document's text
interface, never through a markup sink. Identity names, tags, and
policy text all arrive from imported files, which makes them attacker
content by definition, and the answer is structural rather than
vigilant: the page contains no sink for markup to reach, so escaping
is not something a future edit can forget. A test scans the script for
those sinks and fails the build if one appears, which turns the
promise into a gate; the content policy forbids inline script and
style, and a second test proves the page needs neither, so the policy
can stay strict. Values are never sanitised on the way in or out,
because a tool that quietly rewrites what it found has started lying
about what it found; the hostile name is stored exactly, displayed
exactly, and displayed as text.

The session token lives in a closure variable and never in browser
storage. The cost is real and accepted: a refresh signs the operator
out. The benefit is that the token is not sitting in a place any
future script can read, and this application's whole subject is
credentials that outlive their purpose.

No build step, no framework, no package manager for the page. The
stated cost of the alternative is a second toolchain to pin, audit,
and keep current beside the Python one, for a page that renders tables.
The stated cost of this choice is that the page will stay plain, which
is acceptable while the questions this tool answers, not the interface
it answers them through, are what the project is about.

## D-037: The posture score publishes, and stays out of code scanning

The scorecard's findings were being uploaded into code scanning, where
they became pull request alerts. The consequence showed up on the
first pull request after the frontend landed: a check reporting a high
severity security alert, which turned out to be the repository having
no second person reviewing changes and no fuzzing subphase yet. Both are recorded
accepted risks. Neither is a defect in the change under review, and no
pull request can fix either.

A gate that fails on findings the change cannot address is the alarm
that is always red, and this project already refuses that pattern
where scanners are concerned. So the score keeps publishing, where it
is read from the public scorecard and cited in the security document,
and nothing is written into code scanning. The five alerts already
sitting there were dismissed with that reason recorded on each.

The tool keeps its scoped permission for publishing and loses the one
that wrote findings, which is least privilege applied to a workflow
after learning what it actually needs.

Two smaller pipeline decisions ride with it, both from the same run.
Tool downloads retry, because a reset connection is a network event
and not a build result. And the checks workflow runs on pull requests
and on main rather than on every branch push, with a concurrency
group, because the duplicate run taught nothing and doubled the
exposure to exactly the network blip that failed this one.

## D-038: The owner is typed, and teams are the default

Governance records arrive as an append-only human layer: owner,
purpose, flag, and attestation, on identities and groups, each record
attributed to the person who wrote it and closed rather than edited
when it is superseded or cleared, which is the observation model
applied to human statements.

The owner is not a string. It carries a type: team, business unit,
individual, vendor, or unknown. The reasoning starts from this tool's
own opening finding. An individual owner is the orphan in waiting: the
person leaves, nothing in the provider changes, and the identity keeps
its keys and its privilege with nobody accountable, which is improper
offboarding, the finding class the engine leads with. A tool that
encourages individual ownership manufactures its own top finding, so
the interface and the documentation treat a team as the normal answer.
An individual owner on a privileged identity is reported as a notice
that states the exposure and leaves the judgment to the reader.

Review practice still wants a named person who signed. That need is
met without giving up the durable owner, because the two were never
the same thing: the owner is who answers for the identity over time,
and the attestor is who looked on a given date, which the attestation
record and the audit row already capture with attribution.

An assigned owner outranks the owner tag, because the assignment is
the deliberate human input this table exists to hold, while the tag is
an observation like every other imported field. The unowned finding is
answered by an assignment, which makes it clearable inside role-call
rather than only by re-tagging the provider. A disagreement between
the assigned owner and the tag is surfaced as its own notice naming
both values, because a silent winner would hide exactly the staleness
a governance tool exists to show.

The rejected shape is the three-field enterprise answer: cost centre,
application identifier, and engineering team. They answer different
questions and real organizations track all three, but with no
directory or configuration source to validate against, three free-text
fields are three fields of typos. One typed field now, and the split
becomes worth revisiting when an integration arrives that can validate
at least one of them.

Attestation is open to all three roles, while owner, purpose, and flag
writes stay with the operator and administrator, because stating "I
looked at this and it is still needed" is exactly the reviewer's act,
and changing who answers for an identity is not.
## D-039: The campaign freezes its population, and nobody certifies in bulk

A review campaign resolves its scope into items once, at creation,
with each item carrying the evidence as it stood: the findings, the
owner, the privilege sources, the liveness. The population statement
in the evidence export describes that frozen set, which is what makes
it a statement rather than a moving target.

Every disposition is one item, decided by one person, recorded with
attribution and its audit row in the same transaction. There is no
operation anywhere in the application that disposes more than one
item, because a certification records that someone looked at that
identity, and a button that certifies a hundred rows records that
nobody did. A decision is final within its campaign; a changed mind is
the next campaign's decision, which preserves what was believed
when.

Insufficient evidence is a first-class answer that must name what was
missing, and the rollup collects those notes across campaigns: one
recurring line is a reviewer's problem, the same line across a column
is the program's problem. Close refuses while any item is undecided,
because an access review with gaps is a false population statement.
Recurrence is a preset the next cycle is created from by a person;
the machine recommends with reasons and never decides (D-005).

The engine's recommendation order is deliberate: too little
observation history outranks everything, because a verdict built on
four days of watching is a guess presented as a
verdict; then revocation
signals; then the tier weight; then the quiet default.

## D-040: The report renders through an engine that escapes by default

The risk report is a single self-contained file, built to be opened
from disk years later, which means it runs with no content security
policy and no server headers: whatever is in the file is what
executes. So the report is built by a template engine that escapes
every interpolated value by default, contains no script element at
all, and inlines its styles in the one file.

The engine is Jinja2, vetted at adoption: maintained by the Pallets
project alongside the framework family this application already
trusts, pinned by hash like every dependency, with automatic escaping
selected explicitly rather than assumed. The alternative was
hand-escaping each interpolation in string-built HTML, which is the
pattern where one forgotten call reintroduces the class; the engine
removes the class the way the ORM removes query injection.

The other two exits get the escaping their format needs. CSV cells
that begin with a formula character are prefixed so a spreadsheet
reads them as text, because identity names and tags are controlled by
the observed account's users and a name that starts with an equals
sign is a program. JSON is exported raw, because JSON is data and its
consumers parse rather than interpret; escaping it would corrupt the
values auditors compare against the provider.

## D-041: The proof subphase, and what its checks are allowed to block on

The last subphase is the one that proves the others, and each of its
mechanisms records what it may block a merge on, because a gate that
is always red teaches the eye to skip it (the D-037 lesson, applied
in advance).

The coverage floor is 90, set under the measured 94 at adoption: it
catches erosion without inviting tests written to move a number. The
mutation check is a fixed, reviewed set of seven mutations, each
removing one named control and requiring the tests that claim that
control to fail; fixed rather than generated, so the kill list is
readable in one screen and the check runs in minutes. Generated
mutation sweeps stay a local exploration tool. The check earned its
place on its first run by surviving a broken token hash: nothing
proved a fabricated token was rejected, and now a test does.

The container file is linted, and the base image's operating system
packages are scanned with a deliberate split: the merge blocks only on
critical findings that have fixes, because there the fix is moving the
digest, which a pull request can do. Findings without fixes are
reported for the record; failing on them would be an alarm nothing in
this repository can answer. Adopting the scan surfaced that the pinned
base was months behind its rebuilds, and the digest moved in the same
change, which is the scan doing its job before it was even merged.

The request budget: uploads were already bounded in memory, the
keep-alive timeout is now stated in the serve command, and imports and
campaign creation carry a per-user write budget of thirty per minute,
far above any human pace and below any useful abuse. State for that
budget is process memory, the same stated limitation as the login
limiter (D-027).

The route surface is now a documented enumeration asserted against the
live route table in both directions. Adding that assertion exposed
that the framework had begun wrapping included routers lazily, which
had quietly made the existing drift test vacuous: it was checking
three routes and passing. The flattened enumeration carries a count
canary so the next framework change fails loudly instead of passing
silently, and the incident is the strongest argument this subphase
will make for asserting what a test actually sees.
## D-042: Least privilege at the container boundary, verifiable by command

The compose stack now runs both services with a read-only root
filesystem, no privilege escalation route, dropped capabilities, and
bounded memory and processor use, and the database publishes no host
port at all: only the application container can reach it. Migration
authoring against the real database attaches through the compose
runtime when it needs to, because a standing listener for an
occasional task is a standing surface for everything else.

The application container drops every capability, since serving HTTP
as an unprivileged user needs none. The database container drops
everything and adds back the five its entrypoint genuinely uses to
take ownership of a fresh data volume and step down to its own user:
change ownership, set user and group, file owner operations, and the
discretionary access override that lets it traverse the volume before
owning it. That list was found by dropping everything and reading the
failure, rather than by copying a recommendation.

Temporary filesystems back the paths that must accept writes, so
nothing an attacker writes to the application container survives a
restart. Every claim in this decision is verifiable by command against
the running stack, and the commands are printed in the README, because
a hardening claim without its probe is only a claim.

## D-043: The pipeline runs on a clock as well as on change

The checks workflow gains a weekly scheduled run beside its pull
request and merge triggers. The reason is that two of its gates judge
subjects that move while the code sits still: the base image scan
watches for fixes shipping against the pinned digest, and the
dependency audits watch for new advisories against pinned trees. A
pipeline that runs only on change discovers those the next time
someone proposes an unrelated pull request, which is late, and that
pull request then fails on findings it did not cause, which is the
alarm blaming the wrong thing.

A scheduled failure lands on the main branch's workflow view, blocking
nobody, and its remedy is the same as always: a pull request moving
the digest or the pin, which the gate then judges. The schedule sits
on Tuesday, offset from the Monday runs of the analysis and scorecard
workflows, so one bad platform morning cannot blank every signal at
once.

The rejected alternative was leaving discovery to pull request
cadence, which had been the quiet status quo. It worked while
subphases landed daily; with Phase 1 closed and the pace now set by
review rather than construction, quiet weeks become normal, and a
watcher that only watches when someone happens to knock is not a
watcher.

## D-044: Commits are signed, and the repository grades itself

Two changes from one question: would this application pass the
provenance bar it applies to its own dependencies. It would not, and
the response is to fix what is cheap and record what is not.

Commit signing starts now. Commits are signed with a dedicated SSH
key, registered with the hosting account as a signing key, so
authorship stops resting on account control alone. The key carries no
passphrase, a deliberate trade: a signing key on a controlled
workstation that prompts on every commit gets worked around, and a
control that gets worked around protects nothing. History before this
decision stays unsigned, because rewriting published history to
backfill signatures would destroy the very record the signatures
exist to protect; the boundary is stated instead of hidden.

The rest of the self-assessment lives in SECURITY.md as its own
section, because a repository that demands canonical sources, pinned
artifacts, and verifiable claims from every dependency owes its
readers the same examination of itself: what passes, what fails, and
why each failure is accepted or scheduled rather than denied.

## D-045: The agent proposes under its own identity

The work was always authored by the agent and reviewed by a person,
but the platform could not see it: everything ran under the one human
account, which made that account the recorded author of changes it
actually reviewed, and made a required approving review impossible,
since an account cannot approve its own pull request. The recorded
compensation was D-028's zero-approval ruleset, honest but weaker than
the reality it stood in for.

The agent now holds a GitHub App identity, owned by the human account
and installed on this repository alone, with two permissions: contents
and pull requests. Pull requests are opened by that identity; the
human's approval becomes a required, recorded review by a party other
than the author, which is what it always was in fact. The ruleset
moves from zero required approvals to one.

The trade accepted knowingly: a standing private key on the
workstation, held outside every repository with owner-only
permissions, revocable in one click from the account, minting
one-hour tokens supplied to git through a credential helper from
memory, never as part of a URL, because the first run proved a
credentialed URL leaks into local configuration through the upstream
flag; a commit-time gate now watches that file (the incident and the
ruling are in AI-USAGE.md). Against it, the
narrowing: the agent's routine operations previously rode a user
token scoped to every repository the account owns; the app reaches
one repository with two permissions.

Two boundaries stay stated. Commit authorship and signing are
unchanged, so the gain is at the proposal and review layer, not a
rewrite of the commit record. And this adds no second person: the
self-assessment's more-than-one-set-of-eyes row still fails, because
making one review legible does not make it two. The rare pull request
the human authors himself is handled case by case when one exists.

## D-046: The namespace denies by default, and names its three flows

Network policy starts from nothing: a default-deny policy for both
directions, then exactly the flows the system has. The application
reaches the database and the resolver; the database accepts the
application; the application's port accepts ingress, because the
reachable boundary is the kind port mapping, which binds to loopback
only, and the cluster cannot know which host addresses are friendly
where the host already refuses everything nonlocal. The database gets
no egress at all, because it initiates nothing.

Each denial is proven by a probe, not assumed from the manifest: a
non-application pod hanging against the database port, the application
hanging against an address that is not the database, and the allowed
path connecting, all run against the live cluster before this entry
was written. Calico was installed in 2.1 precisely so these are
enforcements rather than annotations the default plugin ignores.

## D-047: Admission refuses what the files forgot

Two layers at the gate. The namespace enforces the restricted Pod
Security Standard, so a pod that escalates, runs as root, keeps
capabilities, or skips its seccomp profile is refused at creation;
the workload manifests already satisfied it, and the label converts
that compliance from practice into refusal. A validating admission
policy requires every image to be digest-pinned, extending the
repository's pin discipline to the cluster, with one recorded
exception: the application's own image is built locally and loaded
into the cluster, never pulled, has no registry digest to pin, and
imagePullPolicy Never makes any registry substitution a loud failure.

Workload identity is minimized rather than managed: each workload gets
a service account with no permissions and no mounted token, because
the application needs nothing from the orchestrator, and a token that
is not in the pod cannot be stolen from it. Both refusals and the
token absence were verified against the live cluster, including the
case that separates the layers: a fully compliant pod with an unpinned
image, refused by the digest policy alone.

## D-048: Manifests get the schema and posture treatment

kubeconform validates every manifest against its API schema in the
pipeline, and kube-linter reads the same files for posture. Both were
vetted the standard way: fetched from canonical releases, checksummed,
and run here before adoption. Both passed on first contact, which is
not the tools failing to look but the D-042 posture having arrived at
the cluster already hardened; the admission policy kinds are skipped
by the schema check because the public schema registry lags the API,
and the live cluster validated those objects itself.

## D-049: Agent permission changes are recorded as need, request, approval

The agent's identity gained one permission, and the change is recorded
in the shape every future one must follow: the need, demonstrated
before requested; the request, scoped to exactly what the need shows;
the approval, human, explicit, and in two parts, because the platform
separates granting a permission on the app from accepting it on the
installation, and that second consent means an installation never
silently inherits whatever the app later asks for.

The instance. Need: the agent proposes continuous integration changes,
and its push carrying a workflow edit was refused by the platform for
lacking the workflows permission, the least-privilege model
demonstrating the gap rather than a design document asserting it.
Request: workflows read and write, that permission alone, made in
session with the refusal as evidence. Approval: granted on the app and
accepted on the installation in two explicit clicks, then verified by
reading the installation's live permission set from the API, which
answered contents write, metadata read, pull requests write, workflows
write, and nothing else.

One more reason this arrangement earns its place, observed by the
human reviewing under it on its first day: an approving review
requires opening the changed files, where a merge button alone does
not, and a review path that makes reading the diff the road to the
button gets the diff read. The mechanism does not merely record the
review; it produces it.

## D-050: Releases exist, versioned by phase, attested by the platform

The version scheme reads from the roadmap: v0.N means the work through
phase N is complete, with a third number for fixes between, and v1.0.0
is reserved for the day the version one scope deploys somewhere real.
A version a reader can decode against the phase list beats a counter
that means nothing without a changelog.

A release starts with a signed tag, the same key that signs every
commit (D-044), so the pointer to the release carries the same
authorship proof as its history. The workflow builds a source archive
from the tag, packages the sample account, generates the software bill
of materials from the same hash-pinned tree every pipeline job uses,
checksums all of it, publishes the release, and attests build
provenance for every artifact through the platform's attestation
service. A consumer verifies with one command, printed in the README,
and the verification answers from the platform's transparency log, not
from this repository's own claims.

This answers the self-assessment's first failing row: role-call
demanded a canonical, pinnable released artifact of every dependency
while offering none itself. It now offers one. What it still does not
offer is a registry-published package or container image; publishing
the image is a new public surface with its own maintenance duty, and
it stays deliberately behind its own decision for the day a consumer
exists who wants to pull rather than build.

## D-051: D-013 is honored, and the finding is part of the record

A direct question, how is the database protected, was answered by
reading the code instead of the decision record, and the two
disagreed: D-013 decided that migrations run as a privileged role and
the application's role holds data rights only, rejecting schema
changes at application startup in so many words, and the build did
the rejected thing from the first subphase, one owner role running
migrations inside the serving container's start command. The threat
model cited database least privilege on the strength of a decision
the code never implemented. Eighteen subphases passed without anyone,
human or agent, checking the claim against the running system, which
is this project's own first rule applied nowhere.

The implementation now matches the decision. A separate migration
step, a one-shot service on Compose and an init container on the
cluster, is the only holder of the owner credential; it applies
migrations and maintains the runtime role's grants. The application
connects as a role that can read and write rows and touch sequences,
and nothing else: no schema rights, and no delete, because the
application never deletes a row by design, so the append-only tables
are now append-only even against the application's own credential.
Future tables inherit the same grants through default privileges, so
no one has to remember. The pipeline holds it: a probe connects as
the runtime role, reads data to prove the grant, attempts a schema
change, and fails the build unless the database refuses.

Two smaller repairs ride with this entry, from the same audit: the
administrator can now end every session a user holds in one audited
act, turning the threat model's promised stolen-token answer into a
control with a test; and three accepted-risk rows were reworded to
current truth, including the one whose promised exit, hash chaining
with the campaign work, passed unmet and now says so.

-------------------------------------------------------------------------------

## D-052: GuardDog scans the pinned trees for malware shapes

**Date:** 2026-08-22

**Decision:** the pipeline runs DataDog's GuardDog over both pinned
requirement trees, in the container job, from the official image
pinned by digest, blocking.

**Why.** The dependency audit answers one question, known published
vulnerabilities against the pins, and nothing in the gate set
answered the adoption-time question: does this package behave like
malware. Typosquats, install-time execution, and exfiltration shapes
have no advisory on day one, which is exactly when they arrive. The
canonical-source check approximates the answer by hand at adoption;
GuardDog mechanizes it and re-asks on every run.

**Vetted before adoption, not assumed.** A benign package scanned
clean; both of this repository's pinned trees scanned clean; and a
planted package carrying install-time shell execution, an encoded
exec, and a suspicious address was flagged at high risk with all
three shapes named. The pip install of the tool was rejected in favor
of the official container image because the tool's own dependency
tree is heavy and does not belong in this repository's hash-pinned
trees; the image runs digest-pinned, and the digest-parity check
watches the digest, since update automation cannot see images
embedded in workflow files.

**Rejected: CodeFactor**, a hosted quality grader considered the same
week. It duplicates properties already held deterministically, ruff,
strict typing, CodeQL, and the mutation check, and costs a standing
third-party grant of repository access, which the identity-scoping
policy exists to minimize. A letter grade adds no property the
published scorecard does not already state from a party already
trusted.

-------------------------------------------------------------------------------

## D-053: The Python floor is 3.11, held by execution

**Date:** 2026-08-24

**Decision:** the application supports Python 3.11 and newer, states
it in the README, and holds it with a pipeline job running the whole
suite on 3.11; the shipped image stays on 3.14.

**Why.** An outside review found that the repository only imported on
Python 3.14 and crashed on 3.11 through 3.13 with an unexplained
NameError. The cause: 3.14 made annotations lazy, so a class whose
methods reference the class itself in their annotations works on 3.14
alone, and this project develops, tests, and ships on a pinned 3.14
image, so the one interpreter that forgives the pattern was the only
one any gate ever ran. The stated floor was also simply missing:
the sibling application states one and this repository did not.

**The fix went class-wide, not instance-wide.** The review reported
one file; a sweep importing every module on 3.11 found three
independent roots. Each gained the future annotations import, the
suite then passed whole on 3.11, and only after that execution was
the floor written down. The linter's target moved to the floor
version so it enforces the floor's idioms from now on.

**Also from the same review, adopted:** the validation error body
now names the failing fields and their rules while echoing no caller
value, replacing a fixed body that named nothing; the reviewer's
design and its canary-test update were taken nearly verbatim. The
review also supplied the run-without-Docker path, which was verified
against a live SQLite instance here before the README documented it.

**Credit.** The defect and both improvements came from an
independent review performed outside this repository's own gates,
which is the strongest argument yet recorded here for eyes that did
not build the thing.

## D-054: Fuzzing the parsers, publishing the image, and code-owner review

Three adoptions in one pull request, each with its own reason.

The two import parsers read files produced by another system, which
is the shape of code where an input nobody imagined finds a path. The
property-based tests already exercised them with generated inputs, but
a fuzzer runs millions of mutated inputs per minute against the
compiled program under AddressSanitizer, and ClusterFuzzLite does that
on every pull request touching the parsers, from a digest-pinned
fuzzing image against the hash-pinned tree. Each harness swallows the
ValueError-derived refusal the parser promises for bad input and lets
anything else escape, so a finding is an exception nobody wrote. The
first run executed eight million inputs without a crash and with low
coverage, because the parsers refuse random bytes at their first
check; a seed corpus from the shipped sample files is the follow-up
that lets the fuzzer start past the front checks.

Releases now publish the container image to this repository's package
registry under the version tag and attest its digest, because a
consumer who can pull is better served than one who must build, and an
attested digest is verifiable without trusting this repository's word.
A dispatch workflow attests a release cut before attestation existed,
honest about being dated the day it ran.

A CODEOWNERS file names the one human who already approves every
change, and the ruleset now requires code-owner review and up-to-date
branches. The first binds the platform's requirement to the person the
arrangement (D-045) already relies on; the second is the setting that
would have prevented both merge races recorded in the standards.

Rejected: OSS-Fuzz proper, which requires acceptance into a program
this repository has no standing for yet; property-based tests alone,
which run in-process at test speed rather than at fuzzer speed and are
not recognized as fuzzing by the posture rater the program tracks; and
a two-reviewer requirement, which a one-human program cannot honestly
satisfy.

## D-055: The base image scan blocks on the clock, and the build applies Debian's updates

The container job scanned the pinned base image on every pull
request and failed on any critical finding with a published fix. On
September 15, 2026 the scheduled run found thirty-nine such findings,
glib among them, because Debian had shipped the fix and the upstream
python image had not yet been rebuilt with it. Every pull request
opened after that failed the container job, including three that
moved a Python package and could not touch the image, and the newest
upstream digest still carried three fixed findings in perl. The gate
was blocking on something no pull request could change, which is the
failure D-037 names for the scorecard upload.

Moving the digest found a second problem. The pin the update bot had
moved on September 1 and the program merged on September 8 was not
the slim image the Dockerfile's comment named: a digest-only
reference gives the bot no tag to follow, so it followed the default
one and moved the pin to the full python image, 1.6 GB against 190
MB, with the packages that carried most of the thirty-nine findings.
The parity gate checked that both copies moved and nothing checked
what they moved to. It surfaced because the coverage upload, which
had been finding git and curl in the full image, failed on the slim
one.

Three changes. The base image scan now blocks only on the schedule
and on main, where its job is to prompt a digest move, and reports
on a pull request. The Dockerfile applies Debian's package updates at
build time, so the image the pipeline builds carries every fix Debian
has published on the day it is built, and that built image is what a
pull request's scan blocks on, because a pull request can fix what it
builds. And the reference keeps the tag beside the digest,
`python:3.14-slim@sha256:...`, in both homes: the digest still decides
what runs, and the tag tells the bot which family to follow. The
digest moved to the newest slim manifest in the same change.

Rejected: ignoring the findings until upstream rebuilt. Days of red
on every pull request is the alarm that teaches the eye to skip it.

Rejected: dropping the base scan. It is the only mechanism that
notices a fix has shipped for a package the build does not otherwise
touch, and on the schedule it still fails loudly, which is where a
digest bump is owed.

Rejected: applying updates at build time without moving the digest.
The build-time update covers the window; the pin is still the record
of what was reviewed, and a pin nobody moves is a pin nobody reads.

## D-056: Person or service is derived from the credential shape

An IAM user can be a human at a console or a workload holding keys,
and every review treats them differently: a person is offboarded by
the fact of leaving, a service is offboarded by nobody, which is this
tool's founding problem. The inventory now classifies each identity
as person, service, mixed, or unknown, shows the reasoning on the
detail page, and filters and sorts by it (issue 37).

The heuristic reads the credential shape and nothing else. A console
password reads as a person, with or without MFA noted in the reason;
active access keys alone read as a service; both together read as
mixed, the human use of a non-human credential the findings already
name under NHI10; neither reads as unknown. Root is a person and a
role is a service by type. The classification is derived at read
time like every other judgment here (D-006) and never stored, so a
credential change moves it on the next snapshot with nothing to
reconcile. The sample account gained one mixed identity so all three
cases are exercised on the committed data.

Rejected: a stored classification set by the operator. It would go
stale the way every stored status does, and it would invite the
operator to decide what the credentials already say.

Rejected: reading the identity's name or tags for words like
"svc" or "bot". Naming conventions vary by account and lie by
accident; the credential shape is what the provider actually issued.

Rejected: a two-way person-or-service split with no mixed case. The
mixed identity is the one that matters most to a review, and folding
it into either side hides it.


## D-057: The audit trail is hash-chained, anchored by the evidence exports

An actor holding owner access to the database could alter or remove
audit rows and nothing would show it; the accepted-risks section had
said so since the first release, and once promised a fix that shipped
without arriving. Each audit row now carries the SHA-256 of its own
content and the previous row's hash (issue 39). Altering any row, or
removing one, breaks every hash that follows, and a walk names the
first row that fails. The chain head travels in every campaign
evidence export, so a copy held outside the database is an anchor:
history rewritten after the export cannot be made to match it.

The hash covers a fixed, store-independent form of each field, with
the timestamp reduced to whole UTC seconds, because the first test
run found SQLite returning the timestamp without its timezone and the
untouched first row failing verification. Rows written before the
chain existed carry no hash and are reported as the unchained prefix,
never rewritten. Two writes in one transaction flush between them so
the second chains to the first.

Rejected: signing each row with a key the application holds. The
application's key is on the same host as the database it is meant to
guard; an owner who can rewrite rows can re-sign them. The export
anchor puts the trust in a copy the owner does not control.

Rejected: backfilling hashes over pre-chain rows. A hash computed
today over a row that has sat unguarded for a month attests to
nothing about that month.

Rejected: a separate append-only ledger table. It doubles the write
path for the same guarantee, and it is guarded by the same owner.

## D-058: Pull requests need not be current with the mainline before merging

D-054 turned on the ruleset's up-to-date requirement because it would
have prevented the two August merge races. Two weeks of use showed
its cost: every merge into main invalidated every other open pull
request, each one then needed a rebase and a full pipeline run before
it could merge, and a set of three stacked pull requests took most of
an afternoon of re-runs to land. The rule is now off. Code-owner
review and the ten required checks stay as they were.

What the rule guarded against still has an answer. The merge races it
would have prevented were two branches changing the same file; the
pipeline's parity and truth gates run on the merge commit's contents,
and a change that lands behind a moving mainline still fails there if
the two changes conflict in a way the tests can see. What the rule
does not guard against, two changes that pass separately and fail
together without touching the same test, was never something a
rebase alone would catch either.

Rejected: keeping the rule and merging one pull request at a time
from a merge queue, which GitHub offers on this plan only for
organizations; and keeping the rule with the agent rebasing every
open branch after each merge, which is the toil that was measured.

## D-059: The secret scanner drops the one detector that collides with pinning

Every action here is pinned by its full commit hash, and the scanner's
SonarCloud detector matches a forty character hexadecimal string on a
line naming Sonar. The two disciplines collide. The September update
to the SonarQube scan action failed the secrets gate on the pin it was
replacing, reported as an unverified result, which is the scanner
saying it asked SonarCloud and SonarCloud did not know the value. The
pipeline now excludes that one detector by name, and the collision
would otherwise return on every future bump of that action.

What the narrowing costs, stated rather than glossed: a literal
SonarCloud token committed here would no longer be caught by this
layer. Two layers still cover it. GitHub secret scanning and push
protection carry their own SonarQube pattern at the server, the layer
a commit cannot route around (D-017), and this project's SonarCloud
credential is a pipeline secret that never appears in a file. The
exclusion is validated by the tool: a misspelled detector name exits
one rather than passing, so the exclusion cannot quietly become a scan
of nothing.

Rejected: blocking only on verified results, which would have cleared
this finding and also every finding from a detector with no
verification endpoint to ask; and excluding the workflow directory by
path, which would hide every detector from the files that hold the
most credentials. An alarm that is always false teaches the eye to
skip the alarm (D-002), and the remedy is to remove the one false
alarm rather than to lower the gate.

## D-060: Version updates arrive monthly, advisories arrive when they arrive

The update bot ran weekly and opened five pull requests in one
evening, none of which answered a published vulnerability: the
repository held no open advisory that night or now. Each one still
demanded the companion edits the gates require, so a week's churn
cost an evening and taught the reflex these gates exist to prevent,
which is clicking through a bot's work without reading it.

Version updates now run monthly, with at most two pull requests open
per ecosystem. The security half is untouched and is a different
mechanism: Dependabot security updates and the platform's alerts fire
on an advisory the day it publishes, on no schedule of ours. So the
cost of the change is that a pin with nothing wrong with it may sit
one version behind for a few weeks longer, and the thing that would
make it urgent is exactly the thing the monthly schedule does not
govern.

Rejected: turning version updates off, which would leave the tree to
drift until an advisory forced a jump across several versions at
once, and would drop the rater's check that an update tool is
configured; and keeping the weekly cadence with notifications
silenced, which fixes the inbox and not the work.

## D-061: Every pin has one home, and no gate enforces a copy

Two facts were written twice. The Python and PostgreSQL digests lived
in the Dockerfile and the compose file and again in the workflow, and
every action pin lived in a workflow and again in the README table.
Two gates held the copies in agreement.

The update bot can only ever move one side. So every automated bump
arrived half done and failed a gate by construction, and the fix was
always a human or the agent hand-writing the other copy. An evening of
five routine bumps cost an evening of that, on a repository nobody was
working on. The gates were not wrong about the state; the state was a
design that guaranteed the work.

The digests now have one home each and the pipeline reads them at run
time through a resolve job whose outputs feed the container and the
service. The action pins live in the workflows alone; the README table
names what runs and why, without repeating a hash. Both gates were
replaced by gates that hold a property rather than a copy: each digest
has one home and no workflow carries a second, and every action use is
pinned to a full commit hash and named in the table.

The workflow auditor reads one file at a time, so it cannot follow the
value into the job that produced it and reports the container image as
possibly unpinned. That audit is suppressed on those two lines with the
reason beside them, and the property it was watching is held by the
homes check and by the reader, which fails when a home holds no digest.

What this gives up: a reader of the README no longer sees which version
of an action runs without opening a workflow. That is a click, against
an update that no longer requires a human to complete it.

Rejected: generating the README table from the workflows, which keeps
the duplication and moves the toil into a regeneration commit the bot
still cannot make; and dropping the table, which would leave no record
of why any of this third-party code is trusted, which is the question
the table exists to answer.

## D-062: The security rule set was spot-checked against a second analyzer, once

The linter runs the `S` rule set, which is a reimplementation of
Bandit's checks inside ruff (D-022 chose the linter; D-025 added the
dataflow analyzers above it). A reimplementation can drift from its
source, so on September 23, 2026 Bandit 1.9.4 itself was run once over
the application, the scripts, the fuzz harnesses, the migrations, and
the tests, then removed from the environment.

Seven findings, none high. Two were the two places ruff already
flags, each carrying its written suppression and reason: the AWS
action string `iam:passrole`, which both tools read as a password, and
the scoring page's `urlopen` against two fixed HTTPS hosts. The other
five were notices that two scripts import `subprocess` and call git
and pytest with fixed argument lists in the form that takes no shell,
which is the form the notice exists to steer toward. The tests
produced nothing at medium or high.

The result is recorded because it is evidence the pipeline could not
produce on its own: two independent implementations of the same rules
agree on this code, and every suppression is justified in both. Bandit
is not added to the pipeline, because it would run the same checks a
second time under a second configuration and find what the first run
finds. The spot check is worth repeating when the linter's rule set is
upgraded across a major version, or when a finding class is added that
the linter does not carry.

Rejected: adding Bandit as a permanent job, for the reason above; and
not recording the run, which would leave the claim that the linter
covers Bandit's rules as a claim rather than a checked one.

## D-063: Every image pin carries its major version, and the manifest copy is held to the home

The database image was pinned by digest alone, `postgres@sha256:...`,
with no tag beside it. An untagged pin gives the update bot no line
to follow, so it follows `latest`, and on September 1 the bump from
`18cfe3e` to `4ef4dbc` moved the compose file from PostgreSQL 17.11
to 18.6 without anyone reading the major. The 18 image refuses a
data volume mounted at the 17 path, so `docker compose up` on a
fresh clone has failed since that merge. The pipeline did not notice
because its test job runs the database as a service with no volume.
The next bump, on September 22, moved the digest again and the agent
moved the workflow twin to match, checking that the pin moved and
not what it moved to, which is the lesson D-055 already recorded for
the Python image and did not apply to this one.

Both references now read `postgres:17@sha256:...`, and the homes gate
refuses any pinned image whose reference carries no version tag. The
Kubernetes manifest held a third copy of the digest, still on 17,
that no gate covered; the homes gate now holds it to the compose
file's exact reference, tag and digest, because it is not a workflow
and the resolve job cannot feed it.

Found by running the renamed stack end to end before its pull
request opened, which is the verification the doctrine asks for and
the only check in the program that mounts a volume.

Rejected: moving to 18 now, which is a data migration (`pg_upgrade`)
for every existing stack and belongs to its own decision with the
mount layout the 18 image expects; and leaving the Kubernetes copy
outside the gate, which is how it drifted a major version from the
file beside it.

## D-064: role-call becomes manifest-identity

The product grows a second half. role-call reads what identities hold
from the reports a provider already produces, derives their state, and
puts a person's decision on each; that is the observed side. The
declared side, what each identity is supposed to hold, who approved
it, until when, and which team owns it, has no home in any open-source
tool, and the difference between the two sides is the product worth
building. One product needs one name, and manifest-identity names the
declared record: a manifest is the list of what is supposed to be
aboard, and to manifest is to make plain.

The rename is complete rather than partial, by the maintainer's rule
that nothing is kept for convenience. The repository moved to the
manifest-identity organization, which holds the name, with the old
address redirecting. The Python package is `manifest_identity`, the
environment variables `MANIFEST_IDENTITY_*`, the database and its
roles `manifest_identity` and `manifest_identity_app`, and every
name shaped like a host or a label `manifest-identity`. The agent app
that proposes changes is `manifest-identity-agent`, and its commits
now carry its own identity rather than the maintainer's, which is
what D-045 intended and what the organization's review rule requires
to see two parties.

What stays as written: every decision before this one, every release
and its attestations, and the container package under the old name,
because the record is not rewritten. An existing `.env` and an
existing data volume do not survive the rename as they are: the
variables must be renamed and the database recreated from the
sample or restored from a backup under the new role names, and the
README says so.

Found on the way, by running the renamed stack end to end before
this change opened: the audit chain verifier from D-057 had never
run outside pytest, because a script under `scripts/` cannot import
the package. It lives in the package now, as
`python -m manifest_identity.verify_chain`, and it was run inside the
container against the demo data before this decision was written.

Rejected: a companion repository beside role-call, which would have
split one product's record in two and left the observed half with the
name that no longer said what it was; and a rename in place under the
personal account, which would have left the organization holding a
name and pointing at a repository elsewhere.

## D-065: The license is the AGPL 3.0 from the declared-access work onward

The observed half of the product shipped under the Apache 2.0
license, and every release through v0.2.0 stays under it; a
published license is not withdrawn. The declared half, the delta, and
the redefined campaigns are unwritten, and they are the part a
company would pay for, which makes this the moment to choose the
terms the rest of the product carries.

The choice is open core. The platform stays open source, forkable,
and usable by anyone, under the GNU Affero General Public License,
version 3, whose one addition to the GPL is that a party running the
software as a service for others must publish their changes. That is
the lever a one-person product holds against a larger company
reselling the work, and it is also the term some enterprises refuse
on sight; that cost is accepted. Parts a company pays for, single
sign-on, scoped administration, connectors, and support, may live in
a separate repository under the same organization under other terms,
and the boundary will be stated in this file when the first such
part exists.

Every commit in this repository is by its maintainer, by the
maintainer's own agent app, or by the update bot, so no contributor's
consent was needed to change the license of future versions. A
contributor's licence agreement is not added; contributions under
the AGPL are accepted as AGPL, and the maintainer's ability to
relicense ends with the first outside contribution, which is stated
here so that it is a known cost rather than a surprise.

Rejected: staying on Apache 2.0, which offers no protection against
resale and would leave the private parts as the only thing of value;
and the Business Source License, which is not open source by the
accepted definition and would make the program's public claims
untrue.

## D-066: The declared half is designed before it is built, in three documents

The product grows a declared half (D-064). Its design lives in
three files rather than in the README: ARCHITECTURE.md holds the
four parts, the provider-neutral model both halves share from v0.3,
the data flow, the trust boundaries, and the diagram list;
THREAT-MODEL.md holds the ranked threats and accepted risks, version
one's moved in unchanged and the declared half's rows added beneath
them; ROADMAP.md holds version one's roadmap as it stood, then the
declared half by version with a definition of done for each. The
README keeps its sections as short pointers so that its anchors and
its front-door shape stay, and the documentation site publishes the
three files as pages.

The observed half's design was written into the README because there
was one half and one document was enough. An outside consistency
read in September found that shape had begun to hide drift, and the
maintainer had asked for the roadmap and threat model as files in
August. This is that change, made at the moment a second half
needed a place to be designed. Nothing was cut in the move.

Rejected: a second README for the declared half, which would have
made two front doors; and designing the declared half in the private
planning material only, which would have kept the reasoning off the
record that this project exists to keep.

## D-067: GitHub is the second observed provider, because the program is the first user

The original order (D-001) put Entra second after AWS. The second
observer is GitHub instead. The program that builds this product
runs on GitHub: two agent apps with installations and tokens, three
organizations, code-owner review, a release workflow with its own
identity. Those are non-human identities with owners, approvers, and
no record anywhere of what they are supposed to hold. Declaring them
and observing them through the exports the platform already offers
gives the declared half its first live delta on an estate the
maintainer can grant read access to today, and it is the smallest
provider to observe. Entra follows it.

Rejected: Entra second as planned, which is the larger vocabulary
(users, groups, service principals, managed identities, directory
roles, role-based access assignments, Privileged Identity Management)
and would have put the first live delta months out; and no second
provider until the declared half is finished, which would have left
the delta tested only on sample data.

## D-068: A declaration is per grant, and the page shows it per identity

The record is one declaration per grant path: an identity holding a
role definition at a scope by a path. That is the unit a person
approves, the unit that expires, and the unit the delta compares. The
page groups declarations under the identity, because that is how a
person thinks about them: this account, and what it may hold. The
form declares several grants for one identity in one sitting, and
the CSV import takes one row per grant.

Rejected: one declaration per identity carrying a list of grants,
which cannot expire or be revoked one grant at a time and makes
every partial change a rewrite of the whole record.

## D-069: The two records are called observed and declared (superseded by D-073)

The words on the page and in the documents are "observed" for what
the provider's reports show and "declared" for what people said
should be, with "the delta" for the difference. They are the plainest
pair that keeps the distinction NetBox draws between operational
state and desired state, and they read the same to an engineer, an
auditor, and a team lead. "Actual" and "intended" were the
alternatives and they invite argument about which is real; "held"
and "declared" was close and loses the sense that the observed side
is a report and not a fact.

Superseded by D-073 before anything was built on it: declared names
the act of writing something down, and the record's force comes from
a named person authorizing it for a period.

## D-070: The three roles gain a scope, and required fields ship secure and changeable

Reviewer, operator, and administrator stay (D-017); no fourth role.
Each binding carries a scope node in the provider's hierarchy, so an
administrator for one tenant is not one for another, and every write
route checks the caller's binding against the target's node. Which
declaration fields are required is an administrator setting, per
field, because organizations differ in what they will make teams
write. The shipped defaults are the secure ones, expiry on at one
year and justification required, and every change to a default is an
audited administrator action, so an organization that turns one off
has decided to and one that never looked has not.

Rejected: a fourth role for scope administrators, which multiplies
the matrix without adding a property a scoped binding lacks;
prescribing expiry and justification with no way to change them,
which the maintainer ruled out (organizations decide); and shipping
them off by default, which makes the record's quality depend on
someone finding a setting.

## D-071: The observed half is rebuilt on the neutral model, and no data is migrated

Version one's tables were shaped by the file that fed them. An
observation row carried `key1_active` and `key2_last_rotated` because
an AWS credential report has two key slots; a snapshot belonged to an
account because AWS calls a place an account; a policy document was
stored per snapshot because that is how the authorization details
file arrives. Every one of those is a provider's vocabulary standing
where a model belongs, and the declared half has to compare across
providers that count credentials differently and call their places
tenants, subscriptions, projects, and clusters.

Two ways forward were weighed. Map the old tables to a neutral shape
at read time, keeping the storage as it is: cheap this week, and it
leaves every reader translating forever, with two vocabularies in the
code and the mapping as the place bugs live. Or rebuild the tables
neutral now and re-point the readers. The maintainer ruled for the
rebuild, three times and plainly: build it as if the old product
never existed, and let what the old product did arrive as features on
the new model.

So the package is split by part, each owning its own tables and
nothing else: core (users, sessions, scope nodes, bindings, settings,
the audit chain), observe (providers, imports, identities,
observations, credentials, role definitions, grants, memberships,
relationships), declare (governance records, declarations, declared
relationships), decide (campaigns, items, alerts, deliveries), and
api (integration tokens). Snapshots become imports keyed by scope,
source kind, and capture time. A credential is one row per
credential, so a provider with five keys is five rows. A grant names
a versioned role definition at a scope, by a path of hops and in a
mode, which is what makes group-derived and eligible access
expressible at all. Groups stay identities of kind group (D-019).
The provider's own words end at the parser.

No data is migrated, because there is none: the only deployment is a
demo that regenerates from `python -m manifest_identity.sample_data`,
and a released version has never held a production estate. Every
migration before this one is deleted and replaced by a single
greenfield migration, which is honest about what it is rather than
pretending to a lineage nobody walked. Anyone running the demo
recreates the volume; the README says so.

Paths moved with the split: the audit chain verifier D-063 placed at
`python -m manifest_identity.verify_chain` is now
`python -m manifest_identity.core.verify_chain`, and the parsers are
under `manifest_identity/observe/providers/`. Entries before this one
name the old paths where they describe the past, and stay as written.

Rejected: mapping at read, for the reasons above; keeping the old
migrations so the history looks continuous, which would make Alembic
carry a past no database has; and a migration that moves demo data,
which is work performed on data that regenerates in a second.

## D-072: A role binding at a scope replaces the role column on a user

A user had one role, in a column, and it applied everywhere the
application looked. That is the right model for one team watching one
account and the wrong one for an estate: an operator for the payments
account had to be an operator for every account, and the only way to
give someone less was to give them nothing.

Authority is now a row: user, role, scope node, who granted it, when,
and a revocation that ends it without deleting it. A user holds as
many bindings as the estate needs. One function answers every
authority question, and it is the only one that does: does this user
hold one of these roles at this node, at an ancestor of it, or at the
global node, with nothing revoked. Routes ask the matrix first, which
is unchanged and still the single source of which roles a route
admits, and then ask the scope question with the node their target
belongs to. A binding is itself a governance act, so it is audited
like one.

The global node is a real row, created by the first migration,
provider generic and kind global, and an organization-wide binding
names it. Making it a row rather than a null keeps one code path for
every check; a null scope meaning everywhere would have put the most
powerful grant in the value that is easiest to write by accident.

Administration stays global in this version: an administrator bound
at an account cannot yet create users or bind roles, because
per-node administration needs the per-team views that have not been
built, and a half-built one would hand out authority nobody can see.
That refusal is tested rather than assumed.

Revocation over deletion is the same rule the rest of the record
follows (D-006): who could act, when, and who granted it, survives
the end of the grant. A deleted binding would erase exactly the fact
an investigation needs.

Rejected: keeping the column and adding bindings beside it, which
leaves two sources of authority and a question about which wins;
scope as a string on the user, which cannot express a tree or carry
attribution; and inferring scope from the target's account on the
caller's behalf, which is authority derived from data the caller
supplied.


## D-073: The record is an authorization, and that word names nothing else here

D-069 called the two records observed and declared. Declared names the
act of writing something down, and it reads like documentation. What
gives this record its force is that a named person authorized an
identity to hold an access, for a period, with an owner. So the record
is an authorization, the verb is authorize, the person on it is the
authorizer, and the part that owns it is `authorize`.

It is also the word the frameworks already use. AC-2 and AC-6, ISO/IEC
27002 5.18, and the SOX access language all say authorized. The two
sentences the delta exists to produce are "held but not authorized"
and "authorized but not held", which is what an auditor says out loud.
The delta is the product, so the delta's sentences are the ones that
should read best.

Approved was the near miss. An approval implies a request that came
before it, and there is no request object in this design until email
intake, which may never be built; a person can authorize access nobody
asked for. Manifest entry was the other candidate, tying the record to
the product's own name, and it was rejected as the more distinctive
word that fewer readers would recognize on sight.

The cost is a collision, and it is contained by rule rather than by
intention:

1. **In this product, authorization and authorized name this record
   and nothing else.** The application's own gates are called the role
   matrix and the scope check, never "authorization". The code already
   worked this way, in `require_roles` and `require_scope`; the
   product's own documents did not, and now do. AGENTS.md is the
   exception by design: it carries build-doctrine's shared standards
   text, where object-level authorization is a general engineering
   rule that every repository under the doctrine reads the same way,
   and forking that text to suit one product's vocabulary would cost
   more than the collision does.
2. **The bare word unauthorized is never a label**, because HTTP owns
   it: 401 is named Unauthorized and this application returns it. The
   finding is written "held but not authorized".
3. **The AWS authorization details file keeps the provider's name**,
   in the source kind and the parser, because the provider's
   vocabulary ending at the parser is the rule (D-071) and renaming
   someone else's file would be a worse lie than the collision.

The rename happened before the record held a single row: the tables
exist from migration 0001 and no route writes them yet, so this is a
name change, not a data change. An existing demo volume keeps the old
table names and must be recreated, which the clean-slate reset in the
README already covers.

Rejected: keeping declared because it was already written down, which
is the sunk cost of one session against a word in every finding, every
document, and every screen for the life of the product; and carrying
both words, one in the code and one on the page, which is how a
product ends up with two vocabularies and a translation layer between
them.

## D-074: The customer's file keeps its own shape, and the mapping is the object

The CSV door was designed twice. The first design prescribed a column
set, documented it, shipped a template, and put a format version in
every row so a file written to an old contract would be refused rather
than misread. The maintainer asked whether a schema has to be
prescribed at all, and it does not.

Organizations already hold these spreadsheets. Access approvals live in
somebody's sheet with columns called Owner, Business Unit, Expires, and
Ticket. Prescribing a schema asks them to transform that file before
they get anything back, and the transform happens on their side, where
no gate of ours can see it. A bad transform is invisible here forever:
the rows arrive well formed and wrong.

So the file keeps its shape and the import carries a mapping: each
field this product needs, named against the column that holds it, or
against a constant for a field the file does not have. A mapping is a
stored object with a name, the person who wrote it, and a supersession
chain like every other record here, and every import names the mapping
it was read through.

That last property is the one worth the work. If a mapping turns out to
have been wrong, every row imported through it is findable. Under the
prescribed schema, a customer's bad transform leaves nothing to find.

Three consequences follow.

**There is no format version.** Nothing of ours is versioned because
nothing of ours is the format. What changes is their file, and the
answer to a changed file is a new version of their mapping, which the
chain already records. The version column the first design argued for
is dropped rather than kept beside the mapping, because two mechanisms
answering one question is how a reader learns to trust neither.

**Nothing is guessed.** A mapping that does not cover every required
field refuses the file whole, before a row is read. Columns nobody
mapped are ignored explicitly and counted in the result, so an ignored
column is a number a person can see rather than a silence. Dates are
parsed by a format the mapping declares, never inferred, because
03/04/2026 is two different days in two countries and picking one is
the kind of quiet wrong this product exists to prevent. Values pass
exactly the checks the form applies, through the same code, so the
required-field settings and the person-owner rule cannot differ by
which door a record came through.

**A flexible reader needs a dry run.** A mapping makes a systematic
misread more likely than a fixed schema does, so reading and writing
are two routes. The dry run applies the mapping, returns the first
rows as the system understood them with the refusals and their
reasons, and writes nothing. The importer is the attributed authorizer
of every row that lands, so a person confirming a dry run is putting
their name on all of it, which is the reason the preview exists rather
than a convenience.

Rejected: the prescribed column set with a version column, for the
reasons above, though its template survives as the shipped default
mapping so the easy path stays easy; matching their headers against a
list of aliases we maintain, which is guessing with extra steps and
fails silently when two aliases collide; and versioning by filename,
which contradicts the rule that a file's content is authoritative and
its name is not (D-008).

The cost is that subphase 1.3 grows, and it is paid back at 1.11,
where the observed side needs the same door and now uses the same
mechanism rather than a second one. The screen for building a mapping,
rather than sending one, moves to the page work with the rest of the
frontend.
