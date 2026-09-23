# Threat model


The method: STRIDE per component (Spoofing, Tampering, Repudiation,
Information disclosure, Denial of service, Elevation of privilege),
ranked by likelihood and impact, each threat mapped to the control
that answers it. The version one model is the observed half. The declared half adds
its own rows below (D-066), and Phase 7 changes what the tool is
allowed to do and requires a revision before any of its code is
written.

The premise that shapes everything here: manifest-identity's database is a map
of every identity in the target account, which ones are unused, which
ones are over-privileged, and which credentials are old. That
inventory is exactly the reconnaissance an attacker wants, so the tool
that reduces identity risk is itself a concentration of it, and its
own handling is the core of the work.


### Ranked threats

Ordered by likelihood times impact. The STRIDE letter names the category.

| # | Threat | STRIDE | Likelihood | Impact | Control |
|---|---|---|---|---|---|
| 1 | Theft of manifest-identity's own cloud credential, once the live pull phases add one, giving an attacker the full identity map and a foothold shaped like a security tool | S, I | Medium | High | Federated, short-lived credentials rather than a stored key; read-only scope; the role's own use is audited in the target account's trail, so the watcher is watched |
| 2 | Disclosure of the inventory: database access or a leaked export hands over the reconnaissance map | I | Medium | High | Authentication and authorization on every request; response models as an allowlist on the way out; exports carry deliberate fields only; encryption at rest supplied by the deployment layer and stated as a requirement, not assumed (D-020) |
| 3 | A hidden identity: tampering with stored data so an attacker's principal never appears in the inventory | T | Low | High | State is derived at read time from append-only observations, and every sync is a full snapshot, so hiding requires tampering again after every sync; database least privilege; the audit row commits with its action and carries attribution |
| 4 | A malicious imported snapshot rewrites another account's history or plants hostile values | T | Medium | Medium | Bounded parsing on every axis; the one-account-per-file precondition is verified rather than assumed; ingestion is append-only and duplicates are rejected |
| 5 | Stale data presents false comfort: a decision made on an inventory that no longer matches the account | I | Medium | Medium | Every view carries its as-of sync time; recency is a first-class field; an old sync is a visible warning, not a footnote |
| 6 | Theft of an operator session token | S | Medium | Medium | Sessions are revocable from day one; short expiry; step-up authentication arrives with any action that changes the cloud account |
| 7 | Injection through exported identity names and tags, which the target account's users control: formulas in spreadsheets, markup in the generated report | T | Medium | Medium | Formula-leading cells are escaped in every export path, and the report builder context-escapes every value, treating names and tags as data, never markup |
| 8 | A governance action is denied or misattributed: who attested this identity, who cleared this flag | R | Low | Medium | Attribution columns on the record itself, plus the audit row written in the same transaction as the action |
| 9 | Ingest exhaustion: an enormous account, or API throttling turning a sync into an outage | D | Medium | Low | Paced API calls that honor throttling; bounded imports; container resource caps |
| 10 | A shadow admin scored as low risk because its privilege is capability-shaped rather than name-shaped | I | Medium | Medium | Admin-equivalence heuristics judge what a policy can do, not what it is called; the chaining limitation below is stated rather than hidden |
| 11 | A deleted principal is recreated under its old name and inherits the dead identity's governance standing | S, T | Medium | Medium | Identities are keyed by the provider's immutable identifier (D-016), so a recreated principal is a new identity, and reuse of a governed name is surfaced as a finding |


### Accepted risks

Recorded so each is a decision with a reason, not a surprise.

- **Effective privilege through role chaining is not computed.** Version
  one scores what a policy grants directly. A principal that reaches
  admin through a chain of assumable roles will be underscored, and the
  interface says so. Computing reachability is graph analysis that earns
  its own phase; the raw material for it, every trust policy document,
  is already recorded per snapshot as of the second ingestion surface,
  so the later phase starts from data, not from scratch. Two narrower
  limits join it with the privilege findings (D-033): an explicit deny
  is noticed but not evaluated against the allow it narrows, and a
  condition is noticed but not interpreted. Both can overstate a grant,
  and each finding resting on such a document says so in its own text
  rather than relying on a reader finding this paragraph.
- **Creator attribution does not exist in version one.** It arrives
  with the live provider connection, and until the organization trail
  exists in Phase 3 it will reach back 90 days and no further.
  Recorded now so the absence reads as scheduled rather than
  overlooked.
- **Version one observes and records; it does not enforce.** An identity
  flagged in manifest-identity keeps working in the cloud account until a human
  acts there. That is the enrichment-over-automation design, stated as a
  risk because a reader could mistake governance records for applied
  controls.
- **The audit trail's tamper evidence depends on an anchor held
  outside the database.** The trail is atomic and attributed, the
  application's own database role cannot delete rows (D-013), and
  since D-057 every row is hash-chained to the one before it, with
  each campaign evidence export carrying the chain head. An actor
  with owner access can still rewrite history and every hash after
  it; what they cannot do is make the rewritten trail match an
  export someone else holds. So the control is only as strong as the
  practice of keeping exports off the database host, which the
  operating procedure states. An earlier version of this row promised
  the chaining with the campaign work and it shipped without it, a
  stated exit that passed unmet; that history stays recorded here.
- **Snapshot files are only as authentic as their handling.** The
  intended procedure is exporting reports directly from the provider
  to the machine that imports them. A file that traveled through other
  hands in between is a risk the parser's bounds cannot remove,
  accepted and named.
- **Roles are global, not account-scoped.** Any operator sees every
  imported account. Right-sized for one team governing its own
  accounts; account-scoped authorization is the named prerequisite
  for any multi-tenant future, decided before that future starts. The
  sharpest consequence, a stolen token reading every account, has its
  mitigation built: an administrator ends every session a user holds
  in one audited act, and the ended tokens meet 401 on their next
  request.
- **One human's eyes.** Every change lands through a pull request
  proposed by the agent's own identity, must pass the required checks,
  and requires an approving human review before merging; main refuses
  direct pushes, force pushes, and deletion (D-028, D-045). What
  remains accepted is that the approving human is one person, with
  nobody reading behind him. The exit is the first collaborator.
- **The tool depends on the provider's own reporting.** If the account's
  telemetry is wrong or delayed, the inventory inherits that. Verifying
  the provider against itself is out of scope.


## Threats the declared half adds

The declared record is a second map, and a more valuable one: it says
what is supposed to be true, and whoever can write it can make
unwanted access look intended. These rows extend the ranked table
above; numbering continues from it, and each names the control that
answers it in the design (D-066 through D-070) and the subphase that
builds it.

| # | Threat | STRIDE | Likelihood | Impact | Control |
|---|---|---|---|---|---|
| 12 | Laundered access: a declaration written for a grant that should not exist, so the delta reports nothing wrong | T, E | Medium | High | A declaration needs an attributed approver from an authenticated session and a scope binding that covers the identity; every declaration is append-only and audited in the chain; the delta-driven campaign shows owners what was declared in their scope by whom (1.1, 1.2, 1.8) |
| 13 | A declaration written outside the writer's scope: an administrator for one tenant declaring for another | E | Medium | High | Role bindings carry a scope node; every write route checks the caller's binding covers the target's scope; the matrix test walks every write route inside and outside scope (1.1) |
| 14 | Forged or misattributed approval: a declaration claiming an approver who never approved | S, R | Low | High | The approver is taken from the session, never from the form or the file; the CSV importer is the attributed approver of every row it imports; the audit row commits with the declaration (1.2, 1.3) |
| 15 | A stale side making the delta lie: the observed side behind reality, or the declared side behind a revocation, so a difference is missed or invented | I | Medium | Medium | Every finding shows the last observation time of each side beside it; the declared record's expiry is a clock the delta reads, not a field a person remembers (1.5) |
| 16 | Alert flooding or alert loss: an automation downstream drowns in notices, or a revocation is never heard | D, R | Medium | Medium | Every alert that fires is a record with recipients, channel, and delivery result, in the chain; alerts are rate-limited per recipient; a failed delivery is recorded as failed and shown (1.9) |
| 17 | The read API token: a per-integration credential that, stolen, hands over both records | S, I | Medium | High | Per-integration tokens, read-only, revocable, rate-limited, stored as hashes like sessions; a change feed rather than a full dump as the normal path (1.10) |
| 18 | Email intake as a channel: a forged message becomes a declaration | S, T | Medium | High | Not built in Phase 1; when built, a message yields a proposed declaration only, from an allowlisted and signature-checked sender, routed to an approver, attachments ignored, size-bounded (roadmap) |
| 19 | A relationship or eligibility the declaration never mentioned: access arriving through a trust, a delegation, or a group nobody declared | E | Medium | High | Relationships are first-class declared objects; grant paths carry a mode on each hop; the delta reports access via an undeclared relationship and eligibility outside any declaration (1.6) |
| 20 | A role definition that grows after approval: the provider adds actions to a built-in role, or an owner edits a custom one, so the approved grant now holds more | T, E | Medium | Medium | Role definitions are versioned observations; a declaration binds to the definition hash at approval; the changed-since-declaration finding lists the added actions and asks for a new decision (1.7) |

## Accepted risks the declared half adds

- **The declared record is only as honest as the people who write
  it.** A team can declare what it wants declared. The control is not
  a gate on intent, which no tool can judge, but attribution and
  visibility: every declaration names its approver, its owner, and
  its scope, and the delta-driven campaign shows each owner what was
  declared in their name. A wrong declaration is a recorded decision,
  which is the property this product exists to create.
- **The delta compares two snapshots, not two truths.** Both sides
  can be stale, and the finding says when each was last seen. A
  connection (v0.6) narrows the window; it does not remove it.
- **Scope wider or narrower than declared is not computed in v0.3.**
  Comparing a declared permission set against an observed one is
  policy analysis, and it earns its own subphase; until then the
  delta compares grants by identity and path, and the page says so.
