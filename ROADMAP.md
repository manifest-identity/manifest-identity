# Roadmap


The destination is a tool where every non-human identity is governed
the way human accounts already are: a named owner, a stated purpose, a
privilege picture beside its actual usage, a next review date, and
evidence behind every one of those claims, so the identity nobody can
explain becomes visible the day it appears rather than the day it is
abused.

The observed half's roadmap as it stood at version one, in order: expected-profile checks,
where a known vendor integration holding exactly its documented
permissions is furniture and the same integration holding more is a
finding; creator attribution, arriving when the organization trail
exists to feed it; the live provider connection as an adapter behind
the same append-only ingestion; report-only quarantine with review
windows; human-triggered, machine-verified remediation behind step-up
authentication, because clicked is not revoked until the provider says
so; temporary approved re-elevation, where someone else approves and
the clock does the offboarding; and more providers, Okta and Entra,
behind the common identity model rather than as rewrites.

manifest-identity is one application inside a larger project:
[control-plane](https://tltaylor1.github.io), a security engineering
program whose platform phases build the estate around this
application as code. That work includes an AWS organization with
centralized human sign-on through IAM Identity Center, which is the
AWS equivalent of an identity provider's single sign-on (SSO), and
keyless workload federation standing where stored credentials and
app registrations would otherwise be, plus the managed cluster, the
gated pipeline, and runtime detection phases. Those goals belong to
the program and its documents, not to this one; this document stays
at the application's own scope on purpose.

### Out of scope

Recorded so each absence is a decision rather than an oversight.

- **No writes to the cloud account until Phase 7.** Enrichment over
  automation: the tool never holds a credential more powerful than its
  current phase needs.
- **One provider.** AWS first; building two providers before one is
  governed well would add breadth without adding a property.
- **Effective privilege through role chaining is not computed.**
  Version one scores what a policy grants, not what assume-role chains
  can reach, and says so on the page. Reachability is real graph work
  that earns its own phase.
- **No automated remediation, ever, by design.** A tool that revokes
  on its own gets disabled the first time it breaks something.
- **No live provider connection in version one.** Files first, because
  the fresh-clone demo must run with Docker alone; the read-only pull
  joins in the cloud phases behind the same ingestion.
- **No real-time event stream in version one.** Snapshots are
  imported; event-driven refresh arrives with the cloud phases.


## The authorized half, by version

Each version is a definition of done, not a date. The subphases are
detailed in the maintainer's plan and summarized here; a version
ships when every subphase in it is merged with its tests, its
decisions are recorded, and a fresh clone runs the demo with the new
data.

### v0.3: authorize and compare

- Scope tree and scoped administration: the three roles gain a scope
  node, every write route checks it. **Built.**
- The authorization record: append-only, attributed, with required
  fields the administrator sets and secure defaults. **Built.**
- Entry paths: the form, a file import that reads the customer's own
  shape through a mapping with a dry run, authorize from observed,
  and an export shaped for the import. **The form and the file door
  are built.**
- The delta, computed at read: held but not authorized, authorized but
  not held, expired and still held, owner disagreement.
- Home, relationships, and grant paths with a mode on each hop; the
  "holds now" and "can obtain" columns.
- Role definitions as versioned observations, and the finding when a
  definition changes after it was authorized.
- The first release published to the package index under the
  project's name.

### v0.4: decide

- Campaigns rewired: expiry-driven and delta-driven, the manual
  campaign kept; a revoke is a work item.
- Alerts on approval, revocation, and expiry, by email and signed
  webhook, every firing a record in the chain.
- The page: the sidebar shell, the split view, findings grouped by
  class, the campaign queue; the first browser-driven test.

### v0.5: read

- The read API with per-integration tokens and a change feed.
- The generic observed importer with a source selector on the Imports
  page.
- The first user: the program's own GitHub identities authorized and
  observed (D-067), the first live delta.

### v0.6: connect

- The read-only provider connection behind the same append-only
  ingestion, AWS first, the credential the tool has not held until
  now governed as the identity that must be governed best.

### After v0.6

Native observers one provider at a time (Entra and Azure, Google
Cloud, Active Directory, Okta, Kubernetes), email intake as a
proposal channel if it is ever built, scope comparison in
the delta, single sign-on at the cloud phases, and the items the
version one roadmap above still holds.
