# Roadmap


The destination is a tool where every identity, the service accounts
and keys as much as the people, is governed the same way: a named owner, a stated purpose, a
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

manifest-identity stands on its own; its versions read against this
document (D-087). The platform it will deploy to is built as code in
[control-plane](https://tltaylor1.github.io/control-plane/). That
work includes an AWS organization with
centralized human sign-on through IAM Identity Center, which is the
AWS equivalent of an identity provider's single sign-on (SSO), and
keyless workload federation standing where stored credentials and
app registrations would otherwise be, plus the managed cluster, the
gated pipeline, and runtime detection phases. Those goals belong to
that repository and its documents, not to this one; this document
stays at the application's own scope on purpose.

### Out of scope

Recorded so each absence is a decision rather than an oversight.

- **No writes to any provider.** Enrichment over automation: the tool
  never holds a credential more powerful than its current version
  needs, and v0.6 adds a read-only connection and nothing more.
- **Seven providers by file, none live.** AWS came first, because
  building two providers before one was governed well would have
  added breadth without adding a property; the other six followed
  behind the common model, and the live pull for each waits for v0.6.
- **Effective privilege through role chaining is not computed.**
  Version one scores what a policy grants, not what assume-role chains
  can reach, and says so on the page. Reachability is real graph work
  that earns its own phase.
- **No automated remediation, ever, by design.** A tool that revokes
  on its own gets disabled the first time it breaks something.
- **No live provider connection before v0.6.** Files first, because
  the fresh-clone demo must run with Docker alone; the read-only pull
  joins in v0.6 behind the same ingestion.
- **No real-time event stream before the connection exists.**
  Snapshots are imported; event-driven refresh follows v0.6.


## The authorized half, by version

Each version is a definition of done, not a date. The subphases are
detailed in the maintainer's plan and summarized here; a version
ships when every subphase in it is merged with its tests, its
decisions are recorded, and a fresh clone runs the demo with the new
data. v0.3, v0.4, and v0.5 are complete and ship together as v0.5.0,
the first tag since the repository stood alone (D-087).

### v0.3: authorize and compare

- Scope tree and scoped administration: the three roles gain a scope
  node, every write route checks it. **Built.**
- The authorization record: append-only, attributed, with required
  fields the administrator sets and secure defaults. **Built.**
- Entry paths: the form, a file import that reads the customer's own
  shape through a mapping with a dry run, authorize from observed,
  and an export shaped for the import. **Built.**
- The delta, computed at read: held but not authorized, authorized but
  not held, expired and still held, owner disagreement, and the role
  changed after it was authorized. **Built.**
- Home, relationships, and grant paths with a mode on each hop; the
  "holds now" and "can obtain" columns. **Built.**
- Role definitions as versioned observations, and the finding when a
  definition changes after it was authorized. **Built.**
- The first release published to the package index under the
  project's name. **Held** until the platform in control-plane is
  built, by the maintainer's decision (D-087).

### v0.4: decide

- Campaigns rewired: expiry-driven and delta-driven, the manual
  campaign kept; a revoke is a work item. **Built.**
- Alerts on approval, revocation, and expiry, by email and signed
  webhook, every firing a record in the chain. **Built.**
- The page: the sidebar shell, the split view, findings grouped by
  class, the campaign queue; the first browser-driven test. **Built.**

### v0.5: read

- The read API with per-integration tokens and a change feed.
  **Built.**
- The generic observed importer with a source selector on the Imports
  page. **Built.**
- GitHub as the second provider (D-067), proven against a generated
  organization rather than the program's own estate, which is never
  published (D-076). **Built.**

### v0.6: connect

- The read-only provider connection behind the same append-only
  ingestion, AWS first, the credential the tool has not held until
  now governed as the identity that must be governed best.

### After v0.6

The seven native observers planned here (AWS, GitHub, Kubernetes,
Google Cloud, Azure and Entra, Okta, Active Directory) were all
built in Phase 1 as file parsers, subphases 1.12 to 1.15; what
remains is the live pull for each, behind v0.6's first connection,
and the providers that still enter through the table door: Ping,
OneLogin, JumpCloud, Auth0, Google Workspace, and databases. Then
email intake as a proposal channel if it is ever built, scope comparison in
the delta, single sign-on at the cloud phases, and the items the
version one roadmap above still holds.
