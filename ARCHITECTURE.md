# Architecture

The observed half, version one, is described where it runs: the
README's sections on how a request is protected, the trust
boundaries, what runs where, how it is put together, the data model
shape, and the route surface are each asserted against the running
system by a test, and this document does not repeat them. This
document is the design of the authorized half (D-066), the model both
halves share from v0.3, and the diagram list.

## The product in four parts

- **Observe.** Import the reports a provider already produces;
  connect and pull later. Observations are append-only and state is
  derived at read (D-006). This is version one.
- **Authorize.** The intended record: what each identity is supposed
  to hold, who approved it, when, until when, and which team owns
  it. Stored on purpose, append-only, always attributed.
- **Compare.** The delta between the two, computed at read, never
  stored: held but not authorized, authorized but not held, expired and
  still held, owner disagreement, access through a relationship
  nobody authorized, a definition that changed after it was authorized.
- **Decide.** Campaigns as the write path for intent, driven by
  expiry and by the delta, with the evidence export and the audit
  chain behind every decision. A revoke is a work item; nothing here
  changes a cloud (D-024).

The prior art is NetBox, whose record is the desired state of a
network and whose rule is that live state never enters the record
without a human. This applies the same premise to identity and
access: the observed side is never edited, the authorized side is
never automatic, and the difference is the work.

## The model

Provider-neutral, so that AWS is one vocabulary among several rather
than the shape of the tables. Eight objects:

| Object | What it is | Notes |
|---|---|---|
| Provider | The system an identity lives in | AWS, Azure and Entra, Google Cloud, Kubernetes, GitHub, Active Directory, Okta and its peers, databases, SaaS through single sign-on. The partition or cloud (AWS Commercial, AWS GovCloud (US), Azure Commercial, Azure Government, and so on) is an explicit enumerated field shown on every record, so an auditor filters on it |
| Scope node | A place in the provider's hierarchy | AWS partition, organization, organizational unit, account; Azure cloud, tenant (the directory), management group, subscription, resource group; Google organization, folder, project; GitHub enterprise, organization, repository; Kubernetes cluster, namespace; Active Directory forest, domain, organizational unit. Owners and administrator bindings attach to nodes |
| Identity | A principal | Keyed by the provider's immutable identifier (D-016); kind: person, service, mixed, unknown, external; **home**: this directory, another tenant or account by identifier, an identity provider, or a consumer origin (Gmail, Facebook, Apple, Microsoft personal). A guest is an identity whose home is not here |
| Credential | Something an identity authenticates with | Keys, passwords, secrets, certificates, tokens, Kerberos keys, SSH keys; age and expiry are first-class |
| Relationship | A connection between scopes or identities through which access arrives | Trust (cross-account role), federation (an external identity provider), delegation (Azure Lighthouse), cross-tenant access settings, group nesting. Authorizable: owner, authorizer, expiry, scope |
| Role definition | What a grant grants | Referenced by the provider's stable id; contents read at import, hashed, versioned, stored, so a review shows what a role allowed on the day of a decision. Meaning is derived from contents by capability (D-033), never from a name. Custom definitions are authorizable objects with an owner |
| Grant | An identity holding a role definition at a scope | With a **mode**: standing, eligible (may be obtained: PIM eligible, an assumable role, a Privileged Access Manager entitlement), or session (active because an eligibility was activated); and a **path**: direct, or via one or more hops, each hop a membership (active or eligible), a trust, a delegation, with the mode on each hop. The page shows "holds now" and "can obtain" |
| Authorization | What a person authorized one identity to hold, per grant | Identity, grant path, owner (a team, or a person with a required secondary owner), authorizer from the session and the time, justification, reference, valid from, valid until, control reference, intended mode, status (authorized, expired, revoked) with append-only history; bound to the role definition hash when it is authorized |

The tables are these objects, not a translation of them (D-071).
Version one's tables held the AWS vocabulary, two key columns and a
snapshot belonging to an account; they were rebuilt rather than
mapped at read, and no data was migrated, because the only estate the
product had ever held was a demo that regenerates.

Above every provider's tree sits one synthetic node named **global**,
created by the first migration. It is where an organization-wide
binding attaches, and it is a real row rather than an absent value,
so every authority check walks the same path: the target's node, then
its ancestors, then global (D-072).

Two more objects carry the authority and the history of the record
itself:

| Object | What it is | Notes |
|---|---|---|
| Role binding | A user holding a role at a scope node | The only source of authority. Covers that node and everything beneath it; revoked, never deleted, so who could act and when survives. Users carry no role of their own |
| Import | One file or pull that produced observations | Keyed by scope node, source kind, and the capture time taken from the file's own content (D-008), so the same file twice is refused. Every observed row names the import that saw it |

## Data flow

Two stores, one comparison, one write path.

1. Files, and later connections, produce observations: identities,
   credentials, grants with paths, role definitions with versions,
   relationships as seen. Append-only.
2. People produce authorizations, through the form, a CSV import
   with a documented template, "authorize from observed," an export
   shaped for the import, and, if it is ever built, email intake that
   yields a proposal routed to an authorizer.
3. The delta reads both at request time and reports the classes
   above, each finding carrying the last observation time of each
   side, because a stale side makes the delta lie (threat 15).
4. Campaigns turn delta items and expiring authorizations into
   decisions owed to named people; each decision writes an
   authorization or a revocation; each is audited in the same transaction and
   hash-chained (D-057); the evidence export carries the chain head.
5. Alerts fire on approval, revocation, and expiry, to administrators
   or administrator groups, by email and signed webhook; every firing
   is itself a record. The read API and its change feed let a
   security information and event management system, or any
   integration, read the record with a per-integration token.

## Trust boundaries

Version one has three, listed in the README. The authorized half adds
one and sharpens two:

- **The authorized record is a target.** Whoever can write intent can
  make unwanted access look intended (threat 12). The boundary is
  attribution and scope: no authorization exists without an authorizer
  taken from the session, a scope binding that covers the identity,
  and an audit row in the chain.
- **Scope is a boundary inside the application.** An administrator
  for one tenant is not one for another (threat 13). Every write
  route checks the caller's binding against the target's node.
- **Integrations are outside.** The API token is a credential with
  the same care as a session (threat 17); webhooks are signed; email,
  if ever built, is untrusted input that produces a proposal, never
  an authorization (threat 18).

## Where administration lives

The three roles from D-017 stay: reviewer, operator, administrator.
Each binding gains a scope node, so "administrator for tenant X" and
"operator for AWS organization Y" are real bindings, and the role
matrix test walks every write route with a binding inside and
outside scope. Administrators set which authorization fields are
required; the shipped defaults are the secure ones (expiry on at one
year, justification required), and every change to them is an
audited administrator action.

## What it is not

Not a provisioning tool, not a secrets manager, not an identity
provider, not a security information and event management system,
not a ticket system. It feeds all of them: the read API and the
webhooks exist so that they can consume the record.

## Diagrams


Working sketches exist for six here (the system context, the data
flow, the trust ladder, the subphase cycle, the pipeline, and the
runtime split), as sketch-suffixed files in the diagrams directory;
the phase journey lives with the
[program](https://tltaylor1.github.io). The
finished diagrams below are all still to be drawn by hand, and they
replace the sketches as they complete. The first ten are the
observed half's, as listed at version one.

1. **System context.** Operator, application, database, imported
   files, exports out. The one-glance picture.
2. **Data flow.** The sketch above, drawn properly: import, derive,
   govern, report.
3. **Trust boundaries.** The three boundaries with the controls at
   each.
4. **The data model.** The tables and their relationships.
5. **Ingestion sequence.** A file's path from upload through bounds,
   verification, observation rows, and the single commit.
6. **Derivation concept.** How observations plus governance records
   become the state on screen, the diagram that explains the
   no-status-column decision.
7. **Governance swimlane.** Operator, owner, and administrator across
   the recertification flow, because cross-role handoffs are what
   swimlanes show best.
8. **The trust ladder.** The phased trust model as layers: read-only
   observation, then report-only quarantine, then human-triggered
   reversible action, then temporary approved re-elevation. The
   product's story in one picture.
9. **Campaign lifecycle.** A review cycle from creation through its
   item dispositions to close and evidence export.
10. **The subphase cycle.** The loop every build subphase travels,
    with human review as the gate.


The authorized half adds four:

11. **The two records.** Observations flowing in from files and
    connections on one side, authorizations from people on the other,
    the delta between them, and the campaign writing back to the
    authorized side only.
12. **The scope tree.** One provider's hierarchy with an
    administrator binding on a node and an authorization attached
    beneath it.
13. **A grant path.** An identity reaching a role at a scope through
    an eligible group membership and a cross-account trust, with the
    mode on each hop and the "holds now" and "can obtain" columns.
14. **The campaign triggers.** Expiry and delta feeding the queue of
    decisions owed, each decision writing an authorization or a
    revocation, the alert and its record firing after.
