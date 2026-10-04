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
| Provider | The system an identity lives in | AWS, Azure and Entra, Google Cloud, Kubernetes, GitHub, Active Directory (through the directory cmdlets or the SharpHound collector), Okta and its peers, databases, SaaS through single sign-on. The partition or cloud (AWS Commercial, AWS GovCloud (US), Azure Commercial, Azure Government, and so on) is an explicit enumerated field shown on every record, so an auditor filters on it |
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

### The tables

The model is provider-neutral: no table carries a word only one cloud
uses, and the provider's own vocabulary ends at the parser (D-071).

```
scope_nodes --< scope_nodes (the tree, global at the top)
scope_nodes --< imports --< identity_observations >-- identities
imports --< credentials >-- identities
imports --< grants >-- identities, role_definitions, scope_nodes
imports --< memberships >-- identities (groups are identities)
imports --< observed_relationships >-- identities
identities --< governance_records
identities --< authorizations >-- scope_nodes
users --< role_bindings >-- scope_nodes
campaigns --< campaign_items
alerts --< alert_deliveries
audit_events
```

- A **scope node** is one place in a provider's hierarchy: an
  organization, an account, a tenant, a subscription, a cluster. Each
  names its partition explicitly, commercial or government, so a
  government estate is labeled on every record rather than inferred.
  One synthetic node named **global** sits above all of them.
- An **identity** is one principal at one scope node, keyed by the
  provider's immutable identifier, never the name or ARN, which are
  display attributes (D-016). A recreated principal is a new identity.
  Groups are identities of kind group: governable sources of
  privilege, never actors (D-019).
- An **import** is one file or pull: one scope node, one source kind,
  one capture time taken from the file's own content (D-008), unique
  on that triple, so a re-import is rejected rather than
  double-counted.
- A **credential** is one credential as one import saw it. Two access
  keys are two rows and a provider with five is five rows, so nothing
  in the model assumes a cloud that offers exactly two.
- A **grant** is an identity holding a **role definition** at a scope,
  by a path and in a mode. The path records how the privilege arrives,
  hop by hop, through a membership or a trust; the mode records
  whether it is held now or can be obtained, which is what PIM-style
  eligibility is. A role definition is versioned by the hash of its
  contents, so a changed built-in role is a new row and a review can
  show what the role allowed on the day of the decision.
- A **role binding** is authority: a user holding a role at a scope
  node, covering that node and everything beneath it (D-072). Users
  carry no role column. A binding is revoked, never deleted, so the
  record of who could act when survives.
- An **authorization** is what a person said an identity may hold:
  one grant path, an owner, the authorizer taken from the session, a
  justification, and a window that ends (D-073). Nothing is edited. A
  renewal writes a new row that supersedes the old one and a
  revocation writes one too, so the chain from the first authorization
  to the last is the history. Expiry is the clock compared to a
  column, never a job that might not run. Which fields an
  authorization must carry is the administrator's choice, shipped
  strict, and every change to that choice is audited (D-070).
  Authorizations arrive through the form on an identity's page or
  through a file. A file
  keeps its own shape: the import carries a **mapping** that names
  which of their columns holds each field, or a constant for a field
  their file does not have, so nobody is asked to transform their
  spreadsheet before they get anything back (D-074). A mapping is
  written and superseded rather than edited, and every import names
  the mapping that read it, so a mapping later found wrong leaves
  every row it produced findable. Nothing is guessed: a missing
  required column refuses the file, a missing optional one is named
  in the result, unmapped columns are counted, and a date is read by
  a format the mapping declares, because 03/04/2026 is two different
  days in two countries. A dry run shows how the file was understood
  and writes nothing.
  Neither door asks anyone to retype what the system can already see.
  The observed grants come back in the authorized record's own shape,
  as a prefill on an identity's page and as an export in the import's
  columns, with the owner and the justification left empty because
  they are the two things the observed side cannot know. What already
  carries an authorization is marked, so the page asks where the
  answer is still owed. It prefills and never writes: turning what is
  into what should be without a person in the middle would leave the
  delta comparing the observed record against a copy of itself
  (D-024).
- The **delta** is the product, and it is stored nowhere. It is the
  difference between the two records, computed every time somebody
  asks, in nine classes: held but not authorized, reached through an
  unauthorized relationship, expired and still held, can be obtained
  and is not authorized, the role changed after it was authorized, a
  custom definition changed after it was authorized, a custom
  definition nobody authorized, authorized but not held, and owner
  disagreement. The two that read the route rather than the hold
  arrived with 1.6, because comparing what an identity holds against
  what was authorized cannot see access that arrives by assuming a
  role, or the door it arrives through. The two about a definition
  arrived with 1.7, because a custom policy is a thing somebody wrote
  and should own, and when it changes after it was agreed the finding
  names the actions that arrived rather than only saying it moved. Every finding carries when each side
  was last heard from, because a finding from a month-old import is
  true about a month-old world, and a stale side makes a difference
  look like agreement (threat 15).
- An **alert** is a record that people were told, and each delivery to
  each recipient is its own row with its result, so "nobody told me"
  is answerable either way. Alerts fire on an authorization written or
  revoked, an authorization entering its expiry window, and a
  revocation recommended by a review, which is the work item the tool
  produces because it never acts. Delivery sits behind one narrow
  interface; this release records and does not send, so the failure
  paths and the recipient bound are built and tested before any mail
  server is involved. A delivery that fails is recorded as failed and
  never breaks the action that raised it.
- An **integration token** opens a read-only surface under `/api/v1/`
  for a system rather than a person: identities paged from a cursor,
  the delta, and a change feed that walks the audit record from a
  cursor and returns the next one, so a consumer follows decisions as
  they happen rather than polling a full dump. A token is a second kind
  of credential, stored as a hash the way sessions are, shown once at
  minting and never again, revocable, and rate limited per token.
  Session routes refuse tokens and token routes refuse sessions. This
  surface is demonstration-grade: enough to show the shape, and not yet
  hardened for anyone to rely on, which is an open question the plan
  carries on purpose.
- **GitHub is the second native provider** (D-076): one document
  assembled from the REST API's own objects becomes the same neutral
  rows, with the organization and its repositories as scope nodes,
  teams as groups, outside collaborators as guests, app installations
  and deploy keys as identities of their own, and the fixed permission
  levels as provider-managed definitions whose contents say what the
  level can do in the terms the privilege reading already speaks. An
  organization owner, a repository admin, and an app that may write
  members read as administrator equivalent through the same finding as
  an AWS administrator policy.
- **Kubernetes is the third native provider** (D-079): the cluster's
  own dump becomes the same rows, with the cluster and its namespaces
  as scope nodes, service accounts as services, users and outside
  groups as identities the authenticator asserts, the cluster's own
  two groups with their members written, and every role's rules read
  as capabilities, so a role that can bind or escalate reads as
  changing access and a rule for every verb on every resource reads
  as administering. The rules ride as actions, so a changed custom
  role names what it gained.
- **Google Cloud is the fourth native provider** (D-080): a document
  of gcloud's own answers becomes the same rows, with the project as
  the scope node, service accounts keyed by the identifier the
  provider never reuses and their user-managed keys as credentials
  with ages, every member form a policy can write read (a group, a
  domain, the two public forms, a deleted principal a binding still
  names, a federated principal), and a role read from its permission
  list when the export carries one, from a table of the fixed roles
  otherwise, and from its name as the last resort.
- **Azure and Entra are the fifth native provider** (D-081): one
  document of Graph's objects and the command line's output becomes
  the same rows, with the tenant, its subscriptions, and their
  resource groups as scope nodes, members with a password whose second
  factor state the registration report answers, guests from another
  tenant, service principals with their secrets and certificates as
  credentials that expire, groups passing their members up, directory
  roles held standing by members and in the eligible mode by
  privileged identity management, and Azure roles read from their
  actions or their names. An eligibility is what an identity can
  obtain and is never counted as privilege held.
- **Active Directory is the seventh native provider, with two doors**
  (D-083, D-084): a document of the directory cmdlets' objects or the
  SharpHound collector's zip becomes the same rows, with the domain
  as the scope node keyed by its identifier and every organizational
  unit beneath it, a password per user active while the account is
  enabled, a Kerberos key beside it for an account with a service
  principal name, computers as workloads with their machine accounts,
  groups flattened through every level of nesting with the holding
  group named, the built-in groups that hold the domain read from a
  table of what each may do, a member from another domain as an
  external identity, a trust as a relationship, and, from the
  collector alone, a control right on the domain or on a privileged
  group or one of its members as access the principal can obtain.
- **Okta is the sixth native provider** (D-082): one document of the
  management API's objects becomes the same rows, with the
  organization as the scope node, a password only for users whose
  credentials Okta holds, the enrolled factors as the second factor
  state, groups carrying their roles and applications to their members
  with the group's name kept, administrator roles read from a table of
  their types and custom roles from their permissions, and every
  application assignment a grant somebody can be asked to authorize.
- The **observed side reads any provider's table** through the same
  mapping mechanism the authorized side uses, with its own field set
  and a shipped template. An organization with a spreadsheet of
  on-premises accounts, or a vendor's export with no schema, gets the
  same neutral rows the AWS parsers produce and the delta on them the
  same day; a provider earns a native parser later if it earns one at
  all. A definition read this way carries no document, so the
  capability reading says nothing about it, and that limit is stated
  beside the source. The import routes also read a file's shape before
  parsing it and refuse one named as one source and shaped as another,
  naming both.
- A **governance record** is the human layer: an owner, a purpose, a
  flag, or an attestation, on an identity or a group (D-019),
  attributed and audited, stored rather than derived because it IS the
  human input.
- A **review campaign** scopes a set of identities and groups to a set
  of reviewers with a due date (D-021); its items hold each
  disposition, including insufficient evidence, and the campaign
  closes into an evidence export.
- Everything shown about an identity's state, current, stale, unused,
  unowned, over-privileged, is derived from the observed rows plus
  governance records at read time. No status column exists anywhere.

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

Version one has three, in order of hostility:

1. **The imported file.** The only input the application
   accepts from outside, treated as hostile in every particular even
   though it nominally comes from a cloud provider's own reporting:
   bounded, parsed in memory, verified against its own claims, never
   echoed.
2. **The browser session.** Authenticated on every request; nothing
   about a session is trusted from one request to the next. Identity
   names, tags, and paths inside imported data are
   attacker-influenceable and are rendered as text, never markup,
   because the person most exposed to this data is the operator
   reading it.
3. **The exports.** Everything leaving the system passes an allowlist:
   the response models for the API, formula escaping for the
   spreadsheet forms, and deliberate field selection for the report,
   because the inventory is a map of the account's weakest identities
   and an export is that map on the move.

Version one has no outbound connection to any provider. The cloud
credential and its boundary arrive with v0.6, the read-only
connection, and get their own threat model revision first.

The authorized half adds one and sharpens two:

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
