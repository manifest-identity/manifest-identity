# AI usage

Built with an AI coding agent under written standards, and this file
records the arrangement: what the agent got wrong, what caught it, and
what each catch changed.

## The approach

The agent works against [AGENTS.md](AGENTS.md) from the first commit, so
the constraints precede the code. Design documents came before any
application code, and the build itself followed the plan in the roadmap section of [README.md](README.md):
ordered subphases, each closed by human review before the next begins.
Commits the agent co-authors carry a trailer naming the exact model, so
the provenance of the code is readable from history the same way the
provenance of every dependency is readable from the lock file.

Most AI-assisted building optimizes for speed. This project optimizes
for the record: the interesting output of working with a generator is
the catalogue of what it produced that was wrong, plausible, or subtly
overclaimed, and what caught it. That catalogue is the section below. It
only ever contains real events, in the order they happened, because a
manufactured entry would defeat the reason this file exists.

## Caught

- **The group model's first draft was wrong.** The agent proposed groups
  as analyzable but ungovernable, argued confidently for it, and the
  human challenge surfaced that access reviews certify group memberships
  as their standard object, so the model was inverted. D-019 records the
  corrected design and names its own rejected first draft.
- **The threat model cited a control that did not exist.** An early
  revision listed a tamper-evident audit trail as a mitigation while
  nothing provided one. Caught in a gap audit; the claim moved to the
  accepted risks, where it now states when the control actually arrives.
- **The pipeline failed itself on its first run.** The workflow
  downloaded a tool archive into the workspace, and the marker scan then
  found forbidden markers inside the archive it had just downloaded.
  The fix sends tool downloads to the runner's temporary directory so
  the workspace stays pristine for its own scans.
- **The marker gate blocked its own sibling.** The commit adding the
  continuous integration workflow was rejected by the pre-commit marker
  hook, because the workflow names the markers in order to forbid them.
  The exclusion is scoped to the two files that must name them, with the
  reason written beside it.
- **A working sketch broke the drawing rules it shipped under.** A
  connector ran straight through a box that was not its endpoint, the
  exact anti-pattern the diagram doctrine names. Caught by human eye;
  the doctrine's verification list gained an explicit trace check.
- **Two document headings were committed broken.** Markdown headings
  cannot wrap across lines; two did. Repaired in a follow-up commit
  rather than a rewrite, so the history keeps the mistake.
- **The writing gate fired a true false positive.** The rule that keeps
  audience language out of these documents flagged the word that names
  this product's user. The exception is a scoped inline allowlist with
  its reason; the rule runs at full strength everywhere else.

- **The provenance record was corrected wrongly, then corrected again.**
  This one took two tries and is the sharpest lesson in the file. Early
  commit trailers named the model as Claude Opus 4.8. The trailers were
  then "corrected" to Claude Fable 5 on the belief that Opus was a
  mistaken string, and this file said so. That correction was itself
  wrong. The runtime switches models between turns: this is a Mythos-class
  model whose safeguards flag dual-use work, and a security tool that
  reads access policies and models attacker moves is dual-use by
  definition, so many turns are handed to a fallback model. The switch
  happens below the model's own visibility, so its self-report is
  unreliable and the original Opus trailers were most likely accurate
  when written. The human resolved it with an external signal the model
  could not see. Because per-turn attribution is not reliably knowable
  from inside, the trailer no longer names one model; from the commit
  that adds this entry forward it reads "Claude (Anthropic), model varies
  per turn," which is the true statement. History is not rewritten,
  because rewriting a provenance record to look cleaner is exactly the
  failure this entry documents. Updated August 20, 2026: the trailer
  shortened to the standard form, "Co-authored-by: Claude" with the
  attribution address, because the standard form is what external
  tooling parses. The limits stay stated, here and in the README,
  rather than in the trailer's name field; no trailer claims a model,
  which remains the true statement.
- **The code only ran on the interpreter it was built on, and no
  gate could see it.** Every self-referencing annotation the agent
  wrote worked on Python 3.14, where annotations are lazy, and
  crashed 3.11 through 3.13 at import with a bare NameError. The
  pipeline tested on the same pinned 3.14 image the Dockerfile
  ships, so the whole gate set shared the blind spot, and the README
  stated no floor. An outside review caught it by doing what the
  README invites: cloning and running on a normal interpreter. The
  sweep that followed found three independent instances where the
  review reported one. The fix is recorded in D-053, and the
  standing mechanism is a pipeline job that runs the whole suite on
  the floor interpreter, so the class is now visible to the gates
  that missed it (August 2026).
- **An edit silently did not happen, and a commit message lied about
  it.** Two scripted text replacements targeted wording that was not in
  the file, and the replacement primitive reports nothing on a miss: a
  comment claimed for the workflow file never landed, and neither did
  the database service block, so the pipeline shipped a job that needed
  a database with no database. The commit message stating the comment
  was in both files entered public history false. Caught by the
  pipeline failing on the missing service; the falsehood is corrected
  forward, not rewritten. The lesson joins the environment one: an edit
  is not made until the result is read back, and a tool that fails
  loudly on a missed match beats one that continues in silence.
- **The sample data found two defects on its first run.** Importing
  both file formats across three generations, which is what real use
  looks like, is something no hand-made demonstration had ever done.
  It exposed an identity upgraded to its real identifier being
  duplicated by the next credential report, because the report could
  no longer recognise it, and a privilege reading that took the newest
  observation rather than the newest value, so an identity's
  group-granted administrator access vanished whenever two sources
  shared a capture time. Both were written weeks earlier and passed
  every test until the fixture stopped being typed by hand.
- **A destructive cleanup ran on a report of state instead of the
  state.** Told that three pull requests were merged, the agent deleted
  their branches without checking; none had merged, and the deletions
  closed all three. Recovery was total, every tip was known and the
  requests reopened byte-identical, but the lesson is the sharpest form
  of the oldest rule here: a destructive action is never justified by a
  report of state, only by the state itself, read at execution time.
  Caught by reading the API after acting, which is one read too late.
- **The vetting itself was weaker than the gate it vetted.** The
  workflow linter delegates embedded scripts to a shell analyzer only
  when one is installed. The build machine had none, so the local
  vetting run silently skipped a whole class of checks and passed;
  the pipeline, which has the analyzer, failed on two unquoted
  substitutions the local run never saw. The analyzer is now installed
  locally, the finding was real and fixed, and the lesson is that a
  passing check proves nothing until the environments match: the same
  tool ran in both places and was not the same gate.
- **The new gates found work before they were installed.** Vetting the
  pipeline batch meant running each tool against the repository first.
  The workflow audit found every checkout persisting a repository
  token on disk for later steps that never needed it; the link checker
  found three references to a file that lives in another repository.
  Then the fix for those links introduced a misspelled address, caught
  only by running the checker again. Fix, then re-verify the fix: the
  second check is not optional, because the fix is written by the same
  hands that wrote the flaw.
- **The secret gate blocked the first code commit.** The moment a
  Python virtual environment existed, the commit-time scan swept it and
  found dozens of example credentials in installed libraries'
  documentation, all fake, and refused the commit anyway. The fix
  scopes the scan with an exclude file for git-ignored tool
  directories, which nothing can commit from; alarms that are always
  false teach the eye to skip the alarm, and a gate nobody believes is
  not a gate.

- **The route drift test had gone silently vacuous.** A framework
  update began wrapping included routers lazily, and the test that
  asserts every route is governed or named public was iterating a
  collection that no longer contained them: it was checking three
  routes and passing. Nothing failed, which is the danger; the gate
  reported green while guarding nothing. Found while extending the
  test to compare against the documented route enumeration, fixed by
  flattening the wrapped routers, and now held by a count canary that
  fails loudly if enumeration ever collapses again. A test must assert
  what it can see before asserting what it sees is right.
- **The mutation check did its job on its first run.** Seven
  controls were each broken deliberately to prove the suite notices;
  six failed as claimed and one survived: with token hashing broken to
  a constant, every fabricated token matched whatever session existed,
  and no test noticed, because every test presented either a real
  token or none. The missing test now exists, and the check that found
  the gap runs in the pipeline.

- **The runbook claimed a verification that had not happened.** The
  operating procedures stated that each was run against a live stack
  before being written down, and folding them into the README exposed
  the tell: the commands named a service that does not exist in the
  compose file, so they had never been executed. The full cycle,
  backup, restore, the throwaway-database drill with counts compared,
  was then actually run with the corrected commands before the folded
  text was allowed to repeat the claim. A procedure that was never
  executed is not yet a procedure, and the claim of
  verification is itself a figure that needs verifying.

- **The agent's own tooling broke its own promise on its first run,
  and the first remedy was the wrong kind.** The script that pushes
  branches under the agent's identity carried a comment saying tokens
  never touch disk; its first execution wrote the token into the local
  branch configuration, because the push URL carried the credential
  and the upstream flag recorded that URL. Nothing reached the
  repository, the file is git's local configuration, which no commit
  carries, and the token was revoked at the provider inside its
  one-hour life. The initial response was scrubbing the file, and the
  human's ruling on that response became the real lesson: needing to
  scrub means the secret was already somewhere it should never have
  been, and a remedy that depends on noticing is not a control. Two
  mechanisms replaced it. The credential left the URL entirely, git
  now receives it through a credential helper from memory, so no
  upstream, log, or configuration write can ever carry it, removing
  the class rather than the instance. And a commit-time gate now
  watches the one file the secret scanner deliberately skips, the
  local git configuration, so anything credential-shaped landing
  there is a build failure, not a discovery.

- **A decision said one thing and the build did the opposite, for
  eighteen subphases.** D-013 decided the application's database role
  holds data rights only and migrations run separately as a
  privileged role, explicitly rejecting schema changes at startup;
  the build ran migrations in the serving container's start command
  as the owner role from the first subphase onward, and the threat
  model cited the unimplemented decision as a control. Nothing caught
  it, not the agent that wrote both the decision and the code, not
  eighteen subphase reviews, until a direct question was answered by
  reading the code instead of the record. The repair is D-051, and
  the lasting mechanism is the pipeline probe that attempts a schema
  change as the runtime role and fails the build unless refused: the
  class of decision-versus-build drift now has at least one gate, and
  the honest note is that only this instance is gated, because such
  drift is found by asking questions, not by grep.

- **The first hands-on session found two defects in its first hour.**
  Every gate was green when the owner sat down to use the application,
  and the sign-in page showed the tabs of an application nobody had
  signed into: the navigation's display rule silently overrode the
  hidden attribute, which any display rule on a hidden element does.
  Then night mode painted every form control black, because form
  controls never inherit text color and only their backgrounds had
  been themed. Both were the kind of defect that no test written by
  the author of the stylesheet was going to write. The fixes are a
  guard that makes hidden final for every element, held by a test
  that pins the guard ahead of the first display rule, and the ink
  token on every control, verified by a computed-style sweep in dark
  mode. Hands-on use is a gate too, and it found in minutes what
  weeks of automated ones could not see (August 31, 2026).
- **The agent pushed to public branches without asking.** Clearing a
  Dependabot backlog, six of whose pull requests failed this
  repository's own parity gates because the bot moves one copy of a
  pin and the gates require every copy to move together, the agent
  began pushing the companion commits onto those branches under its
  identity. The human stopped it mid-command. Nothing in the commits
  was wrong; the push was. The arrangement here is that every push is
  approved by name, each time, and the agent had folded that approval
  into an earlier yes that covered verification and a merge list. The
  correction that came with it changed the working method: the same
  approvals, batched into one question, rather than fewer approvals
  through an allowlist, which the human refused: fewer questions, not
  fewer controls (September 8, 2026).
- **A digest that could not be pulled, and a fix that installed the
  wrong way.** The fuzzing base image was pinned to the digest a local
  pull reported, and the builder could not resolve it, because a local
  pull reports the digest of the platform-specific image it fetched
  and the registry serves the manifest list under a different one. The
  fuzz workflow failed on its first run. The pin is now the digest the
  registry returns, resolved by digest before the commit that names
  it. The next run failed on the build step, because the harness
  installed the application as a package and the application is a
  source tree, not a package. A pin is not verified by reading it, and
  the same day's second lesson is that a new environment must run the
  application the way the application actually runs (September 9,
  2026).
- **The agent accepted a reading of a screen instead of reading the
  screen.** Adding an outside analyzer, the agent gave the right
  address, then heard that the welcome page named a region that was
  not the human's, took that at face value, and opened a pull request
  moving the pipeline and the badge to the analyzer's other server.
  The page itself said, in plain text, that the other server is for
  enterprise plans only and that free public projects live where the
  first address pointed. The pull request closed unmerged, and the
  first address stood. Then the scan's skip condition, written to read
  the secrets context inside a step condition, which the workflow
  syntax does not allow, failed the workflow at parse time, so a
  change meant to add one check briefly ran zero. The condition now
  reads a job-level variable. Two lessons, one old and one new: an
  agent must check the source when a human relays it, and a workflow
  that fails to parse fails silently in the one place nobody watches,
  the list of checks that never started (September 10, 2026).

- **The update bot changed the base image's family, and the gate that
  watched the pin checked only that it moved.** The Dockerfile pinned
  the base by digest alone, with the slim tag named in a comment. A
  digest-only reference gives the bot no tag to follow, so it followed
  the default one, and the September bump the agent completed with a
  companion commit for the workflow twin moved the pin from the slim
  image to the full one, 1.6 GB against 190 MB, carrying the packages
  behind most of the thirty-nine critical findings the scheduled scan
  later reported. The parity gate passed, because both copies moved
  together; the comment kept saying slim; the agent verified the
  twin and not the target. Caught two weeks later, sideways: the
  coverage upload failed the moment the pin was corrected to slim,
  because it had been finding git and curl in an image that was never
  supposed to have them. The fix keeps the tag beside the digest in
  the reference itself, where the bot reads it, and the lesson is the
  pin rule's missing half: a check that a pin moved is not a check of
  what it moved to (September 2026).

- **The agent spent two hours fixing the wrong commit subject.** The
  doctrine gate refused three stacked pull requests. The agent read
  the failing output as the scorer misreading the update bot's commit
  subjects, opened two scorer changes and two pin changes to chase
  that reading, and each re-run failed the same way. The refusal was
  the agent's own subject on the first commit of the stack, which
  named two issues before the colon where the rule allows one. The
  gate had printed the offending subject from the start; the agent
  had been reading the rule rather than the output. The lesson joined
  the standards as a working rule: when a gate refuses, quote the
  refused line before touching anything (September 2026).
- **A shell flag that does not exist emptied a branch.** Rebuilding
  the stack with corrected subjects, the agent passed a quiet flag to
  a command that has none; the command printed its usage and did
  nothing, the script carried on, and the force push that followed
  set the branch equal to main, which closed its pull request. The
  commit still existed locally and the branch was rebuilt within
  minutes, but a script that pushes must stop at the first failure,
  and this one did not check the step that mattered (September 2026).

- **The agent repeated a recorded lesson on the image it was not
  written for.** D-055 records that a check that a pin moved is not a
  check of what it moved to, after the Python base image drifted to
  the full image. The database image had the same untagged pin, and
  when the bot bumped it the agent moved the workflow twin to match
  and merged, without reading the version. The stack had in fact
  jumped a major on the bump before that one and `docker compose up`
  had been failing on fresh clones for three weeks; the pipeline's
  database has no volume and never saw it. Caught by running the
  renamed stack end to end before its pull request opened. The tag
  now sits beside every image digest, the gate refuses one without,
  and the Kubernetes copy is held to the home (D-063). The lesson
  from D-055 is now a rule a machine checks instead of a paragraph a
  person remembers (September 2026).

Each entry changed a rule, a checklist, or a design, which is the point:
the catches compound, the mistakes do not. The provenance entry
changed the attribution itself, and its lesson is the whole file's
thesis turned on its own record: a confident correction can be wrong,
and only an outside check settles it.
