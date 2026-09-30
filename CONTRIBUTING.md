# Contributing

Contributions are welcome, and the README's Contributing section says what
kind: the open issues labeled for first-time contributors are sized to a
one-screen diff, and anything larger starts as an issue so the shape is
agreed before the work.

Every change travels a branch and a pull request, and the pull request must
pass the gates the README describes under "How it was built and gated",
which run on every push. Run them locally first with the commands in
AGENTS.md; a red pipeline on a pull request is expected during iteration,
but the merge waits for green.

The hooks run the same gates before a commit and, at the second stage,
the pipeline's CodeQL queries before a push, so a finding reaches your
terminal rather than the pull request page. Install both stages once
per clone:

```bash
pre-commit install && pre-commit install --hook-type pre-push
```

Writing matters here as much as code: commit messages lead with an
identifier and say why, documentation follows the writing rules AGENTS.md
states, and the counted figures in the README are recounted by tests, so
a change that adds a test or a route also moves the figure it changes.

By contributing you agree your work is licensed under the repository's
GNU Affero General Public License, version 3 (D-065).
