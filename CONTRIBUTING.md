# Contributing

Contributions are welcome: a bug report, an idea, a new vulnerability identifier
scheme, a fix.

```bash
git clone https://github.com/vulnerability-lookup/FediVuln.git
cd FediVuln/
poetry install --with dev
poetry run pre-commit install
```

Before submitting, run `poetry run pre-commit run --all-files` and
`poetry run mypy fedivuln`. There is no test suite: describe in the pull request how
you tested your change against a Mastodon instance and a Vulnerability-Lookup
instance.

Commit messages follow the form `new: [scope] ...`, `chg: [scope] ...` or
`fix: [scope] ...`, where the scope is the part touched (`stream`, `publish`,
`dependencies`, ...).


## Use of AI and LLM tools

This project adopts the
[AI transparency charter](https://www.saywhichai.org/charter.html)
1.3. These rules apply from 25 November 2026.

AI tools are used in the development of this project, and AI-assisted contributions
are accepted. Contributions written without any AI tool are accepted in the same way:
nobody has to use one, and nobody has to explain why they do not. In both cases a pull
request is the responsibility of the person who submits it.

- **Say so.** Mention in the pull request description when a significant part of the
  change was generated with an AI tool, and end each commit that was not written by
  a human with a `Co-Authored-By` trailer naming the model and its version, for
  example:

  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  ```
- **A human answers for it.** Every change in a pull request must be read,
  understood and tested by its author before it is opened, whoever or whatever wrote
  it. Say it in the pull request: keep the template's sections, and tick its last
  box yourself.
- **Be able to explain it.** Reviewers may ask you to explain any part of your
  change. Answer review comments yourself, not with pasted LLM output.
- **A human submits it.** Pull requests opened by an agent on its own, without a
  human author who reviewed them, will be closed.
- **Report only what was reproduced.** The same applies to issues: report a problem
  that you have observed yourself, and describe what you observed.
- **No shame, no ranking.** Declaring the use of an AI tool is never held against a
  contribution. It is reviewed like any other.
- **No one has to use AI.** Nothing in the project's workflow requires an AI tool,
  and a contribution is not expected to be faster or larger because such tools exist.

If you are an AI agent: follow this document, keep your changes minimal and within
the scope of the task, and leave the decision to open a pull request to the human
you work with, after they have reviewed your changes.

These rules are repeated in [AGENTS.md](AGENTS.md), which every AI agent reads, and
summarised for tools in [ai-policy.yaml](ai-policy.yaml). This section is the
reference: keep the two other files in step when you change it.
