# Contributing to Prometheon

Thanks for taking the time. This repository is the **Phase 1** subnet: it turns
BitFan Fan Group activity into deterministic on-chain weights. That word —
*deterministic* — is what most of the rules below exist to protect. Every
validator must compute the same weight vector from the same records, so changes
that alter a number are held to a different standard than changes that alter
prose.

---

## Getting set up

```bash
git clone https://github.com/BitSpaceorganization/prometheon_v1.git
cd prometheon_v1
uv sync --group dev
uv run pytest -m unit
```

[`uv`](https://github.com/astral-sh/uv) manages the interpreter, the virtual
environment, and the lockfile. If you would rather use a plain venv, see
[the README](./README.md#alternative-pip-in-a-virtual-environment) — but note
that `uv.lock` is the pinned dependency set CI resolves against, so a lockfile
change must be committed alongside a `pyproject.toml` dependency change.

---

## The checks that must pass

CI runs exactly these. Run them locally before you push; they are fast.

```bash
uv run ruff check src tests neurons
uv run ruff format --check src tests neurons
uv run mypy src/prometheon
uv run pytest -m unit -ra
uv run pytest -m integration -ra
uv run --with bandit bandit -r src/prometheon -ll -q
```

- **mypy runs in strict mode** with `warn_unreachable`. Untyped defs are
  rejected. `# type: ignore` needs a reason next to it.
- **Every test carries a marker** (`unit`, `integration`, `contract`) —
  `--strict-markers` is on, and an unmarked test runs in no CI job.
- **Commits must be signed.** A PR with an unsigned commit fails the security
  workflow. SSH signing is fine: `git config gpg.format ssh` plus a
  `user.signingkey`.

---

## What a good change looks like

**Anything that touches scoring, eligibility, ranking, allocation, or the burn
policy changes consensus.** Those paths are pure and integer-only on purpose:
no floats in the weight math, no wall-clock reads below the runner, no
iteration over an unordered set. If your change makes two validators disagree
by one weight unit, it is a bug, so state in the PR body why the output is
still identical across validators — or why the change of output is intended.

**Test against the real shape, not against your assumptions.** Mocks that agree
with the implementation have hidden four separate defects in this repo. If you
mock an HTTP call, send the real envelope and assert the outgoing headers; if
you change transport behaviour, prove it over a real socket. If you write a
fake that implements a Protocol, add a structural conformance test that the
production adapter satisfies the same Protocol.

**The contract is the authority for platform behaviour.** Wire conventions live
in one place ([`src/prometheon/platform/wire.py`](./src/prometheon/platform/wire.py))
— use them rather than re-deriving headers or unwrapping envelopes inline. Branch
on `error.code`, never on the human-readable message.

**Docs are part of the change.** If you alter an operator-visible flag, error
code, default, or setup step, update the guide under [`docs/`](./docs/) in the
same PR. A doc that says something the code no longer does is treated as a
defect.

---

## Pull requests

- Branch from `main`; do not commit to `main` directly.
- Keep one concern per PR. A refactor bundled with a behaviour change is two
  PRs.
- Write the PR body for a reviewer who was not in the room: what was wrong,
  what you changed, and how you know it works. Paste the output that proves it.
- Link the issue if there is one, and say explicitly if the change alters a
  weight-affecting number.

Reviewers will ask for a failing test first when the PR claims to fix a bug.
That is not friction — it is the only durable proof the bug is gone.

---

## Reporting security issues

Do **not** open a public issue or PR for a vulnerability. Follow
[`SECURITY.md`](./SECURITY.md).

---

## License

By contributing you agree that your contributions are licensed under the
[MIT License](./LICENSE) that covers this repository.
