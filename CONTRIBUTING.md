# Contributing to panopticon-response-engine

Thanks for your interest in contributing.

## Development setup

```bash
git clone --recurse-submodules https://github.com/<your-username>/panopticon-response-engine.git
cd panopticon-response-engine
python -m venv .venv
.venv/Scripts/activate   # macOS/Linux: source .venv/bin/activate
pip install -e . pytest ruff
```

If you already cloned without `--recurse-submodules`, run
`git submodule update --init --recursive` to pull in `tests/vendor/panopticon-contracts`, which
`tests/test_contract_fixtures.py` depends on.

## Running checks

These are the same commands CI runs (see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```bash
ruff check .
pytest -v
```

`ruff` is configured in `pyproject.toml` (`line-length = 100`, `select = ["E", "F", "I"]`) and
excludes `tests/vendor` (a vendored separate repository, not this package's own source).

## What this package is and isn't

This is a **pure domain library**: the closed 7-action response vocabulary, tier policy,
recommendation translation, and lifecycle state machine. Read
[`docs/OWNERSHIP.md`](docs/OWNERSHIP.md) before proposing a change — it lays out exactly what this
package owns and what it explicitly does not (persistence, HTTP/transport, authentication identity,
and OS-specific execution all belong to consumers, chiefly `panopticon-manager`).

## Hard constraints on changes

- **Do not add an 8th action.** The 7-action set in `response_engine/contract.py` is closed and
  security-reviewed. If you believe a new action is genuinely needed, open an issue explaining the
  gap before writing code — this is an architectural decision, not a routine PR.
- **Do not weaken `response_engine/policy.py`'s locked tiers.** `KILL_PROCESS`, `ISOLATE_HOST`, and
  `RELEASE_HOST_ISOLATION` must never become `AUTO_SAFE`, regardless of severity or convenience.
- **Do not make `translate_recommendation` guess.** It must keep failing closed (returning `None`)
  when it cannot safely map a recommendation — never default to a "best guess" target.
- **Do not add I/O, a web framework, a database, or OS-specific execution code** to
  `response_engine/`. That breaks the reason this package is a separately-extracted, dependency-free
  library.
- If a change affects the wire contract, update `tests/vendor/panopticon-contracts` fixtures'
  consumer expectations and coordinate with `panopticon-manager` and
  `panopticon-detection-engine` in the same change description.

## Pull request guidelines

- Add or update tests under `tests/` for any behavior change.
- Keep `ruff check .` clean.
- Use descriptive commit messages; [Conventional Commits](https://www.conventionalcommits.org/)
  style (`fix:`, `feat:`, `docs:`, `test:`, ...) is preferred.
- Fill out the PR template, including Security Impact and Cross-Repository Impact.

## Reporting security issues

Do not use pull requests or public issues for security vulnerabilities — see
[`SECURITY.md`](SECURITY.md).
