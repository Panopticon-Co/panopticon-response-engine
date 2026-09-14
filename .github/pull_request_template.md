## Summary
What does this PR change and why?

## Changes
- ...

## Testing
- [ ] Tests added / updated under `tests/`
- [ ] `pytest -v` passes locally
- [ ] `ruff check .` passes locally

## Security Impact
- [ ] No security impact
- [ ] Touches `response_engine/contract.py` (the closed 7-action set) — explain why no 8th action
      is being added
- [ ] Touches `response_engine/policy.py` (tier classification) — confirm no locked
      `ANALYST_APPROVAL` action becomes `AUTO_SAFE`
- [ ] Touches `response_engine/recommendation.py` — confirm it still fails closed (returns `None`)
      rather than guessing a target
- [ ] Adds no I/O, network, or OS-execution code to `response_engine/`

## Documentation
- [ ] README / `docs/OWNERSHIP.md` updated if scope or module responsibilities changed
- [ ] New ADR added under `docs/adr/` if this is an architectural decision

## Cross-Repository Impact
- [ ] None
- [ ] Affects `panopticon-manager` (the sole current consumer) — coordinate the submodule pin bump
- [ ] Affects the recommendation vocabulary consumed from `panopticon-detection-engine`
- [ ] Affects `tests/vendor/panopticon-contracts` fixtures

## Checklist
- [ ] No 8th action added to the closed set
- [ ] No locked tier decision weakened
- [ ] No real process-termination/quarantine/isolation execution added
