---
name: testing
description: Writing and running tests in an existing repository using its own framework and conventions.
---
# Testing
- Detect the framework first (`repo_map`, package.json scripts, pytest.ini, go.mod). Use what exists; do not introduce a new framework.
- Put tests where the repo puts them and mirror naming. Cover the happy path, edge cases, and one failure mode for each behaviour you add or change.
- Run the narrowest test first, then the full suite. Report counts (passed/failed/skipped) exactly as the runner prints them.
- A test that cannot fail is useless: confirm new tests fail without your change when feasible.
- Flaky or slow tests: report them, do not hide them. Never delete or skip a failing test just to get green.
