# Contributing

1. Read docs/STYLE.md and docs/repo-map.md.
2. Set up: `uv sync`, then `git config core.hooksPath .githooks`.
3. Run `uv run pytest`, `uv run ruff check .`, `uv run mypy` and `pwsh scripts/check-style.ps1 docs README.md cspm rules` before a commit.
4. New rules follow docs/procedures/add-a-rule.md and need a positive and a negative test.
5. Commit titles are imperative, under 72 characters and carry no trailers.
