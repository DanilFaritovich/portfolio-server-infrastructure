# Python Quality Reference

Read this reference when the affected project/component uses Python quality tooling.

For Ruff-based projects, a typical safe local normalization is:

```text
ruff check --fix
ruff format
```

Use only safe configured fixes. Do not enable broad unsafe semantic rewrites merely to make checks pass.

Read-only validation commonly includes:

```text
ruff check
ruff format --check
mypy ...
pytest ...
```

Type checkers such as mypy/pyright are validation tools, not generic auto-formatters.

Write type-correct code during implementation. After deterministic fixes, run the smallest relevant typecheck.

On type failure:

```text
targeted typecheck
-> inspect relevant diagnostics
-> edit affected code
-> rerun targeted typecheck
```

Do not rerun the complete quality pipeline after each type correction.
