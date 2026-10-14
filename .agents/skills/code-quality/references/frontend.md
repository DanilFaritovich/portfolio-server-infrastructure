# Frontend Quality Reference

Read this reference when the affected project/component uses Vue/TypeScript or similar frontend quality tooling.

Use the package manager and tools already selected by the project.

Typical safe local normalization may include:

```text
eslint --fix
prettier --write
```

or equivalent package scripts.

Typical read-only validation may include:

```text
eslint
prettier --check
vue-tsc / tsc
vitest
```

TypeScript type checking is validation, not a generic auto-fix step.

Prefer component-scoped normalization/checks during development when supported.

Use compact reporters/output while preserving useful diagnostics.
