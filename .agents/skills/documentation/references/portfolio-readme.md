# Portfolio README Presentation

Read this reference **only when the user explicitly requests a new or revised README for a public or portfolio project**. Otherwise, keep regular documentation opt-in. This is a presentation guide, not permission to update README files automatically during feature/fix tasks.

## Intent and references

Present a project both as a reproducible tool and as an engineering portfolio artifact. A newcomer should understand **what it does**, **how it works**, **which technologies it actually uses**, **why key design choices matter**, **how to run it**, and **what has been verified** without first opening a long operator manual.

Use the repository's established style and, where relevant, these examples as presentation references rather than blindly copying their content:

- [MaximML README](https://github.com/DanilFaritovich/maxim-ml/blob/main/README.md): linked technology/CI/license badges, demo screenshots, key engineering decisions, quality checks.
- [Yandex API Region Parser README](https://github.com/DanilFaritovich/yandex-geocoder-region-parser/blob/main/README.MD): compact badge strip, workflow and architecture diagrams, verified stack, testing and sample output.
- [Task Service API README](https://github.com/DanilFaritovich/task-service-api/blob/main/README.md): architecture flows, explicit design decisions, stack table, start instructions.

Do not force this full format onto tiny utility, private, experimental, or internal-only READMEs; adapt to audience and scope.

## Top-of-page identity (portfolio default)

Place near the top, in this order:

1. Project title (`# ...`), with an optional restrained project-related emoji only if consistent with the repo.
2. Visible language navigation (`**English** | [Русский](README.ru.md)` and its mirrored RU version) when bilingual.
3. **Linked badge strip** with the principal *verified* technologies and signals, directly under the title/language navigation, before the long explanation. Use small inline Shields.io/GitHub Actions Markdown images, like the linked badges already used in the portfolio projects.
4. One or two concise introductory paragraphs (or a short one-line description) stating actual purpose and boundaries. A divider (`---`) may separate the header from the first section when it improves readability.

### Badge rules

- Default to roughly **4–9 meaningful badges** in one or two short wrapped lines; fewer is fine. Do not create a noisy wall of icons or badges for every transitive dependency.
- Choose actual core stack components (e.g., Python, FastAPI, Ansible, Docker, PostgreSQL, Vue, React, Apache Airflow) **only when used in that repository**. For an Ansible VPS tool, Ansible/Docker/Ubuntu/Python may be relevant; FastAPI should not appear just because it is used in other projects.
- Prefer badges with an appropriate technology logo (`logo=`) and readable text. Link each technology badge to the official technology site/docs and use clear alt text. Avoid external stock images, fabricated logos or invented brand artwork.
- Include a **real GitHub Actions CI status badge** only if its referenced workflow exists in `.github/workflows/`. Use `https://github.com/OWNER/REPO/actions/workflows/WORKFLOW.yml/badge.svg` linking to the same workflow. The result is a live status, not a static claim of passing tests.
- Include a license badge only after verifying the actual license file and type. A status/release/coverage/test-count badge is optional and must be backed by a real, maintained source; never fabricate a `passing`, `stable`, version, test count, coverage or production-ready claim.
- Match displayed versions against manifests/tool pins and/or explicit verified docs. When no reliable version exists, omit it from the badge (`FastAPI` rather than made-up `FastAPI 0.x`). Do not confuse controller, target server and CI versions.
- Check rendered image URLs, Markdown alt text, target links, casing, and that both language versions display the **same facts and badge destinations**. Remove dead or irrelevant badges when updating an existing README.

### Example Markdown (illustrative, never copy unverified values)

The following demonstrates syntax only; substitute the *actual* repository and technologies, supported versions, workflow filename, and license:

```markdown
# Example Project

**English** | [Русский](README.ru.md)

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Ansible](https://img.shields.io/badge/Ansible-Automation-EE0000?logo=ansible&logoColor=white)](https://docs.ansible.com/)
[![Docker](https://img.shields.io/badge/Docker-Engine-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/)
[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Short factual description of the project...
```

Use `OWNER`, `REPO`, workflow, license, version and badge subjects **only after replacing/checking them**. The example is not a ready-made template asserting that every project uses Python 3.12, Ansible, Docker or MIT.

## Recommended section structure

Adapt the headings and ordering to the task, but for substantial public portfolio projects aim to cover:

| Section | Reader-facing purpose |
| --- | --- |
| About / Overview | The real-world problem, audience, what exists today and what is explicitly out of scope |
| Capabilities / What it demonstrates | A concise explanation of user benefits and engineering value, not generic promotional language |
| Technology stack | Small table of core technologies, verified versions when meaningful, and **why each is used** |
| How it works / Architecture | One accurate Mermaid or plain-text diagram, plus the responsibilities of major components and their flow |
| Key engineering decisions | Important trade-offs with rationale and consequences (security, layering, idempotency, isolation, reliability, testing); only implemented decisions |
| Getting started | Prerequisites, minimal working installation/setup/usage commands and safe first-run expectations |
| Commands / API / Usage | Essential public commands or API endpoints organized for users; move exhaustive details to a linked guide |
| Tests and CI | Offline, integration and real E2E boundaries; how to run checks; verified results with evidence and environment |
| Structure | Concise directory map when it improves orientation |
| Compatibility / Limitations / License | Tested vs untested platforms, known boundaries, relevant license |

- Add screenshots or sample outputs **only when real assets/results exist and improve comprehension**. For backend/CLI/Ansible projects, clear CLI output and architecture diagrams can be better than screenshots; do not generate fake product screenshots.
- Prefer a clear heading hierarchy, short paragraphs, compact tables, readable code blocks and occasional dividers. Section emojis are optional, not a mandatory decoration.
- If the repository already has a long verified README, reorganize/present it without losing technical content; relocate detailed operational/security/recovery material to focused `docs/` guides **only as part of the user's requested documentation work**, preserving links and safety warnings.
- Cross-check the Makefile, CLI, CI workflow and implementation before describing commands or platform support. Do not imply that Docker deployment, TLS, app delivery, Windows/WSL or production VPS testing exists unless it does.
- Explain the difference between automated CI results and operator-reported/manual E2E. Never silently upgrade manual observations into CI guarantees or claim that a future release is already available.

## Bilingual parity and final review

- `README.md` is English and `README.ru.md` is Russian when both requested; keep navigation at the top of each. Translate naturally; the sections can have idiomatic names but should cover equivalent facts.
- Keep technology badges, CI workflow, screenshots, links, command semantics, support matrix, test claims and safety limitations consistent across languages.
- A README is the welcoming project landing page; `ARCHITECTURE.md` is the deeper architectural map, and `docs/` houses lengthy operator/recovery instructions.
- Final check: compare all presented technologies, versions, command examples, badge URLs, workflow links and tested platforms with actual source files. Verify local relative links and Markdown code fences; do not claim links or badge rendering were tested if they were not.
