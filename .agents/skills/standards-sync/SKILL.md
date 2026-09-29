---
name: standards-sync
description: Efficiently synchronize project-local Codex development standards with this upstream repository without rereading every installed skill. Use when installing, updating, or auditing standards in an existing project.
---

# Standards Sync

Use the standards repository as an installation/update source, not as context that must be fully reread on every task.

## Lock file

Projects using these standards should keep:

`.codex-standards.lock.yaml`

This file records the upstream state used for the current local standards installation.

Recommended shape:

```yaml
version: 1

source:
  repository: https://github.com/DanilFaritovich/codex-development-standards
  ref: <upstream-commit-sha>

profile:
  name: fastapi-vue-clean
  version: 5

skills:
  - task-development-workflow
  - standards-sync
  - code-quality
  - ...

optional_skills:
  - continuous-delivery
```

The lock file contains no secrets.

Commit it to the target repository.

## Initial installation

For the first installation:

1. read `catalog.yaml`;
2. select the applicable profile or individual skills;
3. read only the selected core `SKILL.md` files;
4. install each selected skill package locally, including its colocated `references/` files when present;
5. transfer reference assets without rendering their contents into model context whenever the available tooling supports direct copy/materialization; otherwise fetch each required reference once for installation and do not analyze/reread it unless the current project adaptation requires that topic;
6. record the exact upstream commit SHA in the lock file;
7. record the installed profile and skill names.

Do not scan unrelated upstream skills or eagerly load every reference.

## Single-fetch rule

Within one standards synchronization run, fetch each required upstream file at most once, including core `SKILL.md` and changed reference files.

After a successful fetch:

- reuse the returned content for analysis and local installation/update;
- keep using that same content if a local patch/write must be retried;
- do not fetch the same upstream file again merely to verify the write.

A second fetch is justified only when:

- the first fetch failed and no content was obtained; or
- the selected upstream ref/commit changed during the synchronization.

Do not spend network/tool calls proving that a successfully fetched skill still contains the same text later in the same run.

## Reference transfer without model context

Reference files that do not require semantic adaptation are package assets, not default reasoning context.

Preferred flow:

```text
changed paths
-> transfer changed reference assets directly
-> keep their contents out of model context
-> read a reference only when its topic is required
```

When the available tool can copy, materialize, download, or otherwise transfer a reference file without returning its text to the model, prefer that mechanism over a content-returning fetch.

If no such transfer is available:

1. fetch each required reference at most once;
2. write/install it immediately;
3. do not summarize, inspect, compare, or reread it unless its topic is required for project adaptation.

Do not load a reference merely to prove that it was installed.

## Safe write fallback

If the normal patch/write mechanism cannot modify an installed skill directory, first distinguish a Codex sandbox restriction from a real filesystem permission/ownership/mount failure.

### Sandbox-managed read-only/restricted path

When the failure is caused by the Codex sandbox or managed permission profile (for example, a project-local `.agents` path is intentionally exposed read-only even though the developer owns the files):

1. do not change filesystem permissions, ownership, or mount configuration;
2. do not use `sudo`, `su`, `chmod`, `chown`, remounting, or another privileged OS-level bypass;
3. do not refetch upstream content that was already obtained;
4. prepare the complete replacement before mutating an existing installed file;
5. when the runtime supports explicit user approval for an unsandboxed command, request approval for one narrowly scoped **non-privileged** write operation that updates only the required standards paths;
6. reuse the already fetched upstream content for that approved write;
7. do not widen the approved command to unrelated project files, shell configuration, credentials, or other protected paths;
8. after the approved standards write completes, return immediately to normal sandboxed execution;
9. if the user declines the approval or no approved unsandboxed mechanism is available, stop the synchronization and report the exact blocked paths.

An explicit user-approved unsandboxed write is a sandbox capability exception, not permission repair. It must still run as the normal developer user and must not rely on OS privilege escalation.

### Real filesystem permission, ownership, or mount failure

If a non-sandboxed/non-privileged write still fails because of real OS-level permissions, ownership, or a genuinely read-only mount:

1. do not probe privileged alternatives;
2. do not use `sudo`, `su`, `chmod`, `chown`, or remounting to bypass the failure;
3. preserve any valid existing skill until a replacement can be written successfully;
4. do not delete an existing `SKILL.md` first;
5. stop synchronization and report the exact blocked path and failure.

Filesystem ownership/permission/mount repair is a developer/environment responsibility, not part of standards synchronization.

Never use a delete-first replacement that can leave the project without a valid installed skill after a later write failure.

## Update workflow

When a lock file already exists:

1. read the local lock file first;
2. resolve the current upstream target ref/commit;
3. if the upstream commit equals the locked `source.ref`:
   - inspect only the target project's pending changes under `.agents/skills/` and `.codex-standards.lock.yaml`;
   - if there are no pending standards-sync changes, stop: standards are already current;
   - if pending standards changes are consistent with an incomplete synchronization/delivery, do not refetch upstream and resume local validation, staging, commit, push, and PR/CI delivery as applicable;
   - if the pending standards changes are unrelated or ambiguous, report the conflict instead of overwriting them;
4. otherwise compare the locked upstream commit with the new upstream commit;
5. inspect the changed-file list before fetching skill contents;
6. fetch only:
   - `catalog.yaml` when it changed;
   - the active profile when it changed;
   - changed files inside installed skill packages, including changed `references/`;
   - newly applicable skill packages introduced by the updated profile;
7. install changed reference files locally using direct context-free transfer when supported; otherwise fetch each required reference once without semantic analysis unless its topic is required;
8. do not fetch unchanged installed skill files;
9. do not fetch unrelated skills;
10. preserve compatible project-specific adaptations;
11. update the lock file only after the project-local standards and required project changes are complete.

A repository compare operation or changed-file list is preferred over opening every upstream file.

When the locked commit equals the resolved upstream commit, do not fetch catalog/profile/skills merely to reconfirm an unchanged revision. First distinguish a clean completed sync from pending local standards work, then either stop or resume delivery without restarting upstream synchronization.

## Profile changes

If the active profile changed:

1. read the new profile;
2. compare its required/optional skill list with the lock file;
3. fetch/install newly required skill packages, including their references;
4. update only changed files inside already installed required skill packages;
5. do not automatically enable optional skills unless they apply to the project;
6. remove a local skill only when upstream/profile changes clearly make it obsolete and project-specific rules do not still require it.

## Do not verify byte-for-byte equality

Do not require local project skills to be byte-for-byte identical to upstream.

Forbidden verification patterns include:

- refetching every skill to compare Git blob SHA values;
- `git hash-object` checks performed only to prove upstream equality;
- changing files solely to match upstream trailing newlines or insignificant whitespace;
- treating local/upstream blob mismatch as an error by itself.

The lock file records the upstream revision that was used. Project-local skills may contain compatible project-specific adaptations, so identical blob hashes are not a correctness requirement.

Validate semantic/project compatibility instead of byte identity.

## Local adaptations

Project-local standards may differ from upstream where the project requires it.

Do not blindly overwrite local changes.

For each changed upstream skill:

- identify meaningful upstream changes;
- merge them into the local project version;
- preserve compatible project-specific rules;
- report conflicts that require a project decision.

Avoid reproducing unchanged upstream text merely to prove that it was checked.

## Project implementation changes

After synchronizing changed standards, inspect only the project areas affected by those changed rules.

Do not perform a full repository audit merely because the upstream standards commit changed.

Example:

```text
upstream change: code-quality only
-> inspect Makefiles / lint / format / typecheck workflow
-> do not reread persistence, Docker, Vue architecture, etc.
```

If several changed skills affect architecture/infrastructure, widen the audit only to those affected areas.

## One authoritative upstream channel

Use one authoritative mechanism to inspect the upstream standards repository during a synchronization.

When an authenticated GitHub connector/integration is available, prefer it for:

- resolving branches/commits;
- comparing revisions;
- fetching catalog/profile/skill files.

Once an authoritative upstream channel has been selected, keep all upstream inspection on that channel for the rest of the synchronization.

When the GitHub connector is selected:

- use connector compare results as the source of truth for changed upstream paths;
- fetch changed upstream files through the connector;
- do not run local `git diff`, `git fetch`, `git ls-remote`, or equivalent Git commands to inspect the upstream standards commits;
- do not depend on local availability of upstream Git objects;
- do not trigger promisor/partial-clone object fetching merely to inspect upstream standards history.

Local Git is reserved for the target project's own working tree, index, branches, commits, and final delivery operations.

Preferred boundary:

```text
upstream standards:
GitHub connector compare/fetch

target project:
local git status/diff/add/commit/push
```

Do not verify the same upstream state independently through web search, local Git, and the GitHub connector unless the selected upstream mechanism failed or produced ambiguous results.

If a local Git command unexpectedly tries to fetch an upstream/promisor object during standards inspection, stop that path and continue from the already selected authoritative upstream source instead of retrying the network-dependent command.

## Efficient upstream access

Preferred:

```text
local lock
-> upstream latest commit
-> compare commits / changed paths
-> fetch changed profile/skill-package files only
```

Avoid:

```text
catalog
-> profile
-> fetch every skill
-> discover most files were unchanged
```

## Completion

A standards sync is complete when:

- applicable changed/new skill packages are installed, including their reference files;
- project-specific adaptations are preserved;
- affected project implementation/configuration is aligned when required;
- the lock file points to the exact upstream commit used;
- no unrelated skills were loaded or changed.
