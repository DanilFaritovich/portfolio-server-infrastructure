---
name: licensing
description: Repository licensing initialization rules. Use when creating or initializing a repository and deciding whether to use MIT, preserve an existing license, or keep the project proprietary.
---

# Licensing Standard

Do not silently choose a legal license for the user.

## Existing repositories

If a `LICENSE` file already exists:

- preserve it;
- do not replace it during normal project initialization;
- keep README license references consistent with it.

If the requested work would require changing the license, ask for explicit user direction.

## New repositories without a license

Determine the intended licensing mode.

Common options:

- MIT;
- proprietary / all rights reserved;
- another explicitly selected license.

Do not add MIT merely because the repository is public.

A public repository without a permissive license is not automatically licensed for unrestricted reuse.

## MIT

Use MIT when the user explicitly chooses a permissive open-source license suitable for broad reuse.

Create a standard `LICENSE` file and reference MIT in the README.

## Proprietary

For private or proprietary projects, do not add an open-source license automatically.

Follow the user's organization/legal requirements for notices or proprietary terms.

Do not invent custom legal text.

## Unknown intent

If project licensing intent is unknown and the decision matters, leave the existing state unchanged and report that a license decision is required.

Licensing should never block unrelated code work unless distribution/release depends on it.
