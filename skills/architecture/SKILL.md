---
name: architecture
description: Understanding and preserving a project's architecture before changing it.
---
# Architecture
- Build a mental model from `repo_map` and `dependency_map`: entry points, layers, module boundaries, and the direction of dependencies.
- Find the existing pattern for what you are adding (look for a sibling feature) and copy its structure.
- Respect boundaries: do not add imports that invert the dependency direction or create cycles.
- Record decisions that matter in the repo's existing docs (ADR/README), only if the repo already keeps them.
- For cross-cutting changes, list affected modules first, change them in small steps, and run tests after each.
- Avoid unnecessary rewrites: refactor only when it is required for the task, and say why.
