<!-- Title: Conventional Commit, e.g. "fix(updater): retry downloads after a timeout" (see CONTRIBUTING.md). -->

## What and why

<!-- What does this change, and which problem does it solve? Link issues: "Fixes #123". -->

## Changelog

<!-- Paste the line(s) you added under ## [Unreleased] in CHANGELOG.md, or say why none is needed. -->

## Checklist

- [ ] **Changelog:** a user-facing entry under `## [Unreleased]` in `CHANGELOG.md` ([guidelines](../CHANGELOG-GUIDELINES.md)), **or** the `skip-changelog` label (CI, docs, tests or refactoring users can't notice).
- [ ] **Released sections untouched:** no edits to `## [x.y.z]` sections, no hand-edited version numbers.
- [ ] **Tests:** new or changed logic has unit tests; `dotnet test NetworkScan.slnx` passes locally.
- [ ] **Screenshots:** before/after for every visible UI change, taken with `--demo --hide-banners` (no real network data).
- [ ] **Privacy:** no real names, IP/MAC addresses, host names or user names in code, tests, logs, screenshots or docs.
- [ ] **Title:** Conventional Commit (`feat|fix|perf|refactor|docs|test|build|ci|chore(scope)!: description`).

## Screenshots

<!-- UI changes only. Drag images here. -->
