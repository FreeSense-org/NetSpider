# Copilot instructions

The canonical instructions for this repository are in [AGENTS.md](../AGENTS.md). Read it before making changes.
Key rules, repeated here because they are enforced by CI:

- **Changelog:** every user-visible change adds one line under `## [Unreleased]` in `CHANGELOG.md` in the same PR,
  following [CHANGELOG-GUIDELINES.md](../CHANGELOG-GUIDELINES.md): categories `### Breaking`, `### New`,
  `### Improved`, `### Fixed`, `### Security`, `### Removed`, `### Deprecated` (in that order, no others), entries
  `- User-facing sentence in present tense. (#123)`. Changes users can't notice get the `skip-changelog` label.
- **PR titles** are Conventional Commits: `feat|fix|perf|refactor|docs|test|build|ci|chore(scope)!: description`.
- **Never** push to `main`, edit released `## [x.y.z]` changelog sections, bump versions or create `v*` tags. Versions
  are computed from the changelog.
- **Tests:** `dotnet test NetworkScan.slnx` must pass; new logic gets unit tests in `tests/NetSpider.Tests.Unit`.
- **Style:** match the surrounding code; C# with nullable, file-scoped namespaces, CommunityToolkit MVVM, theme
  resources from `src/NetSpider.App/Theme/NeonTheme.axaml`.
- **Privacy:** no real names, IP or MAC addresses, host names or user names in code, tests, screenshots or docs.
  Screenshots only from `--demo --hide-banners`.
