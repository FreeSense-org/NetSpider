# Contributing to NetSpider

Thanks for helping! NetSpider is a [FreeSense](https://freesense.org) project, MIT licensed. This page covers how
changes get into `main`. For the code layout and conventions, see [AGENTS.md](AGENTS.md); it applies to people too.

## The short version

1. Branch from `main` (naming below).
2. Make the change, with tests, and run `dotnet test NetworkScan.slnx` before pushing.
3. Add a line to `CHANGELOG.md` under `## [Unreleased]` if users will notice the change
   ([CHANGELOG-GUIDELINES.md](CHANGELOG-GUIDELINES.md)); otherwise label the PR `skip-changelog`.
4. Open a pull request with a **Conventional Commit title** and fill in the template.
5. A maintainer squash-merges it once the checks pass.

`main` is protected: every change goes through a pull request, and PRs are **squash-merged**. Nobody pushes to `main`
directly, not even for releases (the release workflow opens a PR too).

## Branch names

`<type>/<short-description>`, lower case with hyphens, using the same types as PR titles:

```
feat/svg-export
fix/updater-timeout
docs/contributing
ci/release-workflow
```

`release/vX.Y.Z` is reserved for release PRs created by the release workflow.

## Pull request titles: Conventional Commits

The squash merge uses the PR title as the commit message on `main`, so the title must follow
[Conventional Commits](https://www.conventionalcommits.org/). The **PR title** check enforces it:

```
type(scope)!: description
```

| Part | Rule |
|---|---|
| `type` | one of `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore` |
| `(scope)` | optional; lower case, e.g. `updater`, `path-doctor`, `storm`, `wifi`, `changelog` |
| `!` | optional; marks a breaking change (also add a `### Breaking` changelog entry) |
| `description` | imperative, lower case start is fine, no trailing period, title at most 100 characters |

Examples: `feat(export): add SVG export of the spider web`, `fix(updater): retry downloads after a timeout`,
`ci: cache NuGet packages`, `feat(settings)!: drop the legacy settings import`.

The title describes the change for the git history. It doesn't decide the version: the changelog categories do
(see [How versions are computed](CHANGELOG-GUIDELINES.md#how-versions-are-computed)).

## The pull request template

Every PR description uses [the template](.github/pull_request_template.md). Fill in:

- **What and why**: the change, and the problem it solves. Link the issue (`Fixes #123`).
- **Changelog**: the entry you added under `[Unreleased]`, or the `skip-changelog` label with a reason.
- **Tests**: what you added or ran. New logic gets unit tests in `tests/NetSpider.Tests.Unit`.
- **Screenshots**: for every visible UI change, before and after. Take them in demo mode
  (`--demo --hide-banners`) so no real network data shows up.

## Checks

Three checks must pass before a PR can merge:

| Check | What it verifies |
|---|---|
| **Build and test** | `dotnet build` and `dotnet test` of `NetworkScan.slnx` on Windows |
| **Changelog** | `CHANGELOG.md` is valid, and `[Unreleased]` gained or changed an entry (unless the PR is labelled `skip-changelog`); released sections are unchanged |
| **PR title** | the Conventional Commit title |

Run the same things locally before pushing:

```powershell
dotnet build NetworkScan.slnx
dotnet test NetworkScan.slnx
dotnet run --project tools/ChangelogTool -- validate
dotnet run --project tools/ChangelogTool -- check-pr --base origin/main
```

## Privacy

Never commit real network data: no real names, IP or MAC addresses, host names, SSIDs or user names in code, tests,
logs, screenshots or docs. Use the demo network (`--demo`) and documentation ranges (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) for examples. Details in [AGENTS.md](AGENTS.md#privacy).

## Releases

Maintainers release; contributors don't need to do anything beyond the changelog entry.
[CHANGELOG-GUIDELINES.md](CHANGELOG-GUIDELINES.md#how-releases-happen) describes the flow: every merge to `main` with
unreleased entries becomes a pre-release automatically, and a release is a `chore(release): vX.Y.Z` PR created by
the *Release* workflow.
