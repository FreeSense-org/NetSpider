# GEMINI.md

Read and follow [AGENTS.md](AGENTS.md): it is the canonical instruction file for all coding agents in this
repository (project layout, build and test commands, code style, changelog and PR rules, privacy, releases).

The rules you must never skip:

- Every user-visible change adds a line under `## [Unreleased]` in `CHANGELOG.md`, per
  [CHANGELOG-GUIDELINES.md](CHANGELOG-GUIDELINES.md), in the same PR (or the PR gets the `skip-changelog` label).
- PR titles and commits follow Conventional Commits: `feat|fix|perf|refactor|docs|test|build|ci|chore(scope)!: description`.
- Never push to `main`, never edit released changelog sections, never bump versions or create tags by hand.
- No real names, IPs, MACs, host names or user names anywhere; screenshots only from `--demo --hide-banners`.
- Run `dotnet test NetworkScan.slnx` before pushing.
