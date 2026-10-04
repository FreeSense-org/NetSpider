# AGENTS.md

Instructions for coding agents (Claude Code, Codex, Copilot, Cursor, Gemini and others) and for human contributors.
These rules are not optional. `CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md` and
`.cursor/rules/netspider.mdc` all point here.

## Project

**FreeSense NetSpider** is a Windows network diagnostics app (Layer 2 and Layer 3): device discovery and
identification, MAC- and IP-level latency, Path Doctor (where does it break?), Storm Center, Wi-Fi ↔ LAN diagnostics,
a built-in updater and installers. C# / .NET 10 / Avalonia 11.3, MIT licensed, public repository
`FreeSense-org/NetSpider`.

| Path | What |
|---|---|
| `src/NetSpider.Core` | Models, contracts, stores, branding (`AppInfo`), the changelog parser (`Changelog/`) |
| `src/NetSpider.Capture` | Npcap capture and injection, pcapng |
| `src/NetSpider.Discovery` | L2/L3 sweeps, protocol parsers, service and vendor probes, SNMP |
| `src/NetSpider.Fingerprint` | MAC-vendor database, device classifier, vendor logos |
| `src/NetSpider.Diagnostics` | Orchestrator, latency, topology, Path Doctor, Storm Center, AP health, probe-agent hub |
| `src/NetSpider.Wifi` | Native WLAN API |
| `src/NetSpider.Export` | SQLite history, exporters, notifiers |
| `src/NetSpider.App` | Avalonia UI: `Views/` (axaml), `ViewModels/`, `Controls/` (custom drawing), `Services/` (shell, updater), `Theme/NeonTheme.axaml` |
| `src/NetSpider.Probe` | Cross-platform headless probe agent |
| `tests/NetSpider.Tests.Unit`, `tests/NetSpider.Tests.Integration` | xUnit tests |
| `tools/ChangelogTool` | CHANGELOG.md validation, version computation, release notes (CI and release scripts) |
| `tools/IconGen` | Renders the brand SVGs into app/installer assets |
| `build/` | `release.ps1` (installers), `upload-release.ps1`, `prepare-release.ps1` (local release PR) |
| `.github/workflows/` | `ci.yml`, `prerelease.yml`, `release.yml`, `publish-release.yml`, `publish.yml` |

## Build, run, test

```powershell
dotnet build NetworkScan.slnx
dotnet test NetworkScan.slnx                               # must pass before every push
dotnet run --project src/NetSpider.App -- --demo           # simulated 43-device network, no Npcap/admin needed
dotnet run --project tools/ChangelogTool -- validate       # CHANGELOG.md format
```

Real scanning needs Npcap and administrator rights. Useful app switches: `--demo`, `--hide-banners` (screenshots),
`--no-welcome`, `--multi-instance`, `--page <name>`, `--about`, `--about-tab changelog`, `--whats-new [last-seen]`,
`--update-preview [available|downloading|ready|error|uptodate|manual|chip]`. Set `NETSPIDER_HOME` to a scratch folder
to run with a clean profile, and delete it afterwards.

## Code style

- **Match the surrounding code.** Read the file and its neighbours first; follow their naming, structure, comment
  density and patterns rather than introducing new ones.
- C# latest, nullable enabled, file-scoped namespaces, `var` where the type is obvious, expression-bodied members
  for one-liners. MVVM with CommunityToolkit (`[ObservableProperty]`, `[RelayCommand]`), Serilog for logging.
- Package versions live in `Directory.Packages.props` (central package management). Don't add packages without a
  good reason; the app ships self-contained.
- UI: use the theme resources in `Theme/NeonTheme.axaml` (brushes, `Icon*` geometries, `card`/`pill`/`badge` classes)
  instead of hard-coded colours. Compiled bindings are on by default.
- Keep logic testable: pure logic goes into static helpers or Core types with unit tests (see `UpdateLogic`,
  `ChangelogParser`). Every bug fix gets a regression test where practical.
- Small, focused changes. Don't reformat or refactor unrelated code in the same PR.

## Mandatory rules

1. **Changelog entry for every user-visible change, in the same PR.** Add one line per change under
   `## [Unreleased]` in `CHANGELOG.md`, following [CHANGELOG-GUIDELINES.md](CHANGELOG-GUIDELINES.md) exactly:
   one of the categories `Breaking`, `New`, `Improved`, `Fixed`, `Security`, `Removed`, `Deprecated` (in that
   order), user-facing, present tense, one sentence ending with a period. Changes users can't notice (CI, docs,
   tests, invisible refactoring) instead get the `skip-changelog` label. CI fails otherwise.
2. **Conventional Commit PR titles** (they become the squash commit message):
   `feat|fix|perf|refactor|docs|test|build|ci|chore(scope)!: description`. Use the same style for commit messages.
3. **Never push to `main`.** All changes go through a pull request; `main` is protected and squash-merged.
4. **Never edit released changelog sections** (`## [x.y.z] - date`). They are frozen; CI rejects edits. Corrections
   go in a new `[Unreleased]` entry.
5. **Never bump or hard-code versions.** Versions are computed from the changelog and git tags (MinVer,
   `tools/ChangelogTool`). Don't edit `<Version>`, don't create `v*` tags and don't write `## [x.y.z]` sections by
   hand; the release workflow does that.
6. **Run `dotnet test NetworkScan.slnx`** before pushing and keep it green. Add tests for new logic.
7. **Privacy** (below).

## Privacy

NetSpider sees people's networks; the repository must never contain real data from one.

- No real names, user names, e-mail addresses, IP addresses, MAC addresses, host names, SSIDs, serial numbers or
  domain names in code, tests, fixtures, logs, screenshots, docs, commit messages or PR descriptions.
- Use the demo network and made-up data. For addresses use documentation ranges: `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, and locally administered or documentation MACs
  (`02:00:00:xx:xx:xx`, `00:00:5E:00:53:xx`). Private ranges like `192.168.1.0/24` are fine in generic examples.
- Screenshots: only from `--demo --hide-banners` (plus `--no-welcome --multi-instance`), never from a real scan. Check
  every image before committing it.
- Don't paste logs, crash dumps or pcaps from a real machine into issues, tests or docs.

## Releases

You don't release; you write the changelog entry. For reference:

- **Pre-release (automatic):** each merge to `main` with `[Unreleased]` entries is tagged `v<next>-pre.<n>` and
  published to the Pre-release channel (`prerelease.yml`). Release notes = `[Unreleased]`.
- **Release (maintainer):** *Actions → Release* (`release.yml`) or `./build/prepare-release.ps1` computes the version,
  moves `[Unreleased]` into `## [X.Y.Z] - date` and opens the PR `chore(release): vX.Y.Z` with auto-merge. When it is
  merged, `publish-release.yml` tags `vX.Y.Z` and publishes it (`publish.yml`).
- Version rules: Breaking → major, New → minor, anything else → patch, nothing → no release. Details in
  [CHANGELOG-GUIDELINES.md](CHANGELOG-GUIDELINES.md#how-versions-are-computed).
