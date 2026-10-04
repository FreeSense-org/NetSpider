# Changelog guidelines

`CHANGELOG.md` is the single source of truth for what changed in NetSpider. It's written by hand, one line per
user-visible change, in the same pull request as the change. Everything else is generated from it:

- the **version number** of every release and pre-release
- the **release notes** in the in-app updater, the GitHub release and the "What's new" dialog
- the **Changelog tab** in *About*

CI checks the format on every pull request (the **Changelog** check), so these rules are strict. They are enforced by
`tools/ChangelogTool`, which uses the same parser as the app (`src/NetSpider.Core/Changelog/`).

## The format

```markdown
# Changelog

Free text about the file (optional).

## [Unreleased]

### New
- The spider web can be exported as SVG. (#142)

### Fixed
- The Devices list no longer jumps to the top while sorting. (#145)

## [1.1.0] - 2026-11-02

### Improved
- Path Doctor finds the failing hop up to three times faster. (#120)

### Security
- The probe agent rejects reports signed with an old key. (#131)
```

The rules:

1. The file starts with `# Changelog`. Free text may follow until the first `##` heading.
2. The first section is always `## [Unreleased]`, written exactly like that. It may be empty.
3. Released sections are `## [X.Y.Z] - YYYY-MM-DD`, newest first, with valid dates that never go backwards. The
   versions are plain `X.Y.Z`: no `v` and no pre-release suffix. **Pre-releases never get a section**: they are built
   from `[Unreleased]`.
4. Inside a section, only these category headings are allowed, **in this order**, each at most once:
   `### Breaking`, `### New`, `### Improved`, `### Fixed`, `### Security`, `### Removed`, `### Deprecated`.
   No other headings (`#### …`, `### Added`, `### Changed`), and no empty categories: leave a heading out if it has
   no entries.
5. Every entry is one line: `- ` followed by a sentence that starts with a capital letter (or a digit, a quote or
   `` ` ``) and ends with a period. Optionally the PR number follows, after the period: ` (#123)`.
   No nested bullets, no `*` or `+` bullets, no continuation lines, no paragraphs between entries.
6. Link references (`[1.0.0]: https://…`) are optional. If you add them, they go at the very end of the file.
7. **Released sections are frozen.** Never edit, reword, re-date or delete them: CI rejects it. If a released entry
   was wrong, add a new entry under `[Unreleased]` (for example under `### Fixed`).
8. Blank lines between headings and entries are fine and ignored.

Check the file locally:

```powershell
dotnet run --project tools/ChangelogTool -- validate
```

Errors come with line numbers, for example
`::error file=CHANGELOG.md,line=12::Unknown category '### Added'. … Did you mean '### New'?`.

## Which category?

| Category | Use it when | Version bump |
|---|---|---|
| `### Breaking` | Something that worked before needs action from the user: a removed command-line switch, a settings or export format that older files no longer load into, a dropped Windows version or architecture, a changed default that changes results. | **major** (1.4.2 → 2.0.0) |
| `### New` | A new feature, view, export, protocol, option or platform. | **minor** (1.4.2 → 1.5.0) |
| `### Improved` | An existing feature works better: faster, more accurate, clearer, easier to use. Includes visible performance and UI polish. | patch (1.4.2 → 1.4.3) |
| `### Fixed` | A bug fix: something didn't work as intended and now does. | patch |
| `### Security` | A security fix or hardening: a vulnerability, a credential or data exposure, an unsafe default, a vulnerable dependency users are affected by. | patch |
| `### Removed` | A feature or option is gone and nobody needs to act (if they do, it's **Breaking**). | patch |
| `### Deprecated` | A feature still works but will be removed in a later release; say what to use instead. | patch |

When one change fits several categories, pick the one that matters most to users. One change is one entry.

### Writing a breaking change

Say what changed, who is affected and what to do. The entry stands alone:

```markdown
### Breaking
- The `--scan` switch is now `--full-scan`; update scheduled tasks and shortcuts that use it.
- Settings exported from 1.x can't be imported; export them again after updating.
```

### Writing a security fix

Describe the effect and the fix, not an exploit recipe. Name the CVE or advisory if there is one. Don't disclose
details of a vulnerability before the fixed release is published: coordinate with the maintainers first.

```markdown
### Security
- The probe agent rejects reports with an invalid signature instead of logging them. (#131)
- Updated SQLite to 3.47.2 to fix CVE-2025-12345 in history imports.
```

## Writing style

- **User-facing.** Write for the person running NetSpider, not for the developer who changed the code. Say what they
  see or can do now. Class names, file paths, refactorings and library internals don't belong here.
- **Present tense, describing the result.** "Path Doctor shows packet loss per hop." / "The update dialog no longer
  freezes on slow networks." Not "Added …", "Fixed a bug where …", or "Will show …".
- **One change per line.** Two unrelated improvements are two entries, even in one PR.
- **Specific.** Name the view or feature ("Storm Center", "Settings → Updates", "the HTML report"). "Various fixes"
  and "Improvements" are not entries.
- **No jargon the user doesn't share.** Network terms users see in the app (VLAN, LLDP, ARP) are fine; internal names
  (`DiagnosticsFeed`, "the orchestrator", "DI", "refactor") are not.
- **No personal data.** No real names, IP addresses, MAC addresses, host names or user names (see `AGENTS.md`).
- A sentence ends with a period. Keep it to one or two lines in the editor; long entries usually hide two changes.

| Instead of | Write |
|---|---|
| `- fixed null ref in DeviceStore` | `- Devices without a host name no longer crash the Devices view.` |
| `- Added SVG export` | `- The spider web can be exported as SVG.` |
| `- Refactored latency engine for perf` | `- Latency measurements use less CPU while monitoring.` |
| `- Improvements to Wi-Fi + fixed roaming bug` | two entries: `### Improved` … and `### Fixed` … |

## When no entry is needed

Changes users can't notice don't need an entry: CI and workflow changes, build scripts, tests, documentation,
refactoring with no visible effect, and code comments. Label such a PR **`skip-changelog`** and the Changelog check
skips the entry requirement (the format is still validated).

If in doubt, add an entry. A dependency update needs one only when users notice it (a fix, a security fix, a
changed requirement).

## How versions are computed

Nobody types version numbers. `tools/ChangelogTool` computes them from the last release tag (`vX.Y.Z`) and the
categories under `[Unreleased]`:

| `[Unreleased]` contains | Next version after 1.4.2 |
|---|---|
| any `### Breaking` | 2.0.0 |
| otherwise any `### New` | 1.5.0 |
| only Improved / Fixed / Security / Removed / Deprecated | 1.4.3 |
| nothing | no release |

- No 1.x release yet: the next release is **1.0.0**.
- A **pre-release** is `<next version>-pre.<n>`, where `n` is the number of commits on `main` since the last release
  tag, for example `1.5.0-pre.7`. Pre-releases sort before their release and after the previous one.
- Untagged local builds read `1.0.0-alpha.0.<n>` or `<next patch>-alpha.0.<n>` (MinVer). That's expected.

```powershell
dotnet run --project tools/ChangelogTool -- next-version         # e.g. 1.5.0
dotnet run --project tools/ChangelogTool -- prerelease-version   # e.g. 1.5.0-pre.7
dotnet run --project tools/ChangelogTool -- notes --unreleased   # the notes a pre-release would ship
```

## How releases happen

**Pre-releases are automatic.** Every merge to `main` with entries under `[Unreleased]` is published to the
Pre-release channel by the *Pre-release* workflow: it computes the version, tags `v1.5.0-pre.7` and publishes the
installers and the update feed. Its release notes are the whole `[Unreleased]` section. A merge that leaves
`[Unreleased]` empty publishes nothing.

**Releases go through a release PR.**

1. A maintainer runs **Actions → Release → Run workflow** on `main` (optionally with a version override), or
   `./build/prepare-release.ps1` locally.
2. The workflow computes the version, moves `[Unreleased]` into `## [1.5.0] - <today>` and opens the pull request
   **`chore(release): v1.5.0`** with the release notes. It starts CI on it and enables auto-merge.
3. When the PR is merged, the *Publish release* workflow tags `v1.5.0` and publishes it to the Release channel (and
   the Pre-release channel, so pre-release users get every release). The release notes are exactly the `## [1.5.0]`
   section.

The `## [1.0.0]` section was written by hand before the first release. *Release* sees that it is written but not
tagged and publishes it directly, without a PR.

To fix wording before a release, edit `[Unreleased]` in a normal PR. After the release, the section is frozen.
