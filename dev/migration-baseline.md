# Trust0 Pre-Transfer Migration Baseline

Status: Captured before repository transfer

Capture started: `2026-08-29T07:25:29+10:00` (AEST) / `2026-08-28T21:25:29Z`

Source repository: `wan0net/trust0`

Target repository: `link42-au/trust0`

This document records the local Git and GitHub-visible state needed to compare the repository before and after transfer. It contains no credentials, secret values, or stash contents.

## Repository Identity and Metadata

| Field | Pre-transfer value |
|---|---|
| GitHub repository ID | `1193472918` |
| GitHub node ID | `R_kgDORyLzlg` |
| Owner/name | `wan0net/trust0` |
| Web URL | `https://github.com/wan0net/trust0` |
| HTTPS clone URL | `https://github.com/wan0net/trust0.git` |
| SSH clone URL | `git@github.com:wan0net/trust0.git` |
| Visibility | Public |
| Description | `trust0 — cryptographic identity verification. Trust no one. Verify everything.` |
| Homepage | Not set |
| Primary API language | JavaScript |
| Repository size | 496 KiB as reported by GitHub |
| Created | `2026-03-27T09:05:45Z` |
| Last GitHub metadata update | `2026-03-27T23:44:20Z` |
| Last push reported by GitHub | `2026-04-12T09:18:38Z` |
| Archived / disabled / fork / mirror | No / no / no / no |
| Stars / watchers / forks | 0 / 0 / 0 |
| Viewer permission used for capture | Admin |
| Detected licence | Other |
| Topics | `cryptography`, `ed25519`, `identity`, `keyoxide`, `open-source`, `privacy`, `verification`, `web-crypto` |

Repository features were enabled for issues, projects, wiki, and Pages; discussions were disabled. Forking was allowed. A repository security policy was not detected.

The merge settings allowed merge commits, squash merges, and rebase merges. Auto-merge, automatic head-branch deletion, default squash-title use, and web commit sign-off were disabled.

The GitHub-visible security-analysis feature flags were all disabled: Dependabot security updates, secret scanning, non-provider-pattern secret scanning, secret-scanning push protection, and secret-scanning validity checks. Only these feature states were queried; secret names and values were not queried.

## Default Branch, Remotes, and Refs

GitHub and `git ls-remote --symref origin HEAD` both identified `main` as the default branch. The local checkout was on `codex/trust0-security-hardening` and tracked `origin/codex/trust0-security-hardening` with no ahead/behind difference.

The local `origin` fetch and push URLs were both:

```text
https://github.com/wan0net/trust0.git
```

### Local refs

| Ref | SHA |
|---|---|
| `HEAD` | `1ed636aa7dd346c3d4eee6d196b37ad954cbe7ab` |
| `refs/heads/codex/trust0-security-hardening` | `1ed636aa7dd346c3d4eee6d196b37ad954cbe7ab` |
| `refs/heads/main` | `98b9e76a146fdd63541013d49b84e26f5918a473` |
| `refs/remotes/origin/codex/trust0-security-hardening` | `1ed636aa7dd346c3d4eee6d196b37ad954cbe7ab` |
| `refs/remotes/origin/main` | `98b9e76a146fdd63541013d49b84e26f5918a473` |
| `refs/stash` | `e483e0826230cb1beef96de4485e6866d3114b28` |

No local tags or `refs/remotes/origin/HEAD` ref were present in `git show-ref --head`.

### GitHub remote refs

| Ref | SHA | Protected |
|---|---|---|
| `refs/heads/codex/trust0-security-hardening` | `1ed636aa7dd346c3d4eee6d196b37ad954cbe7ab` | No |
| `refs/heads/main` | `98b9e76a146fdd63541013d49b84e26f5918a473` | No |

The remote had exactly two branches and no tags. GitHub reported zero branch-protection rules and zero repository rulesets. The REST protection lookup for `main` returned `Branch not protected`.

## Hardening Relationship

| Check | Result |
|---|---|
| `main` | `98b9e76a146fdd63541013d49b84e26f5918a473` (`fix: vite config import + add jose to web deps`) |
| Hardening branch | `1ed636aa7dd346c3d4eee6d196b37ad954cbe7ab` (`Harden trust0 identity flows`) |
| Merge base | `98b9e76a146fdd63541013d49b84e26f5918a473` |
| `main...codex/trust0-security-hardening` left/right count | `0 1` |

The hardening branch was therefore exactly one commit ahead of `main`, with no divergence. Local and remote SHAs matched for both branches.

## Issues, Pull Requests, Releases, and Tags

| Inventory | Count | Detail |
|---|---:|---|
| Issues | 0 | 0 open, 0 closed |
| Pull requests | 1 | 1 open, 0 closed, 0 merged |
| Releases | 0 | None |
| Tags | 0 | None |

GitHub's general `open_issues_count` was 1 because it includes the open pull request.

The sole pull request was draft PR #1, `[codex] Harden trust0 identity flows`, opened by `wan0net` from `codex/trust0-security-hardening` at `1ed636aa7dd346c3d4eee6d196b37ad954cbe7ab` into `main` at `98b9e76a146fdd63541013d49b84e26f5918a473`. It was created and last updated at `2026-04-12T10:43:43Z` and remained unmerged. Its pre-transfer URL was `https://github.com/wan0net/trust0/pull/1`.

## GitHub Pages

| Field | Pre-transfer value |
|---|---|
| Enabled | Yes |
| Status | `built` |
| Build type | `legacy` |
| Source | Branch `main`, path `/docs` |
| Published URL | `http://wan0.net/trust0/` |
| Custom CNAME | Not configured in GitHub Pages (`null`) |
| HTTPS enforced | No |
| Public | Yes |
| Custom 404 | No |
| Protected-domain state | Not set |
| Pending domain verification | Not set |

The most recent Pages workflow run was `pages build and deployment` run 15, ID `23646570002`, for `main` at `98b9e76a146fdd63541013d49b84e26f5918a473`. It was triggered dynamically, completed successfully on attempt 1, and ran from `2026-03-27T12:38:34Z` to `2026-03-27T12:39:17Z`.

## GitHub Actions

Actions were enabled with all actions allowed and required SHA pinning disabled. Default workflow permissions were read-only, and workflows could not approve pull-request reviews.

GitHub reported 54 workflow runs and two workflows:

| Workflow | ID | Path | State |
|---|---:|---|---|
| `trust0 CI` | `252284029` | `.github/workflows/ci.yml` | `disabled_inactivity` |
| `pages-build-deployment` | `252304662` | `dynamic/pages/pages-build-deployment` | `active` |

The most recent repository workflow run was `trust0 CI` run 39, ID `27532417499`, for `main` at `98b9e76a146fdd63541013d49b84e26f5918a473`. It was a scheduled run triggered by `wan0net`, completed successfully on attempt 1, and ran from `2026-06-15T08:01:57Z` to `2026-06-15T08:02:53Z`. Its pre-transfer URL was `https://github.com/wan0net/trust0/actions/runs/27532417499`.

## Worktree and Preserved Stash

At capture start, the index and tracked worktree were clean. The only untracked path was the approved `PLAN.md`. While this evidence was being drafted, the only expected untracked paths were `PLAN.md` and `dev/migration-baseline.md`; there were no staged changes or tracked-file modifications before the plan status update.

The preserved stash inventory, obtained only from `git stash list`, was:

| Selector | Object SHA | Created | Subject |
|---|---|---|---|
| `stash@{0}` | `e483e0826230cb1beef96de4485e6866d3114b28` | `2026-03-27 21:02:01 +1100` | `WIP on main: 07cdc4b docs: add README with quick start, deploy guide, and feature overview` |

`stash@{0}` was not opened, inspected, shown, applied, popped, dropped, or rewritten during baseline capture. Its contents remain untouched and are deliberately absent from this document.

## Post-Transfer Comparison Checklist

After GitHub confirms the transfer, compare the following before changing `origin` or integrating the hardening branch:

- GitHub repository ID and node ID are unchanged, with the canonical owner/name changed only to `link42-au/trust0`.
- The default branch remains `main` and points to the pushed Feature 1 checkpoint whose parent is `98b9e76a146fdd63541013d49b84e26f5918a473`; capture that checkpoint SHA immediately before transfer and require the same SHA after transfer.
- The hardening branch remains at `1ed636aa7dd346c3d4eee6d196b37ad954cbe7ab`. The Feature 1 checkpoint advances `main` independently after this baseline capture, so post-transfer comparison must preserve both tips and their original merge base `98b9e76a146fdd63541013d49b84e26f5918a473`, not expect the branches to remain in a one-commit-ahead relationship.
- The remote still has zero tags and the repository still has zero releases, zero issues, and one open draft pull request, subject to any explicitly recorded transfer-time activity.
- PR #1 and the 54-run Actions history remain reachable under the transferred repository.
- Both Actions workflow identities and their permissions remain present.
- Pages remains configured as legacy Pages from `main:/docs`, or any transfer-required change is recorded before alteration.
- Branch-protection/ruleset state and repository merge, feature, and security-analysis settings match this baseline.
- The old GitHub URL redirects to the transferred repository before the local `origin` URL changes.
- Local `stash@{0}` still resolves to `e483e0826230cb1beef96de4485e6866d3114b28` and remains untouched.

## Capture Limitations

- This is a point-in-time inventory; GitHub timestamps, counters, and workflow state can change after capture.
- GitHub reported repository-visible configuration available to the authenticated administrator. Credentials, secret values, secret names, tokens, deploy-key material, webhook payloads, and environment variables were intentionally not queried.
- No transfer, branch change, commit, push, merge, deployment, runtime edit, or UI edit was performed as part of this baseline.
