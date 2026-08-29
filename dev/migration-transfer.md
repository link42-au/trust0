# Trust0 Post-Transfer Migration Evidence

Status: Repository transfer verified

Comparison captured: `2026-08-29T07:32:37+10:00` (AEST) / `2026-08-28T21:32:37Z`

Baseline: [`migration-baseline.md`](migration-baseline.md)

Canonical repository: `link42-au/trust0`

This document compares the GitHub and local Git state after the administrative repository transfer with the pre-transfer baseline. It contains no credentials, secret values, workflow tokens, or stash contents. No branch change, commit, push, merge, transfer, deployment, code edit, or UI edit was performed while capturing this evidence.

## Transfer Identity and Redirect

| Check | Pre-transfer | Post-transfer | Result |
|---|---|---|---|
| GitHub repository ID | `1193472918` | `1193472918` | Preserved |
| GitHub node ID | `R_kgDORyLzlg` | `R_kgDORyLzlg` | Preserved |
| Owner/name | `wan0net/trust0` | `link42-au/trust0` | Changed as intended |
| Canonical URL | `https://github.com/wan0net/trust0` | `https://github.com/link42-au/trust0` | Changed as intended |
| Old URL | Canonical repository | HTTP `301` to `https://github.com/link42-au/trust0` | Redirect verified |
| Visibility | Public | Public | Preserved |
| Default branch | `main` | `main` | Preserved |

The repository was transferred in place rather than recreated: the stable numeric and node identities are unchanged. The old GitHub URL returned an HTTP `301` with the exact new canonical repository in its `Location` header.

The description, topics, visibility, issue/project/wiki flags, disabled discussions, allowed forking, merge methods, automatic-merge and branch-deletion settings, squash-title default, web sign-off setting, archive/disabled/fork/mirror state, and security-analysis flags match the baseline. GitHub automatically set the repository homepage to `http://link42-au.github.io/trust0/`; it was unset before transfer.

## Branches, History, and Local Remote

| Ref or setting | Post-transfer value | Result |
|---|---|---|
| `main` | `59b75eadec978191ed50b69a0fd74a94ea449751` | Feature 1 checkpoint preserved |
| `main` parent | `98b9e76a146fdd63541013d49b84e26f5918a473` | Pre-baseline `main` tip preserved in history |
| `codex/trust0-security-hardening` | `1ed636aa7dd346c3d4eee6d196b37ad954cbe7ab` | Exact hardening tip preserved |
| Merge base | `98b9e76a146fdd63541013d49b84e26f5918a473` | Preserved |
| `main...codex/trust0-security-hardening` | `1 1` | Expected after independent Feature 1 checkpoint |
| Remote branches | Exactly `main` and `codex/trust0-security-hardening` | Preserved |
| Remote tags | None | Preserved |
| Remote default branch | `main` | Preserved |
| Local `origin` fetch URL | `https://github.com/link42-au/trust0.git` | Updated after transfer |
| Local `origin` push URL | `https://github.com/link42-au/trust0.git` | Updated after transfer |

The remote ref tips match the local refs. The Feature 1 evidence checkpoint advanced `main` by one commit after the baseline inventory, while the hardening branch remained at its exact original commit; the common history therefore matches the baseline's post-transfer checklist.

The local checkout was on `main`, tracking `origin/main`, and the index and worktree were clean before this evidence file and the corresponding plan update were created.

## Pull Requests, Issues, Releases, and Rules

| Inventory | Post-transfer state | Result |
|---|---|---|
| Issues | 0 | Preserved |
| Pull requests | 1 open draft | Preserved |
| Releases | 0 | Preserved |
| Tags | 0 | Preserved |
| Branch protection | No protection on `main` | Preserved |
| Repository rulesets | 0 | Preserved |

PR #1, `[codex] Harden trust0 identity flows`, remains open and draft at `https://github.com/link42-au/trust0/pull/1`. Its head remains `codex/trust0-security-hardening` at `1ed636aa7dd346c3d4eee6d196b37ad954cbe7ab`; GitHub updated the head repository owner to `link42-au`. Its base is still `main`, and its captured base SHA remains the original `98b9e76a146fdd63541013d49b84e26f5918a473`. The PR number, title, state, draft state, timestamps, and history are preserved.

## GitHub Actions and Pages

The two workflow identities and their settings remain present:

| Workflow | ID | Path | State |
|---|---:|---|---|
| `trust0 CI` | `252284029` | `.github/workflows/ci.yml` | `disabled_inactivity` |
| `pages-build-deployment` | `252304662` | `dynamic/pages/pages-build-deployment` | `active` |

Actions remain enabled with all actions allowed, required SHA pinning disabled, default workflow permissions set to read-only, and workflow approval of pull-request reviews disabled. The pre-transfer history is reachable under the new repository, including:

- `trust0 CI` run 39, ID `27532417499`, still completed successfully for `98b9e76a146fdd63541013d49b84e26f5918a473`.
- `pages build and deployment` run 15, ID `23646570002`, still completed successfully for the same commit.

GitHub reports 55 total runs after transfer: the baseline's 54 historical runs plus transfer-triggered Pages run 16, ID `33212752298`, for `main` at `59b75eadec978191ed50b69a0fd74a94ea449751`.

Run `33212752298` attempt 1 built and uploaded the Pages artifact successfully but failed its deployment step. GitHub reported an invalid Actions OIDC audience: Pages expected the new `https://github.com/link42-au` audience but the token carried the former `https://github.com/wan0net` audience. This was a transfer-time owner propagation condition, not a source or workflow change.

The rerun of the same run, attempt 2, started at `2026-08-28T21:30:08Z` and completed successfully at `2026-08-28T21:30:52Z`. Its build, status-reporting, and deployment jobs all passed. No workflow file or Pages setting was changed to obtain the successful rerun.

Pages remains enabled, public, and `built`, using the preserved legacy source `main:/docs`. It still has no custom CNAME, HTTPS enforcement, custom 404, protected-domain state, or pending domain verification. GitHub changed the generated Pages URL from `http://wan0.net/trust0/` to `http://link42-au.github.io/trust0/`, as expected for the new owner.

## Preserved Stash

`stash@{0}` still resolves to object `e483e0826230cb1beef96de4485e6866d3114b28`, with the same subject recorded in the baseline.

The stash was not opened, inspected, shown, applied, popped, dropped, or rewritten during transfer verification. Its contents remain untouched and are deliberately absent from this document.

## Feature 2 Conclusion

Feature 2 is source-complete as an administrative checkpoint. The repository identity, history, required refs, PR #1, earlier Actions history, settings, and Pages configuration survived the transfer; the old repository URL redirects; local `origin` points to the new canonical URL; and the preserved stash object is unchanged. The only recorded transfer effects are the intended owner/URL changes, GitHub's generated Pages/homepage URL update, and the resolved first-attempt Pages OIDC audience failure.
