# Trust0 Link42 Migration and Product Plan

Status: Plan approved; Features 1–6 source-complete

Plan date: 2026-08-29

Product domain: `https://trust0.link42.app`

Canonical repository after transfer: `https://github.com/link42-au/trust0`

## Source of Truth

This file is the authoritative implementation plan for moving Trust0 into the Link42 platform, aligning its public web experience, and evolving identity hosting toward user-owned GitHub repositories with a PR-reviewed Link42 phone book.

Work must proceed in feature-number order. Each feature is sized to be implemented, tested, committed, and pushed in one focused session. Do not begin implementation until this plan is approved. Do not start a dependent feature while any dependency is incomplete.

## Status Definitions

| Status | Meaning |
|---|---|
| `todo` | Approved work has not started. |
| `in_progress` | Implementation is active in one focused session. |
| `blocked` | Work cannot proceed; the blocking dependency is recorded in the feature and Discovered Dependencies table. |
| `source_complete` | Code, documentation, and local tests are complete and pushed, but deployment or live verification is still outstanding. |
| `deployed` | The intended revision is deployed, but the complete live canary has not yet passed or been recorded. |
| `live_verified` | Deployment identity and every required live canary have been recorded successfully. |
| `done` | All feature acceptance criteria are satisfied. For deployable features this requires `live_verified`; for source-only features it requires pushed source and passing required checks. |

An uncaptured, interrupted, or partial test/deployment run is `incomplete`, never a pass. A local pass is not evidence of hosted CI or production behaviour.

## Confirmed Requirements

- Transfer the complete public repository from `wan0net/trust0` to `link42-au/trust0`, preserving history, branches, issues, releases, Actions history, and GitHub Pages settings.
- Preserve and integrate the existing `codex/trust0-security-hardening` branch. It is clean, pushed, and one commit (`1ed636aa`, `Harden trust0 identity flows`) ahead of `main` (`98b9e76a`) at plan creation.
- Preserve `stash@{0}` exactly; do not pop, apply, drop, rewrite, or include it in migration commits.
- Keep all existing identity, proof, signing, export/import, authentication, API, proxy, and bot functionality working.
- Use `trust0.link42.app` for the product and update repository links, documentation, metadata, origins, and deploy configuration from the old owner/domain.
- Add the complete public product suite to Trust0's own banner: `link42`, `rule1`, `patch8`, `threat10`, `trust0`, with Trust0 identified visually and semantically as current. Changes to the other products' banners are owned externally and are not part of this plan.
- Preserve Trust0's teal accent while adopting Link42's Geist typography, neutral light/dark tokens, shared spacing, header/footer language, accessibility, and responsive behaviour.
- Redesign the complete Trust0 web shell and public landing page while retaining all authenticated workflow behaviour.
- Add Vitest and Playwright web coverage for navigation/banner behaviour, theme behaviour, responsive layout, landing content, and signed-in/signed-out states. Required development dependencies are approved.
- Establish the planned identity model: users host signed identity data in repositories they own; a pull request adds a discoverable entry to a Link42 phone book; discovery never replaces cryptographic verification.
- Keep Trust0 entirely free and open source. There is no pricing, billing, subscription, paid tier, commercial upsell, or feature gate in scope now or in the planned product model.
- Use one feature commit per feature in its repository, and push it before beginning the next feature. Never mix unrelated work or use broad staging.
- Deploy and live-verify Trust0 at `trust0.link42.app`, including its own banner, outbound product links, domain, and redesign, before declaring completion.

## Project Information

| Area | Decision |
|---|---|
| Purpose | Free and open-source cryptographic identity verification: users prove ownership of accounts and documents without requiring trust in the Link42 operator. |
| End goal | Trust0 becomes a coherent, entirely free Link42 product at `trust0.link42.app`, while identity ownership moves toward signed, user-controlled GitHub repositories and Link42 provides an optional, reviewed discovery phone book. |
| Users | Individuals creating identities, public viewers verifying claims, technical self-hosters, contributors reviewing phone-book submissions, and Link42 operators. The public journey must work for non-technical users; self-hosting and verification documentation may assume Git/GitHub familiarity. |
| Language/runtime | TypeScript strict mode for Trust0 packages and applications; Svelte 5/SvelteKit 2 frontend; Hono Workers; existing JavaScript in the forked `@trust0/verify` package. Cloudflare Workers/Pages runtime and modern evergreen browsers. |
| Frameworks | SvelteKit with Cloudflare adapter, Hono, Better Auth with GitHub OAuth, `jose`, Web Crypto, D1, and the existing Ariadne/ASPE-compatible libraries. |
| Build/tooling | pnpm workspace, Vite, Wrangler, existing lint/check tools, CSS custom properties, no Tailwind or component framework. Add Vitest and Playwright to the web workspace only where needed. |
| Testing | Existing package/API tests remain mandatory. Add component/programmatic web tests plus Chromium end-to-end tests for public and authenticated-state UI. Every user-facing feature needs browser coverage; logic needs unit tests. |
| Deployment | Cloudflare Pages for `apps/web`; Cloudflare Workers for API, proxy, and bots; D1 remains available during migration. GitHub Actions remains the hosted validation path. CI/CD workflow changes are not authorised by this plan and require separate approval if discovered as necessary. |
| Data/storage | Current signed JWS records and sigchains in D1 remain supported. The target model stores the canonical signed identity bundle in a user-owned GitHub repository. The Link42 phone book stores only discovery metadata and immutable verification references, not private keys or an authoritative identity copy. |
| External services | GitHub OAuth for current sign-in, GitHub repositories and pull requests for the target hosting/discovery flow, supported proof providers, Sigstore Rekor where already used, and existing Discord/Telegram attestation services. |
| Security boundary | Private keys remain non-exportable browser `CryptoKey` objects except existing explicit backup/recovery formats. All identity and claim verification remains client-side. Link42, GitHub, D1, and the phone book are untrusted transports/discovery services, not roots of trust. |
| Reference implementation | Existing Trust0 functionality and tests are authoritative for behaviour. Link42, Rule1, Patch8, and Threat10 are authoritative references for public banner, Geist typography, neutral theme tokens, responsive layout, and shell language. |
| Immediate MVP | Repository transfer, security-hardening integration, canonical domain/link updates, Trust0 banner and shell alignment, complete landing redesign, web test foundation, deployment, and live verification. |
| Planned follow-on | User-owned identity repository schema, publish/update workflow, PR-generated phone-book submissions, phone-book validation, and browser-side discovery/verification. These are planned here but must not delay the immediate Link42 migration unless an explicit dependency is discovered. |
| Product model | Entirely free and open source under the repository's existing licence split: AGPL-3.0 application/bots, Apache-2.0 libraries, and CC-BY-SA specification extensions. No pricing page, billing integration, subscription, paid tier, commercial upsell, or paid feature gate will be introduced. |
| Deferred | Non-GitHub forges, automated repository creation without user consent, decentralised phone-book federation, replacement of every existing D1 path, native mobile apps, and changes to Better Auth configuration. |
| Constraints | Preserve all existing functionality, repository history, pushed branches, and the existing stash. Maintain Ariadne/Keyoxide compatibility and configurable hosting. Meet WCAG 2.2 AA interaction/contrast expectations, keyboard operation, reduced-motion preference, and mobile layouts down to 320 px. |
| Style | Tabs and double quotes in Trust0 TypeScript/Svelte, semicolons, existing section markers, Geist for platform UI, teal accent, CSS custom properties, no CSS-in-JS. Match neighbouring code rather than restyling unrelated authenticated pages. |
| Git discipline | One numbered feature per commit, explicit-path staging only, push after each commit, no history rewriting, no squashing of the existing hardening commit, and no unrelated changes. Commit format: `#<feature>: <description>`. |

## Architecture

### Trust and Ownership Model

```text
User browser
  | creates keys, signs identity state, verifies all signatures and proofs
  v
User-owned GitHub repository
  | canonical portable signed identity bundle; history and hosting controlled by user
  |
  | user opens PR containing a bounded discovery entry
  v
Link42 phone book repository
  | schema checks + duplicate checks + human review; no endorsement of claims
  v
trust0.link42.app
  | reads discovery locator, fetches signed bundle, verifies locally in viewer browser
  v
Verified profile view (or explicit verification failure)
```

The phone book answers only “where is this identity bundle?” It does not answer “is this person trustworthy?” A merged entry is discoverability, not endorsement. The viewer must verify the identity signature, sigchain continuity, repository binding, current key/fingerprint, and supported external proofs before showing a verified state.

### User-Owned Identity Repository Contract

The contract will be versioned and documented before implementation. At minimum it must define:

- a stable manifest path and schema version;
- the current signed ASP/JWS profile and append-only sigchain;
- a stable identity identifier and current public-key fingerprint;
- content hashes or immutable Git object references for material used by verification;
- proof records and revocations without secrets or OAuth tokens;
- key rotation and repository relocation rules that preserve identity continuity;
- deterministic validation and export so the repository is portable to another Git forge or static host later;
- a safe update workflow that never writes to a repository without explicit user action and scoped GitHub authorisation.

GitHub is the first supported hosting workflow, not a cryptographic dependency. A clone or static copy of the signed bundle must remain independently verifiable.

### Link42 Phone Book Contract

The phone book will be a separate reviewable data boundary, preferably a dedicated public repository or a clearly isolated directory selected before Feature 15. Each entry must contain only the minimum discovery fields:

- stable identity identifier;
- display/search label where the user explicitly elects to publish it;
- canonical repository locator and manifest path;
- current public-key fingerprint;
- schema version;
- optional previous locator/fingerprint continuity reference;
- submission metadata needed for review, not private profile data.

Pull requests must pass deterministic schema, path, uniqueness, URL allow-list, case-collision, and signed-bundle verification checks. Review must confirm repository control and identity continuity. Removing an entry removes Link42 discovery only; it must not revoke or delete the user's identity.

### Migration/Coexistence Rule

The existing D1/API/ASPE model remains functional throughout the migration. User-owned repositories are introduced as an additional canonical/export path behind explicit UI, then become the preferred hosting path only after round-trip, rotation, recovery, and offline verification tests pass. Existing users must retain access to current profiles and export/import operations. No destructive D1 migration or Better Auth change is included.

### Trust0 Web Contract

- Domains: `link42.app`, `rule1.link42.app`, `patch8.link42.app`, `threat10.link42.app`, and `trust0.link42.app`.
- Trust0's banner uses the canonical product order and destinations and exposes Trust0 as current with both visual styling and `aria-current`.
- Trust0 retains teal as its accent but uses the shared neutral palette and Geist typography.
- The banner, header, main content, authenticated navigation, menus, and footer remain usable by keyboard and at 320 px width.
- Theme selection follows the established Link42 persistence/system-preference contract and does not flash an incorrect theme during startup.
- External links are canonical and old GitHub/domain links are removed except where explicitly retained as historical references.
- Trust0 may verify that its outbound links resolve, but this plan neither changes nor asserts the banner content, deployment state, or release status of Link42, Rule1, Patch8, or Threat10.
- Cross-site reciprocal banner availability is external coordination and cannot block Trust0 source work, deployment, or completion.

## Feature Plan

| # | Feature | Scope and Acceptance Criteria | Depends On | Status |
|---|---|---|---|---|
| 1 | **Record migration baseline** | Record current default branch, all local/remote refs, tags, releases/issues/Pages/Actions inventories available before transfer, current remote URLs, `1ed636aa` hardening relationship, and stash identifier. Confirm the worktree is clean. Store no credentials or stash contents. Acceptance: evidence is sufficient to compare post-transfer state and explicitly says `stash@{0}` is untouched. | — | `source_complete` |
| 2 | **Transfer repository to `link42-au`** | Transfer the full GitHub repository without recreating or filtering history. Preserve branches, tags, issues, releases, Actions history, security settings where GitHub supports transfer, and Pages configuration. Update the local `origin` only after GitHub confirms the new canonical repository. Acceptance: commit graph/ref inventory matches baseline; old URL redirects; default branch and `codex/trust0-security-hardening` exist remotely; stash identifier is unchanged. This administrative transfer is a checkpoint, not a source feature, so it does not create an artificial code commit. | 1 | `source_complete` |
| 3 | **Integrate the pushed security hardening** | Fast-forward or merge `main` to include existing commit `1ed636aa` without squashing, amending, rebasing, or duplicating it. Run the complete current test/build suite on the resulting `main`. Acceptance: `main` contains the exact existing commit, all checks pass, the branch remains available, and the stash remains untouched. The existing hardening commit is the feature commit; do not manufacture a second implementation commit. | 2 | `source_complete` |
| 4 | **Add Trust0 web test foundation** | Add web Vitest and Playwright configuration, deterministic fixtures/mocks for signed-out and signed-in `getMe` states, and scripts documented in Commands. Keep tests isolated from production accounts and external writes. Acceptance: smoke tests run locally in one command each, Chromium is the required browser, and existing workspace tests/build remain green. | 3, D-003 | `source_complete` |
| 5 | **Adopt Link42 design tokens and theme foundation** | Replace Trust0's standalone font/token baseline with the shared Geist/neutral light-dark contract while retaining teal accent tokens. Add initial theme application, persistence, system preference, focus-visible, reduced-motion, and contrast-safe states. Avoid route-specific redesign in this feature. Acceptance: programmatic theme tests and light/dark browser checks pass with no startup theme flash. | 4 | `source_complete` |
| 6 | **Build the Trust0 platform banner** | Add the five-product banner in canonical order with `trust0` current, correct domains, keyboard/focus behaviour, mobile overflow/wrapping, and semantic current-product state. Acceptance: navigation tests verify all five destinations and `aria-current`; 320 px and desktop screenshots show no overlap or clipping. | 5 | `source_complete` |
| 7 | **Align the complete Trust0 web shell** | Redesign shared header, authenticated navigation, account menu, content container, and footer to the Link42 shell while preserving sign-in, sign-out, dashboard, signing, and public-profile routes. Update source/docs links to the new canonical locations where they appear in the shell. Acceptance: signed-in and signed-out Playwright flows cover navigation/menu states; keyboard traversal, focus return, Escape/outside-click behaviour, responsive header, and existing route access pass. | 6 | `todo` |
| 8 | **Redesign the public landing page** | Rebuild the full landing page around user-owned identity, independent browser verification, portable signed data, GitHub-hosted identity repositories, and the PR-reviewed Link42 phone book. Preserve honest descriptions of currently available features versus planned hosting behaviour; do not present planned phone-book functionality as live. Acceptance: content hierarchy, calls to action, provider coverage, mobile/desktop layout, theme variants, accessibility, and signed-in/signed-out CTAs have tests. | 7 | `todo` |
| 9 | **Regression-polish Trust0 web routes** | Audit shared CSS effects across dashboard, proof-provider pages, signing, onboarding, and public profile routes. Make only compatibility/accessibility adjustments required by the new shell/tokens, preserving workflows and data contracts. Acceptance: representative public, onboarding, proof, dashboard, signing, and profile routes pass responsive smoke tests; no horizontal overflow at 320 px; no existing controls disappear. | 8 | `todo` |
| 10 | **Switch canonical domain and repository references** | Update runtime origins, ASPE domain defaults, auth/public URLs that do not require Better Auth plugin changes, metadata, README/docs, Trust0-owned package repository metadata, Pages/Worker deployment documentation, badges, and source links to `trust0.link42.app` and `link42-au/trust0`. Preserve self-hosting configurability and upstream provenance such as the `@trust0/verify` doipjs origin. Acceptance: repository-wide search finds no active `wan0net/trust0`, `wan0.net/trust0`, or `trust0.app` production reference except explicitly labelled historical/migration text; build and tests pass. Any required Cloudflare binding, CI/CD, or Better Auth configuration change must be logged and approved before implementation. | 3 | `todo` |
| 11 | **Document Trust0's architecture and product boundary** | In the Trust0 repository only, document Trust0 as Link42's free/open-source portable identity and discovery service. Record the user-owned GitHub repository and PR-reviewed phone-book target, replaceable GitHub/D1/Link42 transports, client-side verification authority, current-versus-planned functionality, and the explicit absence of pricing, billing, subscriptions, paid tiers, commercial upsell, or paid feature gates. Acceptance: Trust0 diagrams, domain tables, product links, licence statements, security boundaries, and planned-versus-live labels agree without editing or depending on broader Link42 plans/docs. | 10 | `todo` |
| 12 | **Specify the portable identity repository format** | Write a versioned, implementation-ready schema and threat model for the user-owned repository contract, including manifest, signed profile, sigchain, hashes, rotation, revocation, relocation, recovery, deterministic validation, privacy, and downgrade/fork handling. Provide valid/invalid fixtures and validation acceptance tests before changing runtime behaviour. Acceptance: schema and fixtures prove round-trip portability and offline verification; no private material enters fixtures. | 11 | `todo` |
| 13 | **Implement local repository bundle export/import** | Extend existing export/import logic to produce and consume the versioned GitHub-ready bundle without requiring GitHub access. Retain existing export formats and D1 paths. Acceptance: deterministic round-trip, tamper rejection, schema-version rejection, key-rotation continuity, and legacy-profile regression tests pass. | 12 | `todo` |
| 14 | **Add explicit GitHub publish/update workflow** | Add a user-initiated flow that prepares or updates the signed identity repository using least-privilege GitHub permissions or a download-and-push path. Never silently create repositories or broaden OAuth scopes. Acceptance: exact write preview, explicit consent, blocked unauthorised writes, safe update/conflict handling, no token logging, and recovery instructions are tested. Better Auth plugin or OAuth scope changes require separate approval before this feature starts. | 13 | `todo` |
| 15 | **Define and validate Link42 phone-book entries** | Select the phone-book repository/location, implement the minimum discovery schema and deterministic validator, add duplicate/case-collision/allow-list/continuity checks, and document reviewer responsibilities and removal semantics. Acceptance: valid and adversarial fixtures pass/fail as expected; entries contain no secrets or unnecessary profile data; merging is explicitly described as discovery rather than endorsement. | 12 | `todo` |
| 16 | **Generate phone-book pull-request submissions** | From a verified local identity bundle, generate the exact bounded phone-book change and guide the user through opening a PR. No PR is submitted without explicit user action. Acceptance: preview matches committed payload, repository ownership/bundle signature is checked, duplicate and stale-fingerprint submissions are blocked, and retry/resubmission is safe. | 14, 15 | `todo` |
| 17 | **Consume and verify phone-book discovery** | Add browser-side lookup that resolves a phone-book entry, fetches the referenced identity bundle, and verifies signatures, sigchain continuity, repository binding, and external proofs locally. Fail closed with understandable error states. Acceptance: valid, missing, moved, stale, forked, revoked, malformed, and tampered identities have end-to-end coverage; phone-book availability is not required for direct-profile verification. | 15, 16 | `todo` |
| 18 | **Complete Trust0 release validation and deployment** | Run the full Trust0 workspace tests/checks/builds and web Playwright suites; verify Trust0's hosted CI completion; deploy the exact pushed Trust0 revision; configure/verify `trust0.link42.app` DNS/custom domain and TLS; and perform Trust0-only live canaries. Acceptance: record Trust0 commit/deployment identity, HTTP/TLS success, Trust0's five-product banner and outbound links, `trust0` current-product state, themes, 320 px/desktop layouts, signed-out landing, authenticated sign-in entry, representative public profile verification, API/proxy reachability, and no old canonical links. Outbound links may be checked for reachability, but this feature must not alter or claim the banner/deployment state of another site. Roll back Trust0 to its last known-good deployment if a critical canary fails. | 9, 10, 11 | `todo` |

Features 12–17 are the approved target architecture and follow-on delivery sequence. Feature 18 covers the immediate Trust0 Link42 migration/rebrand release and does not wait on Features 12–17. When the repository-hosting/phone-book workflow is later released, repeat the same source-complete → deployed → live-verified gates for those features.

## Feature Evidence

| Feature | Evidence |
|---|---|
| 1 | Pre-transfer inventory recorded in [`dev/migration-baseline.md`](dev/migration-baseline.md). The index and tracked worktree were clean at capture; the only approved plan/evidence files are recorded. Local and remote refs, GitHub repository identity/settings, branch protection, issues/pulls/releases/tags, Pages, Actions permissions and recent run identity, and the exact hardening relationship are captured. `stash@{0}` remains untouched at `e483e0826230cb1beef96de4485e6866d3114b28`. The feature checkpoint is committed and pushed on `main` before transfer. |
| 2 | Post-transfer comparison recorded in [`dev/migration-transfer.md`](dev/migration-transfer.md). GitHub repository ID `1193472918` and node ID `R_kgDORyLzlg` are preserved at `link42-au/trust0`; the old URL redirects with HTTP 301; `main` is `59b75eadec978191ed50b69a0fd74a94ea449751`; the hardening branch remains `1ed636aa7dd346c3d4eee6d196b37ad954cbe7ab`; PR #1, prior Actions history, repository settings, and legacy `main:/docs` Pages configuration remain present; and local `origin` uses the new canonical URL. Transfer-triggered Pages run `33212752298` attempt 1 failed because its OIDC token carried the old-owner audience, then attempt 2 completed successfully under the new owner without a source or workflow change. `stash@{0}` remains untouched at `e483e0826230cb1beef96de4485e6866d3114b28`. |
| 3 | Source-complete merge integration preserves unchanged first parent `59b75eadec978191ed50b69a0fd74a94ea449751` and exact hardening second parent `1ed636aa7dd346c3d4eee6d196b37ad954cbe7ab`; the hardening commit is neither rewritten nor duplicated. Import now requires proof of possession by the imported identity key through a one-time challenge bound to the authenticated user, exact session, normalized ASPE authority, deterministic bundle digest, nonce, and lifetime; attestations are excluded from the digest because imported server attestations are ignored and require local re-attestation. Verified imports are limited to 40 sigchain links and persisted in bounded chunks. Guarded D1 writes prevent stale or concurrent partial results for import, profile creation, chain initialization, profile rotation, and email challenge consumption; profile/chain writes enforce ownership, active-key authority, verified current state, and the explicit pending-rotation transition. Interrupted browser key rotation is resumable from verified chain state. Canonical ASPE parsing preserves configured authorities with ports and binds signed mutations to the current instance. The proxy and verifier validate each redirect, reject loops and excess hops, and block unsafe targets; the Node verifier additionally validates every resolved address and pins the approved address to the request socket to prevent DNS rebinding. The seven former live-network OpenPGP assertions use a provenance-documented, public-only local fixture while retaining HKP query, WKD fallback, real key parsing/signature verification, and negative-path coverage. Final validation passed: frozen install; identity 102 passed and 5 skipped; verify 442 passed; API 70 passed; verify and web builds; API and proxy Worker dry-runs; verify licence check; diff check; scoped secret scan; and an independent security review with no P0–P3 findings. `stash@{0}` remains untouched at `e483e0826230cb1beef96de4485e6866d3114b28`. D-003 remains open for Feature 4; no hosted-CI, deployment, or live-operation claim is made here. |
| 4 | Added a web-local Vitest configuration and three deterministic `getMe` tests for signed-in, unauthorized signed-out, and unreachable-API states. Added a Chromium-only Playwright configuration plus two browser smoke tests using a fixed synthetic `.invalid` user; the route fixture serves only `/api/me` and blocks every other API request, so the tests cannot reach production accounts or perform external writes. Every workspace package now has an honest `check` boundary using its existing test/build, verifier lint/licence, or Worker dry-run tooling. Validation passed: frozen install; web Vitest 3/3; Chromium Playwright 2/2; root tests with identity 102 passed and 5 skipped, verify 442 passed, API 70 passed, and web 3 passed; all seven workspace `check` scripts; web production build; focused formatting check; and diff check. Existing build warnings about OpenPGP annotations, an empty `hash-wasm` chunk, and mixed static/dynamic `jose` imports remain non-fatal. No CI/CD, binding, authentication, production-data, or external-write change is included. |
| 5 | Replaced the standalone Inter/JetBrains and dark-first baseline with Link42's Geist typography, shared neutral light/dark tokens, semantic state tokens, shadows, and teal product accent. Readable foreground tokens are contrast-strengthened where the decorative Link42 values would not meet the plan's WCAG 2.2 AA requirement. An inline resolver applies cookie, local-storage, or system preference before Svelte renders; the accessible theme control persists its explicit choice across `link42.app`, while unpersisted themes continue to follow system changes. Global focus-visible and reduced-motion rules cover existing controls without route-specific redesign. Six programmatic theme tests cover valid parsing, precedence, pre-render script order, startup-state preservation, shared-domain persistence, toggling, system-change behaviour, and AA contrast for text, actions, and status badges. Three Chromium theme checks verify dark system preference at the first animation frame, explicit light persistence across reload, Geist and neutral computed styles, keyboard focus, and reduced motion; the two existing auth smoke checks remain green. Final validation passed: web Vitest 9/9; Chromium Playwright 5/5; root tests with identity 102 passed and 5 skipped, verify 442 passed, API 70 passed, and web 9 passed; all seven workspace `check` scripts; web production build; and diff check. Existing non-fatal OpenPGP annotation, empty `hash-wasm` chunk, mixed `jose` import, Node colour-environment, experimental SQLite, and Wrangler update notices remain. No banner, route redesign, dependency, lockfile, CI/CD, binding, authentication, external-write, deployment, or sibling-repository change is included. |
| 6 | Added Trust0's own `Link42 products` navigation landmark above the existing header with the exact canonical order and destinations: `link42`, `rule1`, `patch8`, `threat10`, `trust0`. Trust0 is the single current product through `aria-current="page"` and a neutral card treatment with a teal current indicator. Every product remains a native keyboard link with the shared focus-visible treatment. The compact desktop row becomes a five-column mobile grid at 420 px and below, keeping every label inside the 320 px viewport without horizontal document overflow, overlap, or clipping. Four new Chromium checks verify order, exact destinations, the single semantic current state, complete Tab traversal and focus outline, document overflow, pairwise link geometry, and 320 px/1280 px layouts. Temporary screenshots for both viewports were visually inspected and remain ignored test artifacts rather than committed fixtures. Final validation passed: web Vitest 9/9; Chromium Playwright 9/9; root tests with identity 102 passed and 5 skipped, verify 442 passed, API 70 passed, and web 9 passed; all seven workspace `check` scripts; web production build; and diff check. Existing non-fatal OpenPGP annotation, empty `hash-wasm` chunk, mixed `jose` import, Node colour-environment, experimental SQLite, and Wrangler update notices remain. No Feature 7 shell redesign, sibling-site, dependency, lockfile, CI/CD, binding, authentication, external-write, or deployment change is included. |

## Discovered Dependencies

Add a row immediately when implementation reveals an unplanned dependency. Update every affected feature's `Depends On` column before resolving it.

| ID | Dependency | Blocks | Status | Resolution / Evidence |
|---|---|---|---|---|
| D-001 | The hardening commit added `apps/api` Vitest without updating its lockfile importer, so frozen installation failed. | 3 | `resolved` | Regenerated the lockfile mechanically; the only lockfile delta is the three-line `apps/api` Vitest importer. `pnpm install --frozen-lockfile` now passes. |
| D-002 | Seven `@trust0/verify` tests depended on live OpenPGP fixtures fetched from `keys.openpgp.org`; Node connections time out in the current environment. | 3 | `resolved` | Moved the public-only test key into a provenance-documented local fixture and replaced only the test HKP/WKD lookup boundary. The deterministic tests still exercise HKP queries, WKD-to-HKP fallback, OpenPGP parsing, real signature verification, and negative rejection paths. `@trust0/verify` passes all 442 tests, its build and licence check pass, root `pnpm test` passes, and runtime source is unchanged. |
| D-003 | Root `pnpm check` delegates to package `check` scripts, but none of the seven workspace packages defines one. | 4 | `resolved` | Added the smallest truthful `check` script for each package: existing tests/build for identity, API, and web; established lint/licence checks for verify; and Wrangler dry-run compilation for the API, proxy, and both bots. Root `pnpm check` now validates all seven workspace packages successfully without imposing a new formatter baseline on unrelated legacy source. |
| D-004 | Independent integration review found security blockers beyond the original hardening branch coverage: replayable identity import, stale/concurrent D1 writes, interrupted rotation, ambiguous ASPE authorities, and redirect/DNS SSRF paths. | 3 | `resolved` | Added import proof-of-possession and bounded atomic persistence; guarded create, initialization, rotation, and email writes; verified-chain rotation recovery; canonical ASPE authority parsing; and redirect plus Node DNS-rebinding protections. API coverage increased to 70 passing tests, and the final independent security review reported no P0–P3 findings. |

## Per-Feature Workflow

For each feature:

1. Confirm dependencies are `done` and the relevant worktree is clean except for explicitly preserved user changes.
2. Inspect no more than the files needed for that focused feature; split the feature first if it grows beyond roughly 10–15 files or one context window.
3. Implement the feature and its tests together.
4. Run the feature-specific test, then the relevant package/workspace suite.
5. Update this plan's feature status and record evidence.
6. Stage explicit paths only; inspect the staged diff and scan for secrets.
7. Commit with `#<feature>: <description>` and push before beginning another feature.
8. For deployable work, record `source_complete`, `deployed`, and `live_verified` separately.

All implementation, test, documentation, commit, push, and deployment work in this plan is owned by `link42-au/trust0`. Feature 6 changes Trust0's own banner only. Reciprocal banner work in Link42, Rule1, Patch8, and Threat10 is external coordination and must not be committed, pushed, deployed, or claimed by this plan. Repository transfer and exact integration of the pre-existing hardening commit are the two documented administrative/history-preservation exceptions; neither justifies manufacturing or rewriting commits.

## Commands

Run from `/Users/icd/Workspace/keybase/trust0` unless noted.

### Existing baseline

```bash
pnpm install --frozen-lockfile
pnpm test
pnpm --filter @trust0/identity test
pnpm --filter @trust0/api test
pnpm --filter @trust0/web build
pnpm --filter @trust0/api dev
pnpm --filter @trust0/web dev
pnpm --filter @trust0/proxy dev
```

### Web test foundation

```bash
pnpm --filter @trust0/web test
pnpm --filter @trust0/web test:e2e
pnpm --filter @trust0/web test:e2e -- --project=chromium
```

### Full release gate

```bash
pnpm test
pnpm check
pnpm --filter @trust0/web build
pnpm --filter @trust0/web test:e2e
```

If `pnpm check` is not yet implemented consistently across every workspace package, log that as a discovered dependency and add the smallest approved check scripts; do not silently treat a missing check as a pass.

### Deployment commands

```bash
pnpm --filter @trust0/api deploy
pnpm --filter @trust0/proxy deploy
pnpm --filter @trust0/web deploy
```

Bot deployments and D1 migrations are not part of the immediate web migration unless a discovered dependency proves they are required. Database migrations, Cloudflare binding changes, Better Auth configuration changes, and CI/CD changes require explicit approval before execution.

## Release Acceptance Criteria

The immediate Link42 migration is complete only when all of the following are true:

- the canonical GitHub repository is `link42-au/trust0` and preservation checks match the pre-transfer baseline;
- `main` contains the exact pushed security-hardening commit and the original branch remains available;
- the local stash remains present and untouched;
- all existing tests plus new Vitest/Playwright coverage pass;
- Trust0 uses the shared Link42 banner, shell, Geist typography, neutral theme system, teal accent, responsive layout, and accessible interactions;
- the public landing page clearly distinguishes live functionality from the planned GitHub repository/phone-book workflow;
- Trust0's own banner displays and correctly links the complete five-product suite, marks `trust0` current, and passes desktop/mobile accessibility checks; reciprocal banner availability on other sites is external and is not a Trust0 release gate;
- active links, metadata, configuration, and docs use `trust0.link42.app` and `link42-au/trust0`;
- the deployed revision is identified and hosted CI plus live canary evidence is recorded;
- current identity, proof, signing, profile, export/import, authentication, API, and proxy functionality shows no regression;
- no unrelated files, secrets, credentials, stashed changes, or dormant services were modified.

The user-owned identity/phone-book architecture is complete only when Features 12–17 independently reach `done` with round-trip portability, cryptographic verification, least-privilege writes, PR review, failure-path coverage, deployment, and live verification recorded.
