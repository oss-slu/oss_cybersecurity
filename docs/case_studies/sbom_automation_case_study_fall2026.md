# Case Study: Automating SBOMs and Build Attestation at Open Source with SLU

*Fall 2026. One baseline, two repositories, two very different outcomes.*

**Author:** Kysen Krishnaswamy, Security @ Open Source with SLU
**Evidence collected through:** November 14, 2026

---

## Abstract

In Fall 2026 the OSS-SLU security team set out to give every candidate project a Software Bill of Materials (SBOM) generated automatically in CI, together with a signed attestation proving where it came from. At the start of the semester, none of the 22 candidate repositories did this. By November 14, 16 did.

This case study follows that rollout through the repositories where the author built the automation. In **RepoExplorer**, the SBOM workflow merged 4 hours and 29 minutes after it was opened. Since then, all 71 of its runs that executed have passed, and it has attested 23 builds of `main` without a single maintenance commit. In **Material Derailleur**, an equivalent change was approved and merged, but it never reached `main`. When `main` was merged into the branch on merge day, the conflict resolution replaced the change with the old workflow file. That workflow had failed on every run since April, so nobody noticed for 32 days, until the organization replaced it with a central SLSA Build Level 3 workflow. A third case, **DADS**, shows a scan that "succeeded" while describing nothing.

Comparing the cases yields lessons that apply to any student-run organization:

- "Merged" is not "shipped."
- Add CI features in new files.
- Never live with an always-red workflow.
- Choose the scan target from what actually ships.
- Test from a fork the way maintainers will run the change.
- Centralize once the pattern is proven.

---

## At a Glance

| | RepoExplorer | Material Derailleur | DADS |
|---|---|---|---|
| Tracking issue | [oss_cybersecurity#54](https://github.com/oss-slu/oss_cybersecurity/issues/54) | [#23](https://github.com/oss-slu/oss_cybersecurity/issues/23) (baseline), [#36](https://github.com/oss-slu/oss_cybersecurity/issues/36) (automation) | [#63](https://github.com/oss-slu/oss_cybersecurity/issues/63) |
| Pull request(s) | [repoexplorer#76](https://github.com/oss-slu/repoexplorer/pull/76) | [oss_cybersecurity#42](https://github.com/oss-slu/oss_cybersecurity/pull/42), [material-derailleur#772](https://github.com/oss-slu/material-derailleur/pull/772), [#773](https://github.com/oss-slu/material-derailleur/pull/773) | [dads#355](https://github.com/oss-slu/dads/pull/355) |
| Opened → merged | 4 h 29 min | 2 days 15 h (#772) | Still open after 5 days, with no reviews |
| On `main` today? | Yes, unchanged since merge | **No.** Lost on merge day; replaced on Nov 13 by the central workflow | Not yet |
| Runs since merge | 71 executed, 71 passed | n/a | n/a |
| Attested `main` builds | 23 | 0 from #772 | 0 |
| Re-verified for this study | Both SBOMs verified on Nov 14 | Central-workflow SBOMs inspected on Nov 14 | Fork run only |

---

## 1. Background

### 1.1 Why SBOMs and Attestations

An SBOM is a machine-readable ingredient list: every library, package, and system component inside a piece of software. A build provenance **attestation** is a signed statement that binds a specific artifact (identified by its SHA-256 digest) to the repository, commit, and workflow that produced it. Together they answer the two questions the [OSS-SLU Supply-Chain Security Baseline](https://github.com/oss-slu/oss_cicd_automation/blob/main/Docs/Supply_Chain_Security_Baseline.md) opens with: *what is inside this software,* and *where did this exact file or container come from?*

These questions matter even for student projects. Partners deploy OSS-SLU software, and when a widely used library has a critical vulnerability (as [Log4Shell](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) did in 2021), an SBOM is what turns "are we affected?" from a week of digging into a search. The U.S. government's minimum SBOM elements ([NTIA, 2021](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom)) and the [SLSA](https://slsa.dev/spec/v1.0/levels) build levels have made both artifacts standard expectations for open-source software.

### 1.2 How the Program Was Organized

| Phase | When | What |
|---|---|---|
| 1. Baselines | Sprints 1–2 (Sept) | One-time SBOMs produced by hand and stored in [`docs/sbom/`](../sbom/) for Material Derailleur, SALTIFY, GradEval360, DigitalBoneBox, CoreDesk, MechatronicsVR, and shelter_volunteers |
| 2. Automation | Sprints 3–5 (Oct – early Nov) | Issues in this repository asking for SBOM generation, preservation, and attestation in each project's own CI, following the org baseline: SPDX 2.3 JSON from Syft, saved as an artifact, attested with `actions/attest`, verified with `gh attestation verify` |
| 3. Centralization | Nov 11–13 | The CI/CD effort published a reusable workflow, [`slsa-build-attest.yml`](https://github.com/oss-slu/oss_cicd_automation/blob/main/.github/workflows/slsa-build-attest.yml), and five container projects adopted it |

One structural fact shaped everything: security-team students have **read-only** access to most project repositories. Every change went through a fork and depended on the project's own maintainers to review and merge it.

### 1.3 Method and the Author's Role

The author implemented the Material Derailleur baseline (#23) and automation (#36), RepoExplorer (#54), and DADS (#63). The evidence is drawn from:

- pull request timelines, commits, and reviews, read through the GitHub API;
- the full GitHub Actions run history of each workflow;
- SBOMs downloaded from production runs and re-verified on November 14;
- a scan of every workflow file on the 22 candidate repositories' default branches, and the commit history of each one;
- the author's sprint reports.

Times are UTC unless noted. Because the author is also a participant, the conclusions lean on what the records show rather than on recollection; see §11.

---

## 2. Timeline

| Date (2026) | Event |
|---|---|
| Sep 14 | #23 opened: baseline SBOM for Material Derailleur |
| Sep 23 | #36 opened: automate SBOMs and provenance in Material Derailleur's container build |
| Sep 26 | oss_cybersecurity#42 merged: Material Derailleur baseline SBOM (3,480 package entries) |
| Sep 28 | The organization's first automated SBOM workflows land (DigitalBoneBox, MechatronicsVR) |
| Oct 5 | #54 opened: RepoExplorer |
| Oct 8 | Dependabot moves Material Derailleur's server to TypeScript 7. The build check fails, but auto-merge merges it anyway |
| Oct 9 | #63 opened: DADS |
| Oct 10 | material-derailleur#772 (SBOM + provenance) and #773 (TypeScript fix) opened after testing on a fork |
| Oct 12 | #772 approved and merged, but its changes never reach `main` (§4.3) |
| Oct 19 | repoexplorer#76 opened at 19:29 and merged at 23:58 |
| Oct 26 | RepoExplorer SBOMs verified against the `oss-slu` organization |
| Nov 9 | dads#355 opened |
| Nov 11–13 | Central SLSA L3 workflow published and adopted by five repositories. Material Derailleur's old build workflow removed |
| Nov 14 | This study: 16 of 22 candidates generate SBOMs or attestations in CI |

---

## 3. Case A: RepoExplorer, the Rollout That Worked

### 3.1 Context

RepoExplorer has two TypeScript packages: an API server in `api/`, bundled with tsup, and a dashboard in `app/`, built with Vite. Before choosing it, the author compared all eleven open Phase 2 issues on three things: how active each repository was, how healthy its CI was, and how quickly its maintainers merged pull requests from forks. RepoExplorer's maintainer reviewed quickly, which made a merge within the sprint likely. Choosing for reviewability turned out to be one of the most important decisions of the project.

### 3.2 What Was Built

A **new** workflow file, [`.github/workflows/sbom.yml`](https://github.com/oss-slu/repoexplorer/blob/main/.github/workflows/sbom.yml), plus a short guide at [`docs/dev/sbom.md`](https://github.com/oss-slu/repoexplorer/blob/main/docs/dev/sbom.md):

- A two-entry matrix (`api`, `app`) runs Syft through `anchore/sbom-action` and produces `repoexplorer-api-sbom.spdx.json` and `repoexplorer-app-sbom.spdx.json` on every push to `main`, every pull request, and on demand.
- Each SBOM is uploaded as a workflow artifact, and the job fails if the file is missing.
- **On pushes to `main` only**, `actions/attest@v4` signs build provenance for each SBOM, and the job immediately verifies it with `gh attestation verify`, printing the signer workflow and commit to the log as evidence.

Attestation runs only on pushes because pull requests from forks don't receive the `id-token: write` permission that keyless signing needs. Generating the SBOM on pull requests is still useful, because reviewers see the dependency picture of a change before it merges.

### 3.3 The Decision That Mattered: Development Dependencies That Ship

By default, Syft leaves JavaScript development dependencies out of the SBOM, and at first that looked right, because the API's container installs only production packages. The author checked what the builds actually produce instead of trusting the labels in `package.json`. **tsup bundles `cors` into the server, and Vite bundles `recharts` into the dashboard**, even though both are declared as development dependencies. A production-only SBOM would have left out code that ships. The workflow therefore sets `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES: true`, and the PR explains why.

The maintainer's review comment thanked the author for the finding and said both packages would be moved to the right category. As of November 14 they are still listed as development dependencies, so this setting is still the only reason they appear in the SBOM.

### 3.4 Testing From a Fork

With read-only access, every path had to be proven on the author's fork before a maintainer would run it:

- **The push path with attestation** was tested by pushing to the fork's own `main`, since fork pull requests can't sign.
- **A manual run**, where attestation is correctly skipped.
- **Every output**: each SBOM passed the SPDX validator, the issue's own verification commands passed, and a tampered copy correctly failed.
- **Pre-existing failures were documented in the PR.** Three of the repository's existing checks always fail on fork pull requests because they check out `github.head_ref`. The PR linked earlier examples so the reviewer would not blame the new workflow.

### 3.5 Review

The pull request was opened at 19:29 and approved and merged at 23:58, with one comment from the maintainer: thanks for the `cors`/`recharts` finding. The PR was written to be reviewable without any back-and-forth. It linked the test runs, listed the choices a reviewer might question, and explained the existing failures in advance.

### 3.6 Results After 26 Days

| Measure (Oct 19 – Nov 13) | Value |
|---|---|
| Workflow runs | 73 |
| Runs that executed / passed | **71 / 71** |
| Runs held for maintainer approval (fork pull requests) | 2 |
| Pull request runs (SBOMs on contributors' changes) | 48 |
| Attested builds of `main` | **23** |
| Commits to `sbom.yml` since merge | **0** |
| API SBOM size | 583 packages (Oct 25) → 599 (Nov 13) |
| Dashboard SBOM size | 380 → 380 |

The SBOM grew as the API's dependencies changed, and nobody had to touch the workflow for that to happen.

**Independent re-verification (Nov 14).** For this study, both SBOMs from the most recent `main` build ([run 43516077098](https://github.com/oss-slu/repoexplorer/actions/runs/43516077098), Nov 13) were downloaded and checked from scratch:

```bash
gh run download 43516077098 -R oss-slu/repoexplorer
gh attestation verify repoexplorer-api-sbom/repoexplorer-api-sbom.spdx.json --owner oss-slu   # exit 0
gh attestation verify repoexplorer-app-sbom/repoexplorer-app-sbom.spdx.json --owner oss-slu   # exit 0
```

Both verified. The predicate was SLSA provenance v1, signed by RepoExplorer's own workflow on a push to `refs/heads/main`. A copy with one extra byte appended failed, because no attestation exists for its digest. That is the tamper-evidence the baseline promises.

Since November 13, RepoExplorer also runs the central container workflow (§6). The two workflows complement each other. `sbom.yml` describes each package's dependencies, including bundled development code. The central workflow describes the container images.

---

## 4. Case B: Material Derailleur, Approved, Merged, and Never Shipped

### 4.1 The Phase 1 Baseline

Material Derailleur (MDMA) is a donation-tracking web application with a Node.js server and a React client, each published as a container image. For the baseline ([oss_cybersecurity#42](https://github.com/oss-slu/oss_cybersecurity/pull/42), merged Sep 26), the published images required authentication and Docker wasn't available. The author therefore rebuilt each image's `/app` directory from a pinned commit, ran the same `npm install` commands as the Dockerfiles, and scanned the result. The result was an SPDX 2.3 SBOM with **3,480 package entries** (2,393 unique), validated and reproduced from a fresh clone. It surfaced three follow-ups for the project: development dependencies ship in both images, the client lists server-side packages it never imports, and a deprecated `npx` package adds 501 old packages.

Its known limitation was the reason for Phase 2: a folder scan cannot see the **operating system packages or the Node.js runtime** inside the real images.

### 4.2 The Automation (#772) and a Side Discovery (#773)

[#772](https://github.com/oss-slu/material-derailleur/pull/772) extended the existing `build-and-push.yml` matrix (server, client). After each image was pushed, it:

1. generated an SPDX SBOM from the image's exact digest;
2. uploaded it as an artifact;
3. signed a build provenance attestation with `actions/attest@v4`;
4. verified that attestation.

The author used v4 because a teammate's shelter_volunteers workflow had failed after merging on `@v2`. A fork doesn't register its workflows until one of them runs, so testing required a temporary trigger. After that, the [fork run](https://github.com/kysenkrish/material-derailleur/actions/runs/38022811569) passed every step. The server image's SBOM had **1,419 entries, including 413 operating system packages and the Node.js runtime**, which closed the baseline's biggest gap.

Testing also exposed an unrelated break. On October 8, Dependabot moved the server from TypeScript 6.0.3 to 7.0.2 ([#750](https://github.com/oss-slu/material-derailleur/pull/750)). The pull request's `build` check **failed**, but auto-merge merged it anyway, because CI was not a required check. `ts-jest` supports only TypeScript versions below 7, so `npm install` now failed and the server image could not be built from `main`. Nobody noticed, because changes merged with GitHub Actions' built-in token [do not trigger new workflow runs](https://docs.github.com/en/actions/using-workflows/triggering-a-workflow), so the image build never ran. [#773](https://github.com/oss-slu/material-derailleur/pull/773) pinned TypeScript 6 and told Dependabot to skip version 7. A maintainer also merged an equivalent pin (#777) on October 12.

### 4.3 Merge Day, Minute by Minute (October 12, UTC)

| Time | Event |
|---|---|
| 19:13:17 | The maintainer's TypeScript pin (#777) merges |
| 19:24:41 | #774 merges. Among its 29 files is a repository-wide formatting commit that rewrote 27 files, **including `build-and-push.yml` and `README.md`**, the two files #772 changes |
| 19:30:56 | #773 merges |
| 19:31:21 | #772 is approved |
| 19:32:11 | `main` is merged into #772's branch through GitHub's web interface ([`42eb451`](https://github.com/oss-slu/material-derailleur/commit/42eb451542143ee4d2cd3f87bcecc5265f24ba6b)). For both conflicting files, the result is **identical to `main`'s version**, ignoring whitespace |
| 19:32:13 | The new commit automatically dismisses the approval (stale-review dismissal) |
| 19:32:27 | #772 merges, 16 seconds later, without a new approval |
| 21:02:16 | Tracking issue #36 is closed as completed |

The net effect of #772 on `main` ([`f330c87`](https://github.com/oss-slu/material-derailleur/commit/f330c87939fb6a7eb46241f64de338fa954c61ef)) was to change the line endings of `README.md`. GitHub shows 205 lines changed, but **zero once whitespace is ignored**. No SBOM steps and no documentation reached `main`.

No one person caused this. Every step was reasonable on its own: a formatting cleanup, a conflict resolved quickly to unblock a merge, a merge after an approval that had been given a minute earlier. The stale-review rule worked exactly as designed: it noticed that the reviewed content had changed. The merge went ahead anyway.

### 4.4 Why Nobody Noticed for 32 Days

1. **Every status said "done."** The pull request said *merged*, and the issue said *completed*. The author's Sprint 3 plan included "confirm the workflow runs on `main`," and that step never happened.
2. **The workflow was already red.** The last successful run of `build-and-push.yml` on `main` was on **April 25, 2026**. The 149 runs after it all failed. In 142 of them, the failing job was `update-manifests`, which pushes new image tags to a separate repository and needed a token (`K8S_MANIFESTS_TOKEN`) that was missing. The last 7 also failed at the image build itself. The 10 runs from #772's merge onward looked exactly like the 139 before them: a red X. A missing SBOM step does not change the color of a red X.
3. **Nothing checked the outcome.** No step or audit looked for an SBOM artifact or an attestation on `main`. The only evidence that the feature existed was the merged pull request.

Sociologist Diane Vaughan called this pattern *normalization of deviance* in her study of the Challenger launch decision [8]: when a warning signal is always on, it stops carrying information.

### 4.5 How It Ended, and What It Validated

On November 12–13, the organization moved Material Derailleur onto the central SLSA L3 workflow. [#872](https://github.com/oss-slu/material-derailleur/pull/872) adopted it, #874 added Harbor dual-push and Trivy scanning, and #879 removed `build-and-push.yml` as "obsolete." As of November 14, one of the new workflow's four runs on `main` has succeeded ([run 43366753425](https://github.com/oss-slu/material-derailleur/actions/runs/43366753425)). That run's SBOMs make a natural comparison:

| | Sprint 2 baseline (by hand) | Sprint 3 fork test (#772) | Central workflow on `main` (Nov 13) |
|---|---|---|---|
| Server SBOM entries | 3,480 for both app folders, combined | 1,419 | 1,427 |
| Operating system packages | 0 (not visible) | 413 | 413 |
| Client SBOM entries | (included above) | not kept | 3,309, including 413 OS packages |
| Node.js runtime listed | No | Yes | Yes: server **20.20.2**, client **18.20.8** |

Two conclusions follow:

- **The design was right.** A month later, the production workflow (a different author and a different Syft version) produced nearly the same server picture as the fork test: 1,427 vs. 1,419 entries, with exactly the same 413 OS packages. The work in #772 was valid even though it never ran.
- **Image SBOMs find things folder scans cannot.** Both images ship a Node.js release line that is past end-of-life. Node.js 18 reached end-of-life on April 30, 2025, and Node.js 20 on April 30, 2026 [10]. Neither runtime receives security fixes any more. That finding was invisible to the Phase 1 baseline, and it is now a concrete upgrade item for the project.

---

## 5. Case C: DADS, a Green Run That Described Nothing

[dads#355](https://github.com/oss-slu/dads/pull/355) adds SBOM generation and attestation to the DADS backend's existing test workflow.

- **The obvious scan target was empty.** The issue said to scan `Backend/`, but Syft found **zero packages**: `Backend/requirements.txt` is empty, and the real dependencies sit unpinned in the root `requirements.txt`, where Syft cannot resolve versions. A run that "succeeds" with an empty SBOM is worse than a failure, because it looks like coverage. The workflow instead installs the dependencies into a separate folder (`pip install --target`), constrained to the exact versions the tests just used (from `pip freeze`), and scans that folder. The result lists 17 packages, including Flask and psycopg2.
- **Automated policy caught a real weakness quickly.** SonarCloud's quality gate failed the pull request under rule `githubactions:S7637`, because the third-party `anchore/sbom-action` was referenced by a movable tag. The author pinned it to the full commit SHA of v0.24.0 five minutes later.
- **Delays that had nothing to do with the code.** A billing hold on the author's GitHub account stopped fork runs from starting. Later, a GitHub Actions incident (18:12–18:44 UTC) made the PR's runs fail to start. Both were diagnosed from run annotations and GitHub's status page rather than "fixed" in code.

As of November 14, both checks are green, but the pull request has no reviews after five days, and DADS requires **two** approvals. That same two-approval rule is why DADS was the only one of the 22 candidates with no unreviewed changes in the [branch protection audit](../audits/branch_protection_compliance_matrix_fall2026.md). Strong review rules cost latency. A security PR opened on the last day of a sprint, as this one was, pays that cost in full.

---

## 6. Organization-Wide: From 0 to 16 of 22

The table below lists, for each candidate repository, the first commit that added SBOM generation or attestation to a workflow on its default branch. None of the workflows on these default branches predates September 28, 2026.

| First SBOM/attestation commit | Repository | How |
|---|---|---|
| Sep 28 | DigitalBoneBox, mechatronics-vr | Repository-specific workflow |
| Sep 30 | GradEval360 | Repository-specific workflow |
| Oct 5 | shelter_volunteers | Repository-specific; moved to the central workflow on Nov 13 |
| Oct 7 | core_desk | Repository-specific workflow |
| Oct 10 | SpeechTranscription | Release pipeline (macOS and Windows builds) |
| Oct 19 | **repoexplorer** (this study), TheHealthApp | Repository-specific workflow |
| Oct 26 | TULIP, cv_zebrafish | Repository-specific workflow |
| Nov 2 | lrda_mobile | Repository-specific workflow |
| Nov 5 | lrda_website | Repository-specific workflow |
| Nov 9 | pao_surgery_simulator | Repository-specific workflow |
| Nov 13 | geo-enricher, material-derailleur, oss_dev_analytics | Central SLSA L3 workflow |

**Not yet covered:** dads (#355 open), civickit, mithridatium, oss-orb, oss-slu.github.io, and PilotDataSynchronization.

Two patterns stand out:

- **Repository-specific workflows came first and are stable.** Most have passed all or nearly all of their recent runs on the default branch.
- **The central workflow came last, and it consolidates what the repository-specific workflows proved.** It is only two days old: 7 of its first 29 runs across the five adopting repositories have succeeded, which is normal for a new shared pipeline. All five adopters call it at `@main`, which has governance implications. The companion white paper on cybersecurity governance discusses those, and so does recommendation 9 below.

---

## 7. Cross-Case Analysis

### 7.1 What Went Well

1. **One shared baseline.** Every team followed the same org document (SPDX 2.3, Syft, `actions/attest`, `gh attestation verify`), so the outputs are consistent and comparable. Teams also learned from each other's failures: after shelter_volunteers hit the `attest@v2` problem, later workflows used v4.
2. **Read-only contributors were still effective.** Fork testing (pushing to the fork's `main`, forcing the fork to register its workflows) let every path be proven before a maintainer spent time on it.
3. **Pull requests that answered questions in advance.** They linked test runs, explained pre-existing failures, and called out debatable choices. RepoExplorer merged in 4.5 hours without a single question.
4. **Looking at what ships.** In all three repositories the obvious scan target was wrong: package labels in RepoExplorer, a folder instead of the image in Material Derailleur, an empty requirements file in DADS. Checking build output, image digests, and installed environments caught every one.
5. **Adversarial verification.** Each workflow was verified both ways: a real artifact had to pass, and a tampered copy had to fail.
6. **Automated policy enforcement.** SonarCloud turned "pin your actions" from advice into a merge blocker, and the problem was fixed within minutes.
7. **Side findings had value of their own.** Maintainers learned about the TypeScript 7 break, development code shipping in production bundles, a missing deployment token, and an empty scan target.

### 7.2 What Went Wrong

1. **Merged ≠ shipped.** #772 was the most carefully tested change in this study, and it delivered nothing to `main`.
2. **An always-red workflow hid the loss.** 149 consecutive failures had already taught everyone to ignore the signal.
3. **The change was coupled to fragile surroundings.** Editing an existing, already-failing workflow tied the SBOM steps to unrelated jobs and to a repository-wide formatting change.
4. **Late pull requests.** #772 and #355 were opened at the end of their sprints. That put review under merge-day pressure in one case and left too little time for two approvals in the other.
5. **Automation without gates.** Dependabot auto-merge merged a failing build, and the merge itself never triggered the build that would have shown it.
6. **Pinning was applied inconsistently.** RepoExplorer's `sbom.yml` still references `anchore/sbom-action@v0` by tag. That is the same pattern SonarCloud blocked in DADS three weeks later, and it needs a follow-up.
7. **Gaps in the paper trail.** Cross-repository "Closes" lines don't close issues, so #54 had to be closed by hand. The reproduction command in the Sprint 2 baseline README still has a syntax error, which has carried over for four sprints.

### 7.3 Why One Succeeded and the Other Did Not

| Factor | RepoExplorer | Material Derailleur |
|---|---|---|
| Shape of the change | A **new** workflow file | An edit to an **existing**, shared workflow |
| Health of the surrounding CI | Green | Red on every run since April |
| Concurrent changes | None | Repository-wide formatting merged 8 minutes earlier |
| Conflict handling | No conflicts | Resolved in the web editor at merge time |
| Approval at merge | The approved commit was merged | Approval dismissed 16 s before merge |
| Post-merge check | Verified against `oss-slu` a week later | None |
| Timing | Mid-sprint | Last day of the sprint |

The author, the tools, and the baseline were the same in both. The difference was in the change's surroundings and in the habits around it. That is good news, because surroundings and habits are things an organization can change.

---

## 8. Lessons and Recommendations

1. **Define "done" as "observed on `main`."** For any CI change, the tracking issue isn't closed until someone confirms that the first `main` run produced the expected artifact or attestation. Add this as a checklist item in Phase 2-style issue templates.
2. **Add CI capabilities in new files, or by calling a reusable workflow.** A new file fails on its own, rarely conflicts, and is easy to review.
3. **Never tolerate an always-red workflow.** Fix it or delete it within a week. The CI/CD cleanup on November 13 removed the old offenders. As of November 14, none of the 52 workflows across the 22 candidates with at least five recent default-branch runs fails on every run. Keep it that way.
4. **Send conflicted CI pull requests back to their author.** Don't resolve conflicts in workflow files in the web editor at merge time. Require a fresh approval after any branch update, and don't bypass the stale-review rule when it fires.
5. **Choose the scan target from what ships.** Scan build output, image digests, or installed environments, not labels or manifests. Treat a zero-package SBOM as a failure, and spot-check that known dependencies appear.
6. **Hold bots to the same gates as people.** Require CI to pass before Dependabot auto-merge can complete.
7. **Pin third-party actions to full commit SHAs from the start**, with a version comment, and let Dependabot update the pins. Start with RepoExplorer's `anchore/sbom-action@v0`.
8. **Verify independently and adversarially.** Use `gh attestation verify` with `--owner oss-slu`. For artifacts built by the central workflow, also pass `--signer-workflow` so that only the approved reusable workflow is accepted [4]. Keep the tampered-copy test in every demo.
9. **Centralize once the pattern is proven, and pin the paved road.** The 13 repository-specific workflows taught the organization what the central one needed. Consumers should now reference it by tag or SHA instead of `@main`, so that one change to the central repository cannot alter every project's build without review.
10. **Land security pull requests early in the sprint.** Do this especially in repositories that require two approvals, where review latency is the price of a control that works.

---

## 9. Impact

- **Organization coverage went from 0 to 16 of 22 candidate repositories** in about seven weeks, built on a shared baseline and the Phase 1 SBOMs.
- **RepoExplorer:** every `main` build since October 19 has a verifiable, attested SBOM (23 so far), and 48 pull request runs have shown reviewers the dependency picture of a change before merge, with no maintenance cost.
- **Material Derailleur:** the image-level design was validated against production output, and image SBOMs now exist through the central workflow. They exposed two end-of-life Node.js runtimes that the baseline could not see.
- **Findings handed to maintainers:**

  | Finding | Status |
  |---|---|
  | The TypeScript 7 build break | Fixed |
  | Bundled development dependencies | Acknowledged, still open |
  | The missing deployment token | Workflow removed |
  | The empty DADS scan target | Fixed in the open PR |

- **Governance:** the #772 incident is a concrete, documented example of risk R-09 ("unreviewed or malicious changes reach a project's main branch") in this repository's [risk register](../risk_assessment.md). It supports the branch protection baseline, the required-CI recommendation, and the weekly drift audit.

---

## 10. Future Measurements

| Measure | Today (Nov 14) | Suggested target (end of Spring 2027) |
|---|---|---|
| Candidates generating SBOMs or attestations in CI | 16 / 22 | 21 / 22 (the website may be exempt) |
| Central-workflow runs succeeding | 7 of first 29 | ≥ 95% of the last 20 runs per repository |
| Consumers pinning the central workflow by tag or SHA | 0 / 5 | All |
| CI pull requests with a recorded post-merge check | Not tracked | 100% |
| End-of-life runtimes found in SBOMs and still unfixed | 2 (Material Derailleur) | 0 |
| Third-party actions referenced by tag in SBOM workflows | ≥ 1 (RepoExplorer) | 0 |

A natural next step is to add an "SBOM and attestation present on `main`" check to the weekly audit workflow that already monitors branch protection. That would make lesson 1 automatic.

---

## 11. Limitations

- **Insider perspective.** The author built three of the cases. The analysis relies on recorded evidence (timestamps, diffs, run histories), but the choice and framing of cases are still the author's.
- **Scope.** The adoption figures cover the 22 candidate repositories listed in [`scripts/branch_protection_candidates.txt`](../../scripts/branch_protection_candidates.txt), not every OSS-SLU repository.
- **Adoption dates are approximate.** They are the commit dates of the first SBOM-related change to a workflow file that is still on the default branch, so they may differ from merge dates by hours or days. Workflows that were added and later deleted are only visible where history was checked by hand (shelter_volunteers).
- **SBOM sizes depend on tooling.** Package counts vary with the Syft version (1.19.0 in the central workflow, 1.42.3 in RepoExplorer's latest run) and with cataloger settings, so they are compared within a repository, not across repositories.
- **No vulnerability analysis.** This study covers whether SBOMs exist and can be trusted, not what they reveal about known CVEs. Trivy scanning was added to the central workflow on November 13 and is a natural follow-on study.

---

## 12. Reflection: Magis

*Magis* asks for "the more": not more volume, but the fuller good a piece of work can do. Writing this case study, the most uncomfortable finding was my own. When #772 merged, I treated the issue as finished. My Sprint 3 plan said I would confirm that the workflow ran on `main`, and I never did. The SBOM steps I had tested so carefully on my fork never ran for the project they were built for. The tooling wasn't what failed. My definition of "done" was.

RepoExplorer is the counterexample, and the difference is small but decisive: a week after merging, I verified the real SBOMs against the organization, and that is why I can now say with evidence that 23 builds are covered. Across five sprints I also kept relearning the same lesson from different angles. In Sprint 1 I learned that overstating a control is worse than leaving it out. Material Derailleur taught me that a green status isn't proof, DADS that a green run isn't proof, and RepoExplorer that labels aren't proof. For me, "the more" in security work means going back to check what actually happened. For the team, I hope the lasting contribution is less the YAML than the habits it exposed: verify on `main`, keep CI green, and start early enough that the people who review our work have time to do it well.

---

## References

1. OSS-SLU. *Supply-Chain Security Baseline: SBOM and Build Provenance.* https://github.com/oss-slu/oss_cicd_automation/blob/main/Docs/Supply_Chain_Security_Baseline.md
2. NTIA. *The Minimum Elements for a Software Bill of Materials (SBOM),* July 2021. https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom
3. SLSA. *Security Levels, v1.0.* https://slsa.dev/spec/v1.0/levels
4. GitHub Docs. *Using artifact attestations and reusable workflows to achieve SLSA v1 Build Level 3.* https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3
5. GitHub Docs. *Triggering a workflow* (events triggered by `GITHUB_TOKEN` do not create new runs). https://docs.github.com/en/actions/using-workflows/triggering-a-workflow
6. GitHub Docs. *Approving workflow runs from public forks.* https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-workflow-runs/approving-workflow-runs-from-public-forks
7. SPDX. *SPDX Specification 2.3.* https://spdx.github.io/spdx-spec/v2.3/
8. Vaughan, D. *The Challenger Launch Decision: Risky Technology, Culture, and Deviance at NASA.* University of Chicago Press, 1996.
9. Anchore. *Syft.* https://github.com/anchore/syft
10. Node.js. *Node.js Releases* (end-of-life dates). https://nodejs.org/en/about/previous-releases
11. OSS-SLU Security. *Branch Protection Compliance Matrix, Fall 2026.* [`docs/audits/branch_protection_compliance_matrix_fall2026.md`](../audits/branch_protection_compliance_matrix_fall2026.md)

## Appendix: Reproducing the Key Numbers

```bash
# RepoExplorer: every run of the SBOM workflow, grouped by event and result
gh run list -R oss-slu/repoexplorer --workflow sbom.yml --limit 200 \
  --json event,conclusion --jq 'group_by(.event+" "+(.conclusion//"none")) | map({k:.[0].event+" "+(.[0].conclusion//"none"), n:length})'

# RepoExplorer: commits to the workflow since it merged (expect 1, the original)
gh api 'repos/oss-slu/repoexplorer/commits?path=.github/workflows/sbom.yml' --jq length

# Material Derailleur: what #772 changed on main once whitespace is ignored (expect no output)
git -C material-derailleur diff -w --ignore-blank-lines f330c87^1 f330c87

# Material Derailleur: last successful build-and-push run on main, and failures after it
gh run list -R oss-slu/material-derailleur --workflow build-and-push.yml --branch main --limit 500 \
  --json conclusion,createdAt \
  --jq '([.[]|select(.conclusion=="success")|.createdAt]|max) as $s | {last_success:$s, failures_after:([.[]|select(.createdAt>$s)]|length)}'

# Material Derailleur: package counts in the central workflow's SBOMs
gh run download 43366753425 -R oss-slu/material-derailleur -n material-derailleur-server-sbom -D server
jq '.packages | length' server/sbom.spdx.json
```

---

Disclosure: partially drafted with AI assistance.

*Last updated 11/14/26 by Kysen Krishnaswamy*
