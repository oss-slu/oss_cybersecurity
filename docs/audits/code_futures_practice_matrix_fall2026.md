# Code Futures Practice Matrix — Fall 2026

**Governing Issue:** [oss-slu/oss_cybersecurity#69](https://github.com/oss-slu/oss_cybersecurity/issues/69)  
**Tool:** [oss-slu/code-futures](https://github.com/oss-slu/code-futures) v1.0.0, schema `code-futures/v1`  
**Baseline snapshot:** [`code-futures/2026-11-02-snapshot.json`](code-futures/2026-11-02-snapshot.json)  
**Follow-up snapshot:** [`code-futures/2026-11-23-snapshot.json`](code-futures/2026-11-23-snapshot.json)  
**Procedure for future sweeps:** [`code-futures/README.md`](code-futures/README.md)

## Contents

1. [Summary](#1-summary)
2. [How to read the counts](#2-how-to-read-the-counts)
3. [Matrix](#3-matrix)
4. [Gaps across the 22 repositories](#4-gaps-across-the-22-repositories)
5. [Top 5 practice fixes for Iteration 2/3](#5-top-5-practice-fixes-for-iteration-23)
6. [Drift since the baseline](#6-drift-since-the-baseline)
7. [Method and limits](#7-method-and-limits)

## 1. Summary

Code Futures asks the same 34 questions (probes) of every repository and answers each with one of four outcomes: `enforced`, `present`, `absent` or `unreadable`. This document records those outcomes for the 22 candidate repositories from the Phase 1 and Phase 2 Automated SBOM Generation work.

- The baseline is the organization-wide sweep of 2026-11-02. It covers 20 of the 22 candidates. `civickit` and `oss-slu.github.io` were not in it, so their rows come from the 2026-11-23 run and are marked with that date.
- 16 of 22 repositories ship at least one dependency with a known advisory. It is the tool's first suggestion for 16 of them.
- Testing beyond unit tests is rare: integration tests are absent in 21 repositories, end-to-end tests in 20, coverage in continuous integration (CI) in 20.
- Several gaps are one file or one workflow step away from closed: a linter that is configured but not run in continuous integration (CI) in 6 repositories, a formatter in 6, unit tests in 4.
- Between 2026-11-02 and 2026-11-23, 3 practices improved, all in `lrda_website`.

## 2. How to read the counts

The counts in the matrix are an index into each repository's report. They are not a score, and the rows are not a ranking.

- **The four outcomes are a vocabulary, not a scale.** The Code Futures documentation says there is no arithmetic to do on them. A repository with more `enforced` findings is not "better" than another; the practices a project needs depend on what it is for.
- **`unreadable` is the tool's gap, not the repository's.** It means the check could not be completed. It is never counted against a repository.
- **`absent` is sometimes the good outcome.** For the 8 Structure probes and for known vulnerabilities, `absent` means the analysis ran and found nothing to report.
- **17 of the 34 probes cannot reach `enforced`.** Nothing in continuous integration (CI) "runs" a README or a hotspot analysis, so `present` is the top outcome for those.
- **Findings can exceed 34.** Linting and formatting are answered once per language, so a repository with two languages has 36 findings.

## 3. Matrix

"Where to start" and "Next action" are taken from each repository's rendered Code Futures report: the report's primary suggestion and the first item in its follow-up list.

| Repository | Enforced | Present | Absent | Unreadable | Findings | Top hotspot file | Where to start | Next action |
|---|---|---|---|---|---|---|---|---|
| `civickit` (2026-11-23) | 4 | 12 | 6 | 12 | 34 | `mobile/App.tsx` | The licence | Fill in the missing README sections |
| `core_desk` | 7 | 13 | 11 | 3 | 34 | `app/src/components/jobitem/JobItem.jsx` | The dependencies with known advisories | Add an identifiable licence |
| `cv_zebrafish` | 6 | 17 | 9 | 2 | 34 | `src/ui/main_panels/graph_viewer_widget.py` | The licence | Fill in the missing README sections |
| `dads` | 10 | 14 | 10 | 2 | 36 | `Frontend/src/pages/ExploreSystems.js` | The dependencies with known advisories | Add an identifiable licence |
| `DigitalBoneBox` | 7 | 15 | 10 | 2 | 34 | `templates/style.css` | The dependencies with known advisories | Add an identifiable licence |
| `geo-enricher` | 5 | 13 | 9 | 7 | 34 | `app/src/cmp/DatasetGeoJoiner.tsx` | The dependencies with known advisories | Add an identifiable licence |
| `GradEval360` | 7 | 15 | 10 | 2 | 34 | `server/src/routes/appointments.ts` | The dependencies with known advisories | Add an identifiable licence |
| `lrda_mobile` | 7 | 13 | 12 | 2 | 34 | `lib/screens/HomeScreen.tsx` | The dependencies with known advisories | Add an identifiable licence |
| `lrda_website` | 6 | 15 | 11 | 2 | 34 | `package.json` | The licence | Fill in the missing README sections |
| `material-derailleur` | 7 | 16 | 8 | 3 | 34 | `client-app/src/Components/DonatedItemsList.tsx` | The dependencies with known advisories | Add an identifiable licence |
| `mechatronics-vr` | 6 | 15 | 11 | 2 | 34 | `Content/VRTemplate/Maps/VRTemplateMap.umap` | The licence | Run `clang-tidy` in CI |
| `mithridatium` | 7 | 17 | 8 | 2 | 34 | `mithridatium/cli.py` | The dependencies with known advisories | Add an identifiable licence |
| `oss_dev_analytics` | 7 | 9 | 16 | 3 | 35 | `Frontend/src/features/home/routes/Home.jsx` | The dependencies with known advisories | Add an identifiable licence |
| `oss-orb` | 5 | 14 | 13 | 2 | 34 | `api/src/utils/parquet.ts` | The dependencies with known advisories | Add an identifiable licence |
| `oss-slu.github.io` (2026-11-23) | 1 | 8 | 13 | 12 | 34 | `sidebars.js` | Completing the README | Run `the tool` in CI |
| `pao_surgery_simulator` | 7 | 16 | 11 | 2 | 36 | `backend/app.py` | The dependencies with known advisories | Add an identifiable licence |
| `PilotDataSynchronization` | 7 | 18 | 8 | 2 | 35 | `relay/src/state.rs` | The dependencies with known advisories | Fill in the missing README sections |
| `repoexplorer` | 8 | 13 | 11 | 2 | 34 | `app/src/cmp/App.tsx` | The dependencies with known advisories | Add an identifiable licence |
| `SpeechTranscription` | 5 | 11 | 16 | 2 | 34 | `GUI.py` | The licence | Fill in the missing README sections |
| `shelter_volunteers` | 9 | 16 | 8 | 2 | 35 | `server/tests/rest/service_shift/test_service_shift.py` | The dependencies with known advisories | Add an identifiable licence |
| `TheHealthApp` | 7 | 11 | 14 | 2 | 34 | `backend/src/main.py` | The dependencies with known advisories | Add an identifiable licence |
| `TULIP` | 6 | 14 | 12 | 2 | 34 | `app/src/components/intake-form/intake-form.jsx` | The dependencies with known advisories | Add an identifiable licence |

## 4. Gaps across the 22 repositories

Number of repositories where each practice is `absent`. Structure probes are left out because `absent` is the good outcome there.

| Practice | Probe | Absent in |
|---|---|---|
| Mutation testing | `test.mutation` | 22 |
| Integration tests | `test.integration` | 21 |
| End-to-end tests | `test.e2e` | 20 |
| Coverage in continuous integration (CI) | `test.coverage` | 20 |
| Security hotspots reviewed | `quality.hotspots_reviewed` | 19 |
| Security policy | `practice.security_policy` | 16 |
| Formatter | `format` | 13 |
| Code of conduct | `practice.code_of_conduct` | 12 |
| Pull request template | `practice.pull_request_template` | 11 |
| Minimal workflow token permissions | `security.token_permissions` | 9 |
| Dependency update tool | `deps.update_tool` | 8 |
| Static application security testing (SAST) | `security.sast` | 7 |
| Contributing guide | `practice.contributing` | 6 |
| Issue template | `practice.issue_template` | 6 |
| Linter | `lint` | 5 |
| Unit tests | `test.unit` | 5 |
| README | `practice.readme` | 2 |
| License | `practice.license` | 2 |

Practices that are `present` but not `enforced`, meaning the tool or suite exists and no workflow runs it:

| Practice | Probe | Present, not enforced, in |
|---|---|---|
| Review in practice | `review.practiced` | 9 |
| Linter | `lint` | 6 |
| Formatter | `format` | 6 |
| Unit tests | `test.unit` | 4 |

Dependencies with known advisories (`deps.known_vulnerabilities` is `present`): 16 repositories.

## 5. Top 5 practice fixes for Iteration 2/3

Chosen by two things together: how many repositories the fix reaches, and how small the change is in each one.

1. **Update dependencies with known advisories (16 repositories).** Each one is a published vulnerability in shipped code, and the fix is usually a version bump.
2. **Add a dependency update tool (8 repositories).** One Dependabot or Renovate configuration file per repository. It keeps fix 1 from coming back.
3. **Run the linter, formatter and unit tests that already exist (6, 6 and 4 repositories).** The configuration is already in the repository. The fix is one workflow step.
4. **Declare minimal workflow token permissions (9 repositories).** A `permissions:` block in each workflow file.
5. **Add a security policy (up to 16 repositories).** One `SECURITY.md` file. See the note in section 7: two of the 16 already have one in `docs/`.

## 6. Drift since the baseline

Compared with `scripts/diff-code-futures.py`, 2026-11-02 to 2026-11-23, across the 20 repositories in both snapshots.

| Repository | Probe | Was | Now | Reading |
|---|---|---|---|---|
| `lrda_website` | `practice.issue_template` | absent | present | Improved |
| `lrda_website` | `practice.pull_request_template` | absent | present | Improved |
| `lrda_website` | `test.coverage` | absent | enforced | Improved |
| `dads` | `structure.cohesion` | absent | present | Regressed |
| `TheHealthApp` | `structure.change_coupling` | absent | present | Regressed |
| `TheHealthApp` | `structure.cohesion` | absent | present | Regressed |

The three Structure changes mean file pairs that change together now cross the tool's reporting threshold in those repositories. The top hotspot file or hotspot list changed in 12 repositories.

214 findings moved to `unreadable` and 20 moved from it. These are not changes in the repositories. The two snapshots were collected with different access, as section 7 explains.

## 7. Method and limits

- **Baseline (2026-11-02).** The organization-wide sweep, 29 repositories, with OpenSSF Scorecard and SonarQube Cloud results. `review.required` and `ci.present` are `unreadable` in every repository in it.
- **Follow-up (2026-11-23).** Code Futures v1.0.0 run on full clones of the 22 candidates without organization credentials. Structure, Open Source Baseline, Linting and Formatting, Testing and `ci.present` were collected. The 12 probes that need OpenSSF Scorecard, SonarQube Cloud or the branch-protection data are `unreadable` in every repository.
- **Repository names.** Four names in #69 differ from the current repository names: CoreDesk is `core_desk`, MechatronicsVR is `mechatronics-vr`, enroll-dash is `geo-enricher` (renamed), and SALTIFY is `SpeechTranscription`. The list in `scripts/branch_protection_candidates.txt` is used.
- **Security policy.** Checked by hand against the repositories. Of the 16 reported `absent`, 12 have no security policy file. `civickit` and `oss_dev_analytics` have `docs/SECURITY.md`, which the tool did not detect. `material-derailleur` has `Security_Policy.md` and `GradEval360` has a `docs/security` folder, neither under the standard name.
- **Not checked by hand.** Every other finding is the tool's output as collected.
