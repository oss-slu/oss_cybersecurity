# Branch Protection Compliance Matrix — Fall 2026

**Status:** Audit, Fall 2026 semester  
**Governing Issue:** [oss-slu/oss_cybersecurity#66](https://github.com/oss-slu/oss_cybersecurity/issues/66)  
**Related:** Risk R-09 in the [Security Risk Register](../risk_assessment.md); "Branch protection / required PR reviews" in the [Security Controls Inventory](../security_controls_inventory.md)  
**Baseline and how to fix gaps:** [Branch Protection Guide](../standards/branch-protection-guide.md)  
**Raw results:** [`branch_protection_audit_fall2026.json`](branch_protection_audit_fall2026.json)

---

## 1. Summary

The audit ran on 2026-11-13 against all 22 candidate repositories. Practice figures cover 2026-08-01 to 2026-11-13.

- **17 of 22 repositories meet the baseline on paper:** a pull request with at least 1 approving review, force pushes blocked, and deletion blocked. Five do not:
  - `cv_zebrafish` and `oss-orb` have no protection on `main`. cv_zebrafish already has a complete protection ruleset, but it has been **disabled since 2025-10-31**. Switching it to Active fixes the repository.
  - `TULIP` has a ruleset that requires reviews but does not block force pushes or deletion.
  - `geo-enricher` (listed as enroll-dash) and `oss_dev_analytics` require a pull request but **0 approvals**.
- **In practice, unreviewed changes reached `main` in 21 of 22 repositories.** 179 of 738 merged PRs (24%) had no approval from anyone other than the author. People also pushed directly to `main` 200 times, across 16 repositories. `dads` is the only repository with neither.
- **72 of those changes went around a ruleset that was already in force**, across 7 repositories. Rulesets show when they were last changed, so these are confirmed bypasses, not changes made before the rule existed. Classic protection shows no date, so the true number is higher.
- **The main cause is that admins are not bound by the rules.** The rules stop students, but not the tech leads and admins who merge most PRs. Only `dads` is confirmed to bind admins ("Do not allow bypassing the above settings"), and it is the one repository with no unreviewed changes. Seven classic rules are confirmed not to bind admins. civickit has a ruleset named "Allow admin to merge own PRs".
- **No repository requires CI to pass before merging (0 of 22)**, although every one of them has at least one active workflow. This was checked in both classic protection and rulesets.
- **CODEOWNERS:** 12 of 22 repositories have a CODEOWNERS file, and 9 enforce code owner review. Two CODEOWNERS files have errors. civickit and shelter_volunteers require code owner review but have no CODEOWNERS file, so the requirement does nothing.

Four names in #66 did not match a repository. They were audited under their current names: CoreDesk is `core_desk`, MechatronicsVR is `mechatronics-vr`, enroll-dash is `geo-enricher` (renamed; GitHub redirects the old name), and SALTIFY is `SpeechTranscription`.

## 2. Baseline

| Setting | Level |
|---|---|
| Changes reach the default branch through a pull request with at least 1 approving review | **Required (baseline)** |
| Force pushes blocked | **Required (baseline)** |
| Deletion of the default branch blocked | **Required (baseline)** |
| Stale approvals dismissed when new commits are pushed | Recommended |
| Review from code owners required, where a CODEOWNERS file exists | Recommended |
| CI status checks required before merging | Recommended |
| Admins bound by the rules (no bypass, or pull-request-only bypass for one named team) | Recommended |

The baseline is published as an importable ruleset: [`docs/standards/branch-protection-baseline.ruleset.json`](../standards/branch-protection-baseline.ruleset.json).

## 3. Methodology

### 3.1 Data sources

Everything was collected with a read-only account, with no admin access on any of the 22 repositories. The command suggested in #66 (`gh api repos/<repo>/branches/main/protection`) returns 404 without admin access, so the audit uses endpoints that read access can see:

| Signal | Source | Visible with read access? |
|---|---|---|
| Classic protection: review count, code owner review, force pushes, deletion | GraphQL `Ref.refUpdateRule` | Yes |
| Classic protection: required status checks, and whether admins are bound | REST `GET /repos/{owner}/{repo}/branches/{branch}` (`protection.required_status_checks`) | Checks: yes. Admins: only when the rule also has status checks turned on |
| Classic protection: dismiss stale approvals | REST `GET …/branches/{branch}/protection` | No (admin only) |
| Rulesets: every rule and parameter that applies to the branch | REST `GET /repos/{owner}/{repo}/rules/branches/{branch}` | Yes |
| Rulesets: name, enforcement, last change, and rulesets that are switched off | REST `GET /repos/{owner}/{repo}/rulesets[/{id}]` | Yes (bypass lists are admin only) |
| CODEOWNERS present and valid | REST `GET /repos/{owner}/{repo}/codeowners/errors` | Yes |
| Direct pushes, force pushes, and PR merges on the branch | REST `GET /repos/{owner}/{repo}/activity` | Yes |
| Approvals on merged PRs | GraphQL search over merged PRs | Yes |

GitHub enforces classic protection and rulesets together, so the matrix reports the effective (most restrictive) value of the two.

### 3.2 Validation against admin ground truth

Read-only results were checked on a sandbox branch in a repository where the auditor is an admin (`kysenkrish/repoexplorer`; the branch has since been deleted). Three classic configurations were applied through the admin API. Each was audited twice: once with admin endpoints and once with `--read-only`.

| Configuration | Admin view | Read-only view | Result |
|---|---|---|---|
| A: 1 review, dismiss stale, admins bound, force pushes and deletion blocked | PASS | PASS; dismiss stale shown as Unknown | Match |
| B: PR with 0 approvals, admins not bound, required check `build`, force pushes allowed | FAIL | FAIL; PR requirement shown as Unknown | Match |
| C: no PR requirement, admins bound, deletion allowed | FAIL | FAIL; admins shown as Unknown | Match |

Every value the read-only view reported matched the admin view. Values it cannot see are reported as Unknown, never guessed. The validation also caught three API behaviors that would otherwise have produced wrong results:

1. `refUpdateRule.requiredStatusCheckContexts` is always empty for non-admins. Required checks are therefore read from the branch summary.
2. `refUpdateRule.requiredApprovingReviewCount` is `0` both for "PR required, 0 approvals" and for "no PR required". The matrix shows `0` without claiming which of the two applies; both fail the baseline.
3. `refUpdateRule` describes the rule as it applies to the viewer, so an admin who is not bound by the rule sees `0`. Non-admin viewers are always bound, so they see the configured rule. This agrees with `lrda_mobile`, which shows its configured 2 reviews to a read-only account even though its admins are not bound.

The baseline ruleset and enforcement script were tested on the same sandbox. The tests covered creating the ruleset, re-running it with no change, updating it, and adding it on top of a stricter classic rule (the classic rule's 2 required reviews and required check were kept). Live `git push` attempts were also made: a direct push, a force push, and a branch deletion were all rejected with `GH013: Repository rule violations`. Running with `--remove` rolled the change back.

### 3.3 Practice measures

- **Merged without independent approval:** a merged PR with no `APPROVED` review, submitted before the merge, from someone other than the author.
- **Direct pushes (people):** `push` events on the default branch in the repository activity log. Merges through the pull request page are logged separately as `pr_merge`, and pushes by bots are counted separately. All 12 direct pushes to repoexplorer since 2026-09-12 were checked by hand: each is a single-parent commit with no associated pull request.
- **Confirmed ruleset bypasses:** direct pushes made after a pull request ruleset was last changed, plus unapproved merges made after a ruleset requiring at least 1 approval was last changed. Before that date the rule may not have existed, so earlier changes are not counted.

The published report contains only counts, dates, and PR numbers. It does not name the people who pushed or merged. `--include-actors` adds GitHub logins to local output when a project lead needs to follow up.

### 3.4 Limitations

- Two settings need admin access and show as Unknown: stale-approval dismissal on classic rules, and ruleset bypass lists.
- Classic protection has no visible creation date, so unreviewed changes on classic-protected branches may predate the rule.
- A PR whose approval was later dismissed as stale counts as unapproved. GitHub treats it the same way when the setting is on.
- The results are a snapshot taken on 2026-11-13.

### 3.5 Reproduce

```bash
gh auth status                      # any account that can read the repositories
python3 scripts/audit_branch_protection.py --since 2026-08-01 \
  --json docs/audits/branch_protection_audit_fall2026.json \
  --markdown docs/audits/branch_protection_compliance_matrix_fall2026.md
python3 -m unittest discover -s tests -v
```

## 4. Results

The tables in this section are generated by `scripts/audit_branch_protection.py`. Re-run it rather than editing them by hand.

<!-- BEGIN GENERATED: scripts/audit_branch_protection.py -->
_Generated 2026-11-13T22:51:32Z by `scripts/audit_branch_protection.py`. Practice window: 2026-08-01 to 2026-11-13. Token access: admin on 0 of 22 repositories, read-only on the rest._

### Summary

| Measure | Result |
|---|---|
| Candidate repositories | 22 (22 found, 0 not found) |
| Active (pushed within 180 days, not archived) | 22 |
| **Meet the baseline** (≥1 review, force pushes blocked, deletion blocked) | **17 of 22** (17 of 22 active) |
| Require at least one approving review | 18 of 22 |
| Block force pushes | 19 of 22 |
| Block branch deletion | 19 of 22 |
| Require CI status checks | 0 of 22 |
| Dismiss stale approvals | 5 confirmed, 12 not visible without admin |
| CODEOWNERS file present / code owner review enforced | 12 / 9 |
| Admins bound by the rules (confirmed yes / confirmed no) | 1 / 5 (the rest are not visible without admin) |
| Repositories where unreviewed changes reached the default branch in the window | 21 of 22 |
| PRs merged in window / merged without an independent approval | 738 / 179 |
| Direct pushes by people / force pushes to default branches in window | 200 / 3 |
| Confirmed bypasses of a ruleset already in force² | 72 across 7 repositories |

### Compliance matrix

| # | Repository | Default branch | Protection | Required reviews | Dismiss stale approvals | CODEOWNERS review required | Force pushes | Deletions | Required CI status checks | Admins bound by rules | Baseline | Remediation status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | [civickit](https://github.com/oss-slu/civickit) | `main` | Classic + ruleset | 1 | Yes | Yes, but no CODEOWNERS file | Blocked | Blocked | None | Unknown¹ | ✅ Pass | Compliant — unreviewed changes observed |
| 2 | [core_desk](https://github.com/oss-slu/core_desk) | `main` | Classic | 1 | Unknown¹ | No (no CODEOWNERS file) | Blocked | Blocked | None | Unknown¹ | ✅ Pass | Compliant — unreviewed changes observed |
| 3 | [cv_zebrafish](https://github.com/oss-slu/cv_zebrafish) | `main` | None | None | n/a | No (no CODEOWNERS file) | Allowed | Allowed | None | n/a | ❌ Fail | Open — needs repo admin |
| 4 | [dads](https://github.com/oss-slu/dads) | `main` | Classic | 1 | Unknown¹ | No (no CODEOWNERS file) | Blocked | Blocked | None | Yes | ✅ Pass | Compliant |
| 5 | [DigitalBoneBox](https://github.com/oss-slu/DigitalBoneBox) | `main` | Classic | 1 | Unknown¹ | Yes | Blocked | Blocked | None | Unknown¹ | ✅ Pass | Compliant — unreviewed changes observed |
| 6 | [geo-enricher](https://github.com/oss-slu/geo-enricher) | `main` | Ruleset | 0 | No | Yes | Blocked | Blocked | None | Unknown¹ | ❌ Fail | Open — needs repo admin |
| 7 | [GradEval360](https://github.com/oss-slu/GradEval360) | `main` | Ruleset | 1 | Yes | No (no CODEOWNERS file) | Blocked | Blocked | None | Unknown¹ | ✅ Pass | Compliant — unreviewed changes observed |
| 8 | [lrda_mobile](https://github.com/oss-slu/lrda_mobile) | `main` | Classic | 2 | Unknown¹ | Yes | Blocked | Blocked | None | No | ✅ Pass | Compliant — unreviewed changes observed |
| 9 | [lrda_website](https://github.com/oss-slu/lrda_website) | `main` | Classic | 1 | Unknown¹ | No | Blocked | Blocked | None | No | ✅ Pass | Compliant — unreviewed changes observed |
| 10 | [material-derailleur](https://github.com/oss-slu/material-derailleur) | `main` | Classic | 1 | Unknown¹ | Yes | Blocked | Blocked | None | Unknown¹ | ✅ Pass | Compliant — unreviewed changes observed |
| 11 | [mechatronics-vr](https://github.com/oss-slu/mechatronics-vr) | `main` | Ruleset | 1 | Yes | Yes | Blocked | Blocked | None | Unknown¹ | ✅ Pass | Compliant — unreviewed changes observed |
| 12 | [mithridatium](https://github.com/oss-slu/mithridatium) | `main` | Classic | 1 | Unknown¹ | No (no CODEOWNERS file) | Blocked | Blocked | None | Unknown¹ | ✅ Pass | Compliant — unreviewed changes observed |
| 13 | [oss_dev_analytics](https://github.com/oss-slu/oss_dev_analytics) | `main` | Classic + ruleset | 0 | Yes | Yes | Blocked | Blocked | None | Unknown¹ | ❌ Fail | Open — needs repo admin |
| 14 | [oss-orb](https://github.com/oss-slu/oss-orb) | `main` | None | None | n/a | No (no CODEOWNERS file) | Allowed | Allowed | None | n/a | ❌ Fail | Open — needs repo admin |
| 15 | [oss-slu.github.io](https://github.com/oss-slu/oss-slu.github.io) | `main` | Classic | 1 | Unknown¹ | No (no CODEOWNERS file) | Blocked | Blocked | None | Unknown¹ | ✅ Pass | Compliant — unreviewed changes observed |
| 16 | [pao_surgery_simulator](https://github.com/oss-slu/pao_surgery_simulator) | `main` | Classic | 1 | Unknown¹ | No | Blocked | Blocked | None | No | ✅ Pass | Compliant — unreviewed changes observed |
| 17 | [PilotDataSynchronization](https://github.com/oss-slu/PilotDataSynchronization) | `main` | Classic | 1 | Unknown¹ | Yes | Blocked | Blocked | None | No | ✅ Pass | Compliant — unreviewed changes observed |
| 18 | [repoexplorer](https://github.com/oss-slu/repoexplorer) | `main` | Ruleset | 1 | No | Yes | Blocked | Blocked | None | Unknown¹ | ✅ Pass | Compliant — unreviewed changes observed |
| 19 | [SpeechTranscription](https://github.com/oss-slu/SpeechTranscription) | `main` | Classic | 1 | Unknown¹ | No | Blocked | Blocked | None | Unknown¹ | ✅ Pass | Compliant — unreviewed changes observed |
| 20 | [shelter_volunteers](https://github.com/oss-slu/shelter_volunteers) | `main` | Classic | 1 | Unknown¹ | Yes, but no CODEOWNERS file | Blocked | Blocked | None | No | ✅ Pass | Compliant — unreviewed changes observed |
| 21 | [TheHealthApp](https://github.com/oss-slu/TheHealthApp) | `main` | Ruleset | 1 | No | Yes | Blocked | Blocked | None | Unknown¹ | ✅ Pass | Compliant — unreviewed changes observed |
| 22 | [TULIP](https://github.com/oss-slu/TULIP) | `main` | Ruleset | 1 | Yes | No (no CODEOWNERS file) | Allowed | Allowed | None | Unknown¹ | ❌ Fail | Open — needs repo admin |

¹ Not visible without admin access. Classic protection hides “dismiss stale approvals” from read-only accounts. “Include administrators” is visible only when the classic rule also requires status checks, and ruleset bypass lists are admin-only. A repository admin can confirm these settings in Settings → Branches / Rules, or re-run this script with an admin token. A required review count of 0 means the rule asks for no approvals, so the baseline is not met.

### Observed practice since 2026-08-01

Configuration only shows what is supposed to happen. These counts come from the repository activity log and merged pull requests, and show what actually reached each default branch. A non-zero count on a protected branch means someone with admin or bypass rights went around the rule, or the rule was added later in the window.

| Repository | PRs merged | Merged without independent approval | Direct pushes (people) | Direct pushes (bots) | Force pushes | Confirmed ruleset bypasses² |
|---|---|---|---|---|---|---|
| civickit | 15 | 14 | 0 | 0 | 0 | 0 push(es) after 2026-07-24; 14 merge(s) after 2026-07-24 |
| core_desk | 32 | 12 | 6 | 0 | 0 | — |
| cv_zebrafish | 23 | 7 | 0 | 0 | 0 | — |
| dads | 16 | 0 | 0 | 0 | 0 | — |
| DigitalBoneBox | 34 | 8 | 5 | 0 | 0 | — |
| geo-enricher | 31 | 15 | 24 | 2 | 1 | 10 push(es) after 2026-09-13 |
| GradEval360 | 13 | 2 | 2 | 0 | 0 | 2 push(es) after 2026-04-24; 2 merge(s) after 2026-04-24 |
| lrda_mobile | 11 | 4 | 17 | 0 | 0 | — |
| lrda_website | 31 | 4 | 9 | 0 | 0 | — |
| material-derailleur | 203 | 14 | 4 | 0 | 0 | — |
| mechatronics-vr | 26 | 1 | 18 | 0 | 0 | 8 push(es) after 2026-09-13; 1 merge(s) after 2026-09-13 |
| mithridatium | 39 | 9 | 7 | 0 | 0 | — |
| oss_dev_analytics | 7 | 7 | 0 | 0 | 0 | 0 push(es) after 2026-11-13 |
| oss-orb | 2 | 2 | 16 | 5 | 0 | — |
| oss-slu.github.io | 33 | 29 | 0 | 0 | 0 | — |
| pao_surgery_simulator | 43 | 1 | 28 | 0 | 0 | — |
| PilotDataSynchronization | 35 | 1 | 0 | 0 | 0 | — |
| repoexplorer | 48 | 10 | 25 | 6 | 0 | 11 push(es) after 2026-09-12; 6 merge(s) after 2026-09-12 |
| SpeechTranscription | 17 | 9 | 3 | 0 | 0 | — |
| shelter_volunteers | 29 | 13 | 9 | 0 | 0 | — |
| TheHealthApp | 36 | 11 | 2 | 0 | 2 | 0 push(es) after 2026-10-06; 7 merge(s) after 2026-10-06 |
| TULIP | 14 | 6 | 25 | 0 | 0 | 8 push(es) after 2026-08-25; 3 merge(s) after 2026-08-25 |

² Only countable for repositories whose review rule is a ruleset, because GitHub shows when a ruleset was last changed. A direct push, or a merge with no independent approval, after that date went around a rule already in force. Admins and the ruleset's bypass list can do this. Classic protection shows no date, so those rows show —.

### Remediation actions by repository

- **civickit**
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Code owner review is required but there is no CODEOWNERS file, so the requirement has no effect; add one
  - Require the repository's CI checks to pass before merging (2 active workflow(s), none required)
  - **Observed:** 14 PR(s) merged without an approval from someone other than the author (#202, #209, #210, #216, #226, #227, #228, #229, #231, #232 and 4 more); 14 merged after the approval ruleset was last changed on 2026-07-24
- **core_desk**
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Confirm stale-approval dismissal is on (only repo admins can see this setting)
  - Add a CODEOWNERS file so reviews route to the project's tech lead
  - Require the repository's CI checks to pass before merging (2 active workflow(s), none required)
  - **Observed:** 6 direct push(es) to `main` by people since 2026-08-01, without a pull request
  - **Observed:** 12 PR(s) merged without an approval from someone other than the author (#217, #228, #229, #231, #234, #238, #242, #249, #261, #263 and 2 more)
- **cv_zebrafish**
  - **Baseline:** Require a pull request with at least 1 approving review before merging
  - **Baseline:** Block force pushes
  - **Baseline:** Block deletion of `main`
  - Quick fix: ruleset “main” (deletion, non_fast_forward, pull_request) already covers `main` but its enforcement is `disabled`; set it to Active (Settings → Rules → Rulesets)
  - Add a CODEOWNERS file so reviews route to the project's tech lead
  - Require the repository's CI checks to pass before merging (2 active workflow(s), none required)
  - **Observed:** 7 PR(s) merged without an approval from someone other than the author (#112, #125, #131, #137, #140, #141, #144)
- **dads**
  - Confirm stale-approval dismissal is on (only repo admins can see this setting)
  - Add a CODEOWNERS file so reviews route to the project's tech lead
  - Require the repository's CI checks to pass before merging (5 active workflow(s), none required)
- **DigitalBoneBox**
  - Quick fix: ruleset “Main branch PR” (deletion, non_fast_forward, pull_request) already covers `main` but its enforcement is `disabled`; set it to Active (Settings → Rules → Rulesets)
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Confirm stale-approval dismissal is on (only repo admins can see this setting)
  - Require the repository's CI checks to pass before merging (4 active workflow(s), none required)
  - **Observed:** 5 direct push(es) to `main` by people since 2026-08-01, without a pull request
  - **Observed:** 8 PR(s) merged without an approval from someone other than the author (#405, #491, #495, #496, #497, #502, #503, #505)
- **geo-enricher**
  - **Baseline:** Require a pull request with at least 1 approving review before merging
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Dismiss stale approvals when new commits are pushed
  - Require the repository's CI checks to pass before merging (7 active workflow(s), none required)
  - **Observed:** 24 direct push(es) to `main` by people since 2026-08-01, without a pull request; 10 came after the pull request ruleset was last changed on 2026-09-13, so they went around a rule already in force (check the ruleset's bypass list)
  - **Observed:** 1 force push(es) to `main` since 2026-08-01
  - **Observed:** 15 PR(s) merged without an approval from someone other than the author (#3, #4, #10, #11, #24, #33, #37, #39, #40, #43 and 5 more)
- **GradEval360**
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Add a CODEOWNERS file so reviews route to the project's tech lead
  - Require the repository's CI checks to pass before merging (1 active workflow(s), none required)
  - **Observed:** 2 direct push(es) to `main` by people since 2026-08-01, without a pull request; 2 came after the pull request ruleset was last changed on 2026-04-24, so they went around a rule already in force (check the ruleset's bypass list)
  - **Observed:** 2 PR(s) merged without an approval from someone other than the author (#62, #92); 2 merged after the approval ruleset was last changed on 2026-04-24
- **lrda_mobile**
  - Bind admins to the rules: turn on “Do not allow bypassing the above settings” so admins cannot push or merge without a review
  - Confirm stale-approval dismissal is on (only repo admins can see this setting)
  - Require the repository's CI checks to pass before merging (1 active workflow(s), none required)
  - **Observed:** 17 direct push(es) to `main` by people since 2026-08-01, without a pull request
  - **Observed:** 4 PR(s) merged without an approval from someone other than the author (#289, #295, #296, #298)
- **lrda_website**
  - Bind admins to the rules: turn on “Do not allow bypassing the above settings” so admins cannot push or merge without a review
  - Confirm stale-approval dismissal is on (only repo admins can see this setting)
  - Require review from code owners (a CODEOWNERS file exists but is not enforced)
  - Fix 1 CODEOWNERS syntax/user error(s)
  - Require the repository's CI checks to pass before merging (7 active workflow(s), none required)
  - **Observed:** 9 direct push(es) to `main` by people since 2026-08-01, without a pull request
  - **Observed:** 4 PR(s) merged without an approval from someone other than the author (#354, #364, #366, #377)
- **material-derailleur**
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Confirm stale-approval dismissal is on (only repo admins can see this setting)
  - Require the repository's CI checks to pass before merging (8 active workflow(s), none required)
  - **Observed:** 4 direct push(es) to `main` by people since 2026-08-01, without a pull request
  - **Observed:** 14 PR(s) merged without an approval from someone other than the author (#644, #700, #702, #718, #772, #773, #777, #795, #850, #852 and 4 more)
- **mechatronics-vr**
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Require the repository's CI checks to pass before merging (3 active workflow(s), none required)
  - **Observed:** 18 direct push(es) to `main` by people since 2026-08-01, without a pull request; 8 came after the pull request ruleset was last changed on 2026-09-13, so they went around a rule already in force (check the ruleset's bypass list)
  - **Observed:** 1 PR(s) merged without an approval from someone other than the author (#103); 1 merged after the approval ruleset was last changed on 2026-09-13
- **mithridatium**
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Confirm stale-approval dismissal is on (only repo admins can see this setting)
  - Add a CODEOWNERS file so reviews route to the project's tech lead
  - Require the repository's CI checks to pass before merging (2 active workflow(s), none required)
  - **Observed:** 7 direct push(es) to `main` by people since 2026-08-01, without a pull request
  - **Observed:** 9 PR(s) merged without an approval from someone other than the author (#107, #114, #117, #133, #150, #167, #168, #171, #182)
- **oss_dev_analytics**
  - **Baseline:** Require a pull request with at least 1 approving review before merging
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Require the repository's CI checks to pass before merging (5 active workflow(s), none required)
  - **Observed:** 7 PR(s) merged without an approval from someone other than the author (#237, #239, #242, #244, #248, #250, #253)
- **oss-orb**
  - **Baseline:** Require a pull request with at least 1 approving review before merging
  - **Baseline:** Block force pushes
  - **Baseline:** Block deletion of `main`
  - Add a CODEOWNERS file so reviews route to the project's tech lead
  - Require the repository's CI checks to pass before merging (1 active workflow(s), none required)
  - **Observed:** 16 direct push(es) to `main` by people since 2026-08-01, without a pull request
  - **Observed:** 2 PR(s) merged without an approval from someone other than the author (#3, #7)
- **oss-slu.github.io**
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Confirm stale-approval dismissal is on (only repo admins can see this setting)
  - Add a CODEOWNERS file so reviews route to the project's tech lead
  - Require the repository's CI checks to pass before merging (2 active workflow(s), none required)
  - **Observed:** 29 PR(s) merged without an approval from someone other than the author (#296, #306, #307, #309, #311, #313, #314, #315, #316, #317 and 19 more)
- **pao_surgery_simulator**
  - Bind admins to the rules: turn on “Do not allow bypassing the above settings” so admins cannot push or merge without a review
  - Confirm stale-approval dismissal is on (only repo admins can see this setting)
  - Require review from code owners (a CODEOWNERS file exists but is not enforced)
  - Require the repository's CI checks to pass before merging (3 active workflow(s), none required)
  - **Observed:** 28 direct push(es) to `main` by people since 2026-08-01, without a pull request
  - **Observed:** 1 PR(s) merged without an approval from someone other than the author (#134)
- **PilotDataSynchronization**
  - Bind admins to the rules: turn on “Do not allow bypassing the above settings” so admins cannot push or merge without a review
  - Confirm stale-approval dismissal is on (only repo admins can see this setting)
  - Fix 1 CODEOWNERS syntax/user error(s)
  - Require the repository's CI checks to pass before merging (4 active workflow(s), none required)
  - **Observed:** 1 PR(s) merged without an approval from someone other than the author (#226)
- **repoexplorer**
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Dismiss stale approvals when new commits are pushed
  - Require the repository's CI checks to pass before merging (9 active workflow(s), none required)
  - **Observed:** 25 direct push(es) to `main` by people since 2026-08-01, without a pull request; 11 came after the pull request ruleset was last changed on 2026-09-12, so they went around a rule already in force (check the ruleset's bypass list)
  - **Observed:** 10 PR(s) merged without an approval from someone other than the author (#13, #15, #24, #25, #45, #92, #99, #101, #102, #103); 6 merged after the approval ruleset was last changed on 2026-09-12
- **SpeechTranscription**
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Confirm stale-approval dismissal is on (only repo admins can see this setting)
  - Require review from code owners (a CODEOWNERS file exists but is not enforced)
  - Require the repository's CI checks to pass before merging (4 active workflow(s), none required)
  - **Observed:** 3 direct push(es) to `main` by people since 2026-08-01, without a pull request
  - **Observed:** 9 PR(s) merged without an approval from someone other than the author (#318, #321, #323, #325, #326, #336, #340, #343, #346)
- **shelter_volunteers**
  - Bind admins to the rules: turn on “Do not allow bypassing the above settings” so admins cannot push or merge without a review
  - Confirm stale-approval dismissal is on (only repo admins can see this setting)
  - Code owner review is required but there is no CODEOWNERS file, so the requirement has no effect; add one
  - Require the repository's CI checks to pass before merging (8 active workflow(s), none required)
  - **Observed:** 9 direct push(es) to `main` by people since 2026-08-01, without a pull request
  - **Observed:** 13 PR(s) merged without an approval from someone other than the author (#427, #429, #440, #446, #449, #452, #453, #467, #468, #470 and 3 more)
- **TheHealthApp**
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Dismiss stale approvals when new commits are pushed
  - Require the repository's CI checks to pass before merging (1 active workflow(s), none required)
  - **Observed:** 2 direct push(es) to `main` by people since 2026-08-01, without a pull request
  - **Observed:** 2 force push(es) to `main` since 2026-08-01
  - **Observed:** 11 PR(s) merged without an approval from someone other than the author (#132, #140, #141, #142, #209, #212, #217, #220, #221, #222 and 1 more); 7 merged after the approval ruleset was last changed on 2026-10-06
- **TULIP**
  - **Baseline:** Block force pushes
  - **Baseline:** Block deletion of `main`
  - Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing the above settings” in classic rules, the bypass list in rulesets) and remove that bypass
  - Add a CODEOWNERS file so reviews route to the project's tech lead
  - Require the repository's CI checks to pass before merging (1 active workflow(s), none required)
  - **Observed:** 25 direct push(es) to `main` by people since 2026-08-01, without a pull request; 8 came after the pull request ruleset was last changed on 2026-08-25, so they went around a rule already in force (check the ruleset's bypass list)
  - **Observed:** 6 PR(s) merged without an approval from someone other than the author (#2, #3, #5, #8, #9, #18); 3 merged after the approval ruleset was last changed on 2026-08-25
<!-- END GENERATED: scripts/audit_branch_protection.py -->

## 5. Recommendations, in priority order

1. **Bring the five failing repositories up to the baseline.** A repository admin runs `scripts/enforce-branch-protection.sh --repo <name> --apply`, or imports the baseline ruleset (see the [guide](../standards/branch-protection-guide.md#3-for-project-leads-repository-admins)). For cv_zebrafish, switching the existing "main" ruleset to Active also works.
2. **Bind admins to the rules.** In practice, this is the largest gap. Turn on "Do not allow bypassing the above settings" in classic rules, and keep ruleset bypass lists empty. If a team really needs someone to merge without an approval, give one named team a "For pull requests only" bypass, which still blocks direct pushes and force pushes. Review the bypass lists on both civickit rulesets.
3. **Require CI before merging.** Every repository already runs CI. Mark the main build or test job as a required status check.
4. **Ask an org owner to apply one organization ruleset** (`scripts/enforce-branch-protection.sh --all --org-ruleset --apply`). One ruleset then covers every candidate repository and can't be loosened from inside a single repository.
5. **Give the security team read access to admin settings.** Save a fine-grained token with "Administration: Read-only" on the candidate repositories as the `BRANCH_AUDIT_TOKEN` secret. The weekly audit will then also see the settings that show as Unknown today.
6. **Clean up CODEOWNERS.** Add a CODEOWNERS file to the 10 repositories that lack one, starting with civickit and shelter_volunteers, where code owner review is already required but has no effect. Fix the errors in lrda_website and PilotDataSynchronization. Turn on code owner review where a file exists but isn't enforced: lrda_website, pao_surgery_simulator, and SpeechTranscription.

## 6. Status against the #66 acceptance criteria

| Criterion | Status |
|---|---|
| Branch protection audit run on all 22 candidate repositories | Done. All 22 were audited; four names were corrected (§1). |
| Compliance matrix published at `docs/audits/branch_protection_compliance_matrix_fall2026.md` | Done (this document). |
| Minimum baseline (1 required review, force pushes and deletions disabled) on all active repositories | 17 of 22 already meet it. The other 5 need a repository admin or org owner. The script, the importable ruleset, and per-repository steps are ready (§5). |
| Remediation guide published for project leads and students | Done: [Branch Protection Guide](../standards/branch-protection-guide.md). |

## 7. Keeping this current

`.github/workflows/branch-protection-audit.yml` runs the audit every Monday. It posts the matrix to the run summary, uploads the JSON results, and fails if any control got weaker than the snapshot committed next to this file. After remediation, regenerate this file with the command in §3.5 to update the snapshot.

---

Disclosure: partially drafted with AI assistance and manually reviewed.

Last updated 11/13/26 by Kysen Krishnaswamy
