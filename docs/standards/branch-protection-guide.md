# Branch Protection Guide

**Status:** Organizational standard (proposed)  
**Governing Issue:** [oss-slu/oss_cybersecurity#66](https://github.com/oss-slu/oss_cybersecurity/issues/66)  
**Applies to:** the default branch of every active OSS-SLU project repository  
**Current state:** [Branch Protection Compliance Matrix — Fall 2026](../audits/branch_protection_compliance_matrix_fall2026.md)  
**Related risk:** R-09 in the [Security Risk Register](../risk_assessment.md)

---

## 1. Why this matters

`main` is what gets built, deployed, and handed to project partners. Branch protection makes sure that every change to it has been seen by a second person, and that its history can't be rewritten or erased.

| What can go wrong | Control |
|---|---|
| An unreviewed change, whether a mistake or deliberate, reaches `main` | Pull request with at least 1 approving review |
| A force push rewrites or erases `main`'s history | Block force pushes |
| `main` is deleted | Block deletion |
| A change is approved, then new commits are pushed and merged without another look | Dismiss stale approvals |
| A change that breaks the build or tests is merged | Required CI status checks |
| The people with the most access skip all of the above | Admins bound by the rules |

The Fall 2026 audit found that configuration alone is not enough. 17 of 22 repositories meet the baseline on paper, yet unreviewed changes reached `main` in 21 of them, mostly through admin bypass. Binding admins (section 3.4) is what turns these settings into an actual control.

## 2. The baseline

| Setting | Level |
|---|---|
| Changes reach the default branch through a pull request with at least 1 approving review | **Required** |
| Force pushes blocked | **Required** |
| Deletion of the default branch blocked | **Required** |
| Stale approvals dismissed when new commits are pushed | Recommended (included in the baseline ruleset) |
| Review from code owners required, where a CODEOWNERS file exists | Recommended |
| CI status checks required before merging | Recommended |
| Admins bound by the rules | Recommended |

The required and recommended settings that apply to every repository are packaged as a ruleset: [`branch-protection-baseline.ruleset.json`](branch-protection-baseline.ruleset.json). It targets the default branch and has an empty bypass list. These settings are among those the [OpenSSF Scorecard Branch-Protection check](https://github.com/ossf/scorecard/blob/main/docs/checks.md#branch-protection) scores, so meeting this guide also improves a project's Scorecard result.

## 3. For project leads (repository admins)

All three options below add the baseline as a **separate ruleset**. GitHub enforces rulesets and classic branch protection together, and the stricter setting wins. Adding the baseline therefore never removes or loosens anything a repository already has, such as required checks, extra reviewers, or other rulesets. To undo it, delete that one ruleset.

### 3.1 Option A — Import the ruleset in the browser (about 5 minutes)

1. Download [`branch-protection-baseline.ruleset.json`](branch-protection-baseline.ruleset.json).
2. In your repository, open **Settings → Rules → Rulesets**.
3. Click **New ruleset → Import a ruleset** and choose the file.
4. Check the imported values: **Enforcement status: Active**, **Target branches: Default**, **Bypass list: empty**.
5. Click **Create**.
6. Optional, but recommended: edit the ruleset to add **Require status checks to pass** (section 3.5) and, if the repository has a CODEOWNERS file, **Require review from Code Owners**.

### 3.2 Option B — Run the script

You need admin access on the repository, the [GitHub CLI](https://cli.github.com/) (`gh auth login`), and `jq`.

```bash
scripts/enforce-branch-protection.sh --repo <name>                          # dry run: shows the current state and the planned change
scripts/enforce-branch-protection.sh --repo <name> --apply                  # creates or updates the "oss-slu-baseline" ruleset
scripts/enforce-branch-protection.sh --repo <name> --apply --require-code-owners   # also require code owner review (only if CODEOWNERS exists)
scripts/enforce-branch-protection.sh --repo <name> --remove                 # undo
```

The script is safe to re-run: it reports `NOOP` when the ruleset is already correct. After every change it reads the branch's live rules back and confirms the baseline is in force.

### 3.3 Option C — One organization ruleset (org owners)

An org owner can protect every candidate repository at once with a single organization ruleset. Repository admins can't edit or loosen it from inside their repositories.

```bash
gh auth refresh -h github.com -s admin:org
scripts/enforce-branch-protection.sh --all --org-ruleset            # preview the ruleset JSON
scripts/enforce-branch-protection.sh --all --org-ruleset --apply    # create or update it
```

### 3.4 Fixing specific findings from the matrix

| Finding | Fix |
|---|---|
| "Quick fix: ruleset … is disabled" | **Settings → Rules → Rulesets** → open the ruleset → set **Enforcement status** to **Active** → **Save changes**. |
| Required reviews = 0 | Ruleset: edit **Require a pull request before merging** → **Required approvals: 1**. Classic rule: **Settings → Branches** → edit the rule for `main` → **Require approvals: 1**. |
| Force pushes or deletions allowed | Ruleset: turn on **Block force pushes** and **Restrict deletions**. Classic rule: leave **Allow force pushes** and **Allow deletions** unchecked. |
| No protection at all | Use option A or B. |
| Admins not bound / unreviewed changes observed | Classic rule: check **Do not allow bypassing the above settings**. Ruleset: remove everyone from the **Bypass list**. If a small team really needs someone to merge without an approval, add **one named team** with bypass mode **For pull requests only**. That still blocks direct pushes and force pushes, and bypasses are listed under **Settings → Rules → Insights**. |
| CODEOWNERS present but not enforced | Turn on **Require review from Code Owners**. |
| Code owner review required but no CODEOWNERS file | Add `.github/CODEOWNERS`, for example `* @your-tech-lead @your-co-lead`. Until the file exists, the setting does nothing. |
| CODEOWNERS errors | Open the CODEOWNERS file on GitHub; invalid lines are highlighted. The usual cause is a user or team without write access. |

### 3.5 Requiring CI status checks

1. Open any recent pull request and go to the **Checks** tab. Note the exact name of the job that builds and tests the project (for example `build` or `test (3.12)`).
2. Add it under **Require status checks to pass** in the ruleset, or the classic rule.
3. Pitfalls:
   - A workflow limited by `paths:` doesn't run on every PR, and a required check that never runs blocks the merge forever. Require only jobs that run on every pull request.
   - Each leg of a matrix job is a separate check (`test (3.11)`, `test (3.12)`). Require the ones that matter.
   - If a job is renamed, update the required check, or PRs will wait on a check that no longer exists.

### 3.6 Verify

```bash
python3 scripts/audit_branch_protection.py --repo <name>
# [PASS] <name> (main, Ruleset, read): reviews=1 force-push=blocked deletion=blocked …
```

## 4. For students and contributors

With protection on, every change to `main` goes through a pull request:

```bash
git switch main && git pull                 # start from the latest main
git switch -c 123-short-description         # one branch per issue
# …commit your work…
git push -u origin 123-short-description    # then open a pull request on GitHub
```

- Ask a teammate or your tech lead to review. If you push new commits after an approval, the approval is dismissed and you need a new one. This is intended: the reviewer approves what actually gets merged.
- To bring your branch up to date: `git fetch origin && git rebase origin/main`, then `git push --force-with-lease`. Force-push only your own feature branch, never `main`.
- External contributors keep using fork-and-pull. Nothing changes for them.

Common messages:

| Message | Meaning and fix |
|---|---|
| `GH013: Repository rule violations found … Changes must be made through a pull request` | You pushed to `main`. Move the work to a branch with `git switch -c my-fix && git push -u origin my-fix`, open a pull request, then reset your local `main` with `git switch main && git reset --hard origin/main` (only after the branch has been pushed). |
| `Cannot force-push to this branch` / `Cannot delete this branch` | `main` is protected. Make the change through a pull request. |
| `Review required` / `At least 1 approving review is required` | Ask for a review. You can't approve your own pull request. |
| `Required status check "…" is expected` | CI hasn't reported yet, or the check name changed. Ask your tech lead if it stays stuck. |

## 5. Exceptions

A repository may need to deviate from the baseline, for example an archived project, or a documentation-only repository with a single maintainer. In that case, the project's tech lead and the security team agree on the exception in an issue in this repository, and the next audit links to it. Undocumented exceptions are treated as findings.

## 6. Monitoring

[`branch-protection-audit.yml`](../../.github/workflows/branch-protection-audit.yml) audits the candidate repositories every Monday and posts the matrix to the run summary. It fails if any control got weaker than the committed snapshot, so a protection that is removed or loosened is caught within a week. Add or remove repositories in [`scripts/branch_protection_candidates.txt`](../../scripts/branch_protection_candidates.txt).

## 7. References

- GitHub Docs: [About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- GitHub Docs: [About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- OpenSSF Scorecard: [Branch-Protection check](https://github.com/ossf/scorecard/blob/main/docs/checks.md#branch-protection)

---

Disclosure: partially drafted with AI assistance and manually reviewed.

Last updated 11/13/26 by Kysen Krishnaswamy
