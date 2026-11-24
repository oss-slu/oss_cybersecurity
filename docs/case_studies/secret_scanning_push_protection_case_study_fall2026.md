# Case Study: Secret Scanning and Push Protection at Open Source with SLU

*Fall 2026. Twenty-two candidate repositories, one audit script, and a security posture that only administrators can see.*

**Author:** Prabhnoor Singh, Security @ Open Source with SLU
**Semester:** Fall 2026
**Evidence collected:** November 23, 2026

---

## Abstract

Committed secrets (API tokens, private keys, database credentials) are risk R-01 in the OSS-SLU Security Risk Register, and its follow-up action is to confirm that GitHub Secret Scanning is enabled on all active repositories. In Fall 2026 the security team built `scripts/audit_secret_scanning.sh` (PR #74) to measure three things across the 22 candidate repositories: whether Secret Scanning is enabled, whether Push Protection is enabled, and how many secret scanning alerts are open.

Run on November 23, 2026 from a security-team member's account, the audit returned **"Permission Required" for all 22 of 22 candidates**. GitHub returns repository security settings and secret scanning alerts only to repository administrators and organization security managers, so the Secret Scanning enablement rate, the Push Protection enablement rate, and the open alert count for the organization **could not be measured** by the team responsible for measuring them. Run against the author's own test repository (`sprabhnoor/secret-scan-test`), where the author is an administrator, the same script returned complete results: Secret Scanning **enabled**, Push Protection **disabled**, **0** open alerts. That repository detects leaked secrets after they are pushed but does nothing to stop them being pushed.

Key organizational findings:

- **Compliance with R-01 cannot currently be verified by the security team.** The control exists, but its status is visible only to administrators.
- **Detection is not prevention.** Secret Scanning alerts after a secret is already in public git history, while Push Protection blocks the push. The testbed result shows the two can easily be configured differently.
- **The barrier is organizational, not technical.** The script works. What is missing is a sanctioned way for a decentralized student audit team to read security metadata.

---

## At a Glance

| | Compliant repositories (Secret Scanning + Push Protection enabled) | Repositories lacking Push Protection | Personal testbed: `sprabhnoor/secret-scan-test` | Permission barrier edge case: `oss-slu/civickit` |
|---|---|---|---|---|
| Repositories in this group | Unknown: cannot be identified from a non-admin account | Unknown: cannot be identified from a non-admin account | 1 | 1 (representative of all 22 candidates) |
| Auditor's access | Non-admin | Non-admin | Repository administrator | Non-admin (public repository) |
| Secret Scanning | Enabled (by definition) | Not measured | **Enabled** | Permission Required |
| Push Protection | Enabled (by definition) | **Disabled** (by definition) | **Disabled** | Permission Required |
| Open alerts | Not measured | Not measured | **0** | Permission Required |
| What the case shows | The target state, which no candidate can currently be confirmed to meet | The gap between detection and prevention | The script works end to end when the caller has admin access | GitHub redacts security settings and alerts for non-admin callers, even on public repositories |
| Evidence | `audit_secret_scanning.sh`, Nov 23 | `audit_secret_scanning.sh`, Nov 23 | `audit_secret_scanning.sh` with `ORG=sprabhnoor`, Nov 23 | `audit_secret_scanning.sh`, Nov 23 |

---

## 1. Background and Context

### 1.1 Risk R-01: Committed Secrets

The [OSS-SLU Security Risk Register](../risk_assessment.md) lists committed secrets as its first risk:

| ID | Risk | Affected area | Existing protection | Follow-up |
|---|---|---|---|---|
| R-01 | Secrets (API keys, tokens, passwords, private keys) are committed to a repository | All repositories | GitHub Secret Scanning. The Incident Response Plan requires immediate acknowledgement and same-day rotation or revocation, and immediate escalation for tokens with enterprise access. | TL review: confirm Secret Scanning is enabled on all active repositories. |

Two features of this entry shape the rest of this study. First, the existing protection is **Secret Scanning**, a detection control: it raises an alert after a secret has already been pushed. Push Protection, which blocks the push itself, is not mentioned. Second, the follow-up is a **verification task**: someone has to confirm that the control is actually enabled. `scripts/audit_secret_scanning.sh` was written to do that confirmation.

### 1.2 Why Leaks in Open-Source University Repositories Are Catastrophic

Most OSS-SLU repositories are public. A secret committed to a public repository is not a private mistake that can be quietly corrected. It is published.

- **Public commits are scraped by bots.** A large-scale study of public GitHub found secret leakage in over 100,000 repositories, with thousands of new, unique secrets leaked every day, and showed that attackers who monitor commits can find them efficiently [1]. GitGuardian counted 28.65 million new hardcoded secrets in public GitHub commits in 2025 alone [2]. Once a secret is public, the safe assumption is that it has already been copied.
- **Deleting the commit does not remove the secret.** The secret remains in git history, in forks, and in any clone made before the deletion. The same study found that most leaked secrets were still in place more than two weeks later [1], and GitGuardian found that 64% of valid secrets leaked in 2022 had still not been revoked in January 2026 [2]. The only real fix is rotation or revocation, which is why R-01 requires same-day action.
- **Cluster tokens expose shared infrastructure.** OSS-SLU projects deploy to shared organizational infrastructure. A leaked cluster credential or SSH private key is not limited to one project. It can give an attacker a foothold in systems that many projects and partners depend on.
- **Database credentials expose real people's data.** Partners deploy OSS-SLU software to serve real users. A committed database password or connection string can expose those users' records, turning a student coding mistake into a data breach for a community partner.

University organizations face these risks with extra pressure. Contributors rotate every semester, many are committing to a public repository for the first time, and local `.env` files and test credentials are part of everyday development. Training reduces mistakes, but it cannot eliminate them. That is why the controls in this study matter: they have to work even when someone makes a mistake.

---

## 2. Timeline of Secret Governance at OSS-SLU

| Date (2026) | Event |
|---|---|
| May 11 | Incident Response Plan added to this repository. It requires immediate acknowledgement of a leaked secret, same-day rotation or revocation, and immediate escalation for tokens with enterprise access. |
| Sep 12 | Security Risk Register added ([#20](https://github.com/oss-slu/oss_cybersecurity/pull/20)). R-01 names GitHub Secret Scanning as the protection against committed secrets, and its follow-up asks the Team Lead to confirm that Secret Scanning is enabled on all active repositories. |
| Sep 14 | Security Controls Inventory added. It lists GitHub Secret Scanning as **"Expected; whether it's enabled on all active repos is TBD,"** and notes that individual repository settings such as Secret Scanning toggles were not checked directly. |
| Fall semester | [#65](https://github.com/oss-slu/oss_cybersecurity/issues/65) sets the audit requirement: record Secret Scanning status, Push Protection status, and open alert count for each candidate repository in a compliance matrix. #65 is then locked, and the automation work continues in a new issue, [#72](https://github.com/oss-slu/oss_cybersecurity/issues/72), which asks for a script to produce the matrix. |
| Nov 13 | [PR #74](https://github.com/oss-slu/oss_cybersecurity/pull/74) merged: `scripts/audit_secret_scanning.sh` (closes #72). The script was validated on the author's test repository, `sprabhnoor/secret-scan-test`. |
| Nov 18 | [#77](https://github.com/oss-slu/oss_cybersecurity/issues/77) opened: this case study. |
| Nov 23 | The audit is run against all 22 candidates from a security-team account. All 22 return "Permission Required." The testbed returns complete results (Secret Scanning enabled, Push Protection disabled, 0 open alerts). |

**Enforcement status.** As of November 23, there is no organization-wide enforcement of Push Protection that the security team can confirm, and the R-01 follow-up ("confirm Secret Scanning is enabled on all active repositories") remains open. The audit tooling is in place. What has not yet happened is a run with the access needed to read the results, followed by enabling the controls wherever they are missing. Section 4 explains why, and Section 6 recommends how to close the gap.

---

## 3. Empirical Findings from the 22 Candidate Repositories

### 3.1 Method and Scope

`scripts/audit_secret_scanning.sh` was run on November 23, 2026 from the author's GitHub account, which is a member of the `oss-slu` organization but not an administrator of the candidate repositories. For each repository the script reads the `security_and_analysis` settings from `GET /repos/oss-slu/{repo}` and, if those are visible, counts open alerts from `GET /repos/oss-slu/{repo}/secret-scanning/alerts`.

The script's repository list has 23 entries. Two of them, `enroll-dash` and `geo-enricher`, are the same repository under its old and new names (GitHub redirects the old name; see [`scripts/branch_protection_candidates.txt`](../../scripts/branch_protection_candidates.txt)). This study counts that repository once, giving the 22 candidates. All 22 are public repositories.

The same script was then run against the author's personal test repository with `ORG=sprabhnoor`, where the author is the administrator.

### 3.2 Quantitative Breakdown

| Measure (Nov 23, 2026) | 22 candidate repositories | Testbed: `sprabhnoor/secret-scan-test` |
|---|---|---|
| Repositories audited | 22 | 1 |
| Results readable | **0 / 22** | 1 / 1 |
| "Permission Required" | **22 / 22** | 0 |
| "Repository Not Found" | 0 | 0 |
| Secret Scanning enabled | Not measurable | **Yes** |
| Push Protection enabled | Not measurable | **No** |
| Open secret scanning alerts | Not measurable | **0** |
| Script summary line | 0 compliant, 0 pending remediation, 23 permission required, 0 not found (23 entries, 22 unique repositories) | 0 compliant, 1 pending remediation |

The result is uniform: not one candidate returned readable data. This is not a failure of the script. The same code, run by an administrator against the testbed, returned every field. The difference between the two columns is the caller's access, not the repositories.

### 3.3 Detection vs. Prevention: The Enablement Gap

The issue that commissioned this study asked for the Secret Scanning enablement rate and the Push Protection enablement rate to be compared, because the difference between them is the gap between **reactive detection** and **proactive prevention**:

- **Secret Scanning** scans what is already in the repository and raises an alert. By the time it fires, the secret is in public git history.
- **Push Protection** checks each push and blocks it if it contains a supported secret, so the secret never reaches the repository.

For the 22 candidates this comparison could not be made, because neither rate is readable without administrator access. Three findings still stand:

1. **The testbed shows the gap is real and easy to fall into.** On `sprabhnoor/secret-scan-test`, Secret Scanning is enabled and Push Protection is disabled. The repository will report a leaked secret, but it will not stop one. A repository can look "covered" by secret scanning while having no prevention at all.
2. **Cost is not the barrier.** GitHub Secret Protection, which includes both Secret Scanning and Push Protection, is free to enable for public repositories [3], and secret scanning runs automatically on public repositories [4]. All 22 candidates are public, so enabling Push Protection everywhere would cost the organization nothing.
3. **R-01 only names detection.** The risk register's existing protection for R-01 is Secret Scanning alone (§1.1). Even a complete audit showing 22 of 22 repositories with Secret Scanning enabled would leave the prevention question unanswered.

### 3.4 Open Alerts and Token Classes

The open alert count for the candidates, and therefore the classes of secrets those alerts represent, could not be measured: the alerts endpoint is restricted in the same way as the settings (§4). The testbed has 0 open alerts.

The token classes that matter most for OSS-SLU are the three named in R-01 and §1.2:

| Token class | Examples | Why it matters at OSS-SLU |
|---|---|---|
| API tokens | GitHub personal access tokens, cloud provider keys, third-party service keys | Can act as the project or a person on outside services, often with billing attached |
| Private keys | SSH private keys, TLS keys | Can grant shell access to shared infrastructure |
| Database credentials | Connection strings, passwords in `.env` or config files | Can expose partners' user data |

GitHub's secret scanning detects known secret patterns from over 200 service providers [5]. Generic secrets such as a database password in a `.env` file do not always match a provider pattern, so a count of zero open alerts is not proof that no credentials have been committed. A breakdown of alerts by token class is possible with administrator access, because each alert records its secret type; the command is in the Appendix.

---

## 4. The "Permission Barrier" Phenomenon

### 4.1 The Technical Discovery

While validating `audit_secret_scanning.sh`, the author found that GitHub restricts security metadata in two different ways, depending on the endpoint:

| Endpoint | What a non-admin caller gets | What an admin caller gets |
|---|---|---|
| `GET /repos/{owner}/{repo}` | **HTTP 200**, with the `security_and_analysis` block silently left out of the response | HTTP 200, with `security_and_analysis` showing the status of Secret Scanning and Push Protection |
| `GET /repos/{owner}/{repo}/secret-scanning/alerts` | **HTTP 404 Not Found** instead of alerts | HTTP 200, with the list of alerts |

Both behaviors were confirmed on November 23 against `oss-slu/civickit` from the author's account: the repository request returned no `security_and_analysis` block (`null`), and the alerts request returned `HTTP/2.0 404 Not Found`.

GitHub documents both restrictions. To see the `security_and_analysis` block, the caller must have admin permissions on the repository or be an owner or security manager of the organization [6]. Secret scanning alerts are likewise limited to administrators and security managers [7].

The first behavior is the more dangerous one for an auditor. The request **succeeds**. Nothing in the status code says that data was withheld. A script that simply read `security_and_analysis.secret_scanning.status` and treated a missing value as "not enabled" would have reported 22 repositories as having Secret Scanning **disabled**, a confident and completely false result. `audit_secret_scanning.sh` avoids this by checking whether the block is present at all before reading it, and reports "Permission Required" when it is missing. That check is why the November 23 results say "unknown" instead of "non-compliant."

The second behavior is ambiguous in the same way. GitHub also returns 404 from the alerts endpoint when Secret Scanning is disabled on a repository. To a non-admin caller, "this repository has no secret scanning" and "you are not allowed to see this repository's secret scanning" look identical. The status code cannot be used to infer compliance either way.

### 4.2 The Organizational Challenge

The barrier is a reasonable design choice by GitHub. Security settings and alerts can point to live, unrevoked secrets, so restricting them to administrators protects the repository. But it collides with how OSS-SLU is organized:

- **The auditors are not the administrators.** Security-team students have read-only access to most project repositories and work through forks and pull requests, as the SBOM case study also found. Administrative access sits with project leads and organization owners.
- **The data needed for compliance is exactly the data that is restricted.** The R-01 follow-up asks for confirmation that Secret Scanning is enabled. That confirmation can only come from someone who can read the setting.
- **Granting access has its own risk.** The Access Control Policy requires least privilege and documented grants, and risk R-05 in the register covers members holding more access than their role needs. Making every auditor a repository admin to read one setting would trade a measurement gap for an access-control problem.
- **Decentralized teams multiply the problem.** Each project has its own leads and its own admins. Without a central role, collecting 22 sets of results means asking 22 different people, every semester, as contributors rotate.

GitHub's own answer to this tension is the organization **security manager** role, which is designed to read security settings and alerts across all of an organization's repositories without granting general admin rights [6][7]. Whether OSS-SLU uses that role, has an organization owner run the audit, or both, is an organizational decision rather than a technical one. Section 6 turns it into a recommendation.

### 4.3 What This Means for Measurement

The audit produced a precise answer to a different question than the one it was built for. It did not measure how many candidates have Secret Scanning and Push Protection enabled. It measured that **0 of 22** candidates allow the security team to check. For a control that the risk register treats as the primary defense against committed secrets, that is itself a finding: R-01 is currently protected by a control whose status the responsible team cannot observe.

---

## 5. Real-World Case Analysis: Reactive vs. Proactive

### 5.1 Reactive Scanning: The Window of Exposure

With reactive Secret Scanning, the sequence after a leak is:

| Step | What happens | Who is exposed |
|---|---|---|
| 1. Commit and push | The secret enters public git history | Anyone watching public commits, including automated scrapers [1] |
| 2. Detection | Secret Scanning raises an alert, if the pattern is supported and enabled | Still public |
| 3. Triage | Someone with access to the alert sees it and acknowledges it | Still public. Only admins and security managers can see the alert (§4) |
| 4. Rotation or revocation | The credential is replaced, so the leaked copy stops working | Exposure ends here |
| 5. Cleanup (optional) | The secret is removed from history | Does not end exposure: forks and clones keep the old commit |

The **window of exposure** runs from step 1 to step 4, and every step after step 1 depends on a person. The Incident Response Plan's same-day rotation rule (§1.1) is designed to keep that window short. It can only start, though, once someone sees the alert, and at OSS-SLU the people responsible for R-01 cannot currently see alerts at all.

### 5.2 Proactive Push Protection: No Window at All

Push Protection works at step 1. When a push contains a supported secret, GitHub rejects it and tells the contributor which file and line triggered the block. The secret never enters the repository's history, so:

- there is no public copy to scrape;
- there is nothing to rotate, unless the contributor bypasses the block;
- there is nothing to clean up, and forks never receive it;
- no one has to be watching an alerts page for the protection to work.

If a contributor does bypass the block, GitHub records the bypass and creates an alert, which turns an invisible mistake into a visible, reviewable decision.

### 5.3 What the Comparison Shows

| | Reactive: Secret Scanning | Proactive: Push Protection |
|---|---|---|
| When it acts | After the secret is public | Before the secret is stored |
| Exposure window | From push until rotation | None, unless bypassed |
| Depends on someone reading alerts | Yes | No |
| Effect of the permission barrier (§4) | Alerts may go unseen by the security team | Still blocks the push |
| Remaining work after a leak | Rotate, then optionally rewrite history | Remove the secret from the local commit and push again |
| Limits | Only detects supported and enabled patterns | Only blocks supported patterns; can be bypassed |

The two controls are complementary, not interchangeable, and both have gaps. GitHub classifies OpenSSH and RSA private keys as **non-provider patterns** [8]. Because they are harder to detect reliably, scanning for them is not enabled by default and has to be turned on for the repository or organization [9], so neither control with default settings guarantees that a committed SSH key is caught. But in an organization where the security team cannot see alerts, any control that works **without** someone watching is worth more than one that depends on it. That is the core argument for moving R-01's protection from detection alone to prevention plus detection.

---

## 6. Lessons and Recommendations for University OSPOs

1. **Enforce Push Protection organization-wide, not repository by repository.** Use the organization's security configuration to enable Secret Scanning and Push Protection on every repository, including new ones by default. All 22 candidates are public, so this costs nothing [3]. Per-repository toggles drift as projects are created and handed over each semester.
2. **Give the audit function a sanctioned way to see results.** Assign the organization **security manager** role to the security team, or to a small team within it, so that auditors can read security settings and alerts without becoming repository admins [6][7]. Record the grant under the Access Control Policy so it stays least-privilege and reviewable (R-05).
3. **Run the audit on a schedule with the right credentials.** Until recommendation 2 is in place, have an organization owner run `audit_secret_scanning.sh` at the start and end of each semester and commit the matrix. A result of "Permission Required" should be treated as **unknown**, never as compliant or non-compliant (§4.1).
4. **Update R-01 to name prevention, not just detection.** Change the risk register's existing protection for R-01 to "Secret Scanning **and** Push Protection," and change the follow-up to require confirmation of both. A complete Secret Scanning result alone does not answer whether leaks are being prevented (§3.3).
5. **Turn on detection for non-provider patterns.** Enable scanning for private keys, connection strings, and similar generic secrets at the organization level [9]. These are the token classes most relevant to OSS-SLU's infrastructure and partner databases (§3.4), and they are off by default.
6. **Require a pre-commit secret hook in every project template.** Add a local secret scanner, such as `gitleaks` or `detect-secrets`, through the `pre-commit` framework in new-project templates and onboarding docs. It catches secrets on the contributor's machine, before a push, and covers patterns that GitHub does not.
7. **Verify Push Protection with a dummy token, every semester.** Keep a test repository like `sprabhnoor/secret-scan-test`. Each semester, try to push a commit containing a well-known example or deactivated token in a supported format and confirm that the push is **blocked**. A setting that says "enabled" is a claim. A blocked push is evidence.
8. **Teach the bypass and rotation rule at onboarding.** Every contributor should know three things: never bypass a Push Protection block without asking the security team; a leaked secret must be **rotated** the same day, because deleting the commit is not enough (§1.2); and secret values belong in environment variables or GitHub Actions secrets, never in files that are committed.

Together these recommendations move OSS-SLU toward two external standards: the OpenSSF OSPS Baseline, whose Level 1 control OSPS-BR-07.01 requires a project to prevent the unintentional storage of secrets and credentials in version control, and whose Level 3 control OSPS-BR-07.02 requires a documented secrets-management policy [10]; and NIST SP 800-218 (SSDF), whose practice PS.1 calls for protecting all forms of code from unauthorized access and tampering, with access granted on the principle of least privilege [11].

---

## 7. Impact and Future Measurements

### 7.1 Impact in Fall 2026

- **A repeatable audit now exists.** Before PR #74, the Security Controls Inventory could only say that Secret Scanning status was "TBD." `audit_secret_scanning.sh` turns that question into one command that produces a compliance matrix for all candidates.
- **The audit reports unknowns honestly.** Because the script detects the missing `security_and_analysis` block, it reports "Permission Required" instead of a false "Disabled" (§4.1). An inaccurate compliance report would have been worse than none.
- **The real blocker is identified.** The Fall 2026 baseline shows that the gap is access, not tooling or cost. That turns an open-ended task ("confirm Secret Scanning is enabled") into a specific organizational decision (who is allowed to read the results).
- **A working testbed is in place.** `sprabhnoor/secret-scan-test` proves the script end to end and is ready to be used for the semester Push Protection check (recommendation 7).

### 7.2 Targets for Spring 2027

| Measure | Fall 2026 baseline (Nov 23) | Spring 2027 target | How it will be measured |
|---|---|---|---|
| Candidates whose results the security team can read | 0 / 22 | **22 / 22** | `audit_secret_scanning.sh`: 0 "Permission Required" |
| Secret Scanning enabled | Unknown | **22 / 22** | Compliance matrix |
| Push Protection enabled | Unknown | **22 / 22 (100%)** | Compliance matrix |
| Open secret scanning alerts | Unknown | **0** | Compliance matrix, `open_alerts` column |
| Automated secret scanning check on pull requests | None | **In place** in every candidate | A secret-scanning step that runs on every pull request, confirmed in each repository's workflows |
| Push Protection verified with a dummy token | Not done | **Blocked push recorded** each semester | Testbed push attempt (recommendation 7) |

### 7.3 Measurement Plan

The audit should be run at least twice per semester, at the start and at the end, with credentials that can read the results (recommendations 2 and 3). Each run should commit the generated matrix to `docs/audits/`, so that progress between runs is visible in git history. The first useful comparison is the first run that returns readable results for all 22 candidates: that run becomes the real baseline for Secret Scanning, Push Protection, and open alerts, which this study could not measure.

---

## 8. Limitations and Reflection: Magis

### 8.1 Limitations

- **API permission barriers.** The central limitation. The audit ran from a non-admin account, so Secret Scanning status, Push Protection status, and open alert counts for all 22 candidates are unknown, not zero (§4). The enablement rates and the alert breakdown by token class asked for in §3 could not be produced.
- **No inspection of private commit histories.** Without elevated tokens, the audit could not examine private repositories or the alerts that point into commit history. All 22 candidates are public, but the organization's private repositories, if any, were out of reach and outside the candidate list.
- **A single point in time.** The results describe November 23, 2026 only. Settings can change at any time, and a later run may differ.
- **Scope.** The study covers the 22 candidate repositories in [`scripts/branch_protection_candidates.txt`](../../scripts/branch_protection_candidates.txt), not every OSS-SLU repository.
- **One testbed.** The detection-vs-prevention gap is shown with readable data from a single personal repository. It demonstrates that the gap can exist. It does not show how common it is across the organization.
- **Pattern coverage.** Even with full access, an alert count of zero would not prove that no secrets were committed. Secret scanning only finds supported and enabled patterns, and generic secrets such as passwords in `.env` files may not match one (§3.4).
- **Insider perspective.** The author wrote the audit script being evaluated. The analysis relies on recorded output and GitHub's documentation, but the choice and framing of evidence are still the author's.

### 8.2 Reflection: Magis

*Magis* asks for "the more": not more work for its own sake, but the fuller good that a piece of work can do for others. In security, the fuller good is usually invisible. A leaked credential that Push Protection blocks never becomes an incident, never needs a same-day rotation, and never puts a community partner's users at risk. Nobody sees it, which is exactly the point.

This study's most important result was not a compliance number but the absence of one. The audit was built to confirm that our repositories are protected, and it could confirm nothing. It would have been easy to treat "Permission Required" as a dead end, or to report a number that looked complete. *Magis* points the other way: to report what we actually know, to name what we do not, and to keep going until the people responsible for a control can see whether it works.

For a student-run organization, the deeper lesson is that protecting a community's systems should not depend on one careful person at the right moment. Contributors change every semester and mistakes will happen. The more we can offer is to build defenses that work even then, through prevention that runs on every push, an audit that anyone on the team can repeat, and a clear path for fixing what it finds.

---

## References

[1] M. Meli, M. R. McNiece, and B. Reaves, "How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories," *Network and Distributed System Security Symposium (NDSS)*, 2019. https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/

[2] GitGuardian, *The State of Secrets Sprawl 2026*, March 2026. https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/

[3] GitHub Docs, "Choosing GitHub Secret Protection." https://docs.github.com/en/enterprise-cloud@latest/code-security/securing-your-organization/understanding-your-organizations-exposure-to-leaked-secrets/choosing-github-secret-protection

[4] GitHub Docs, "Supported secret scanning patterns" (availability: public repositories). https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns

[5] Microsoft Learn (GitHub training), "Examine GitHub's security and code quality tools." https://learn.microsoft.com/en-us/training/modules/resolve-github-secret-scanning-alerts-github-copilot-agent/2-examine-github-security-code-quality-tools

[6] GitHub Docs, "REST API endpoints for repositories: Get a repository" (`security_and_analysis` visibility). https://docs.github.com/en/rest/repos/repos

[7] GitHub Docs, "REST API endpoints for secret scanning." https://docs.github.com/en/rest/secret-scanning/secret-scanning

[8] GitHub Docs, "Supported secret scanning patterns: Non-provider patterns." https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns

[9] GitHub Docs, "Non-provider patterns." https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/non-provider-patterns

[10] OpenSSF, *Open Source Project Security Baseline*, version 2026.08.28, controls OSPS-BR-07.01 and OSPS-BR-07.02. https://baseline.openssf.org/versions/2026-08-28

[11] M. Souppaya, K. Scarfone, and D. Dodson, *Secure Software Development Framework (SSDF) Version 1.1*, NIST SP 800-218, February 2022, practice PS.1. https://doi.org/10.6028/NIST.SP.800-218

Internal documents: [Security Risk Register](../risk_assessment.md) (R-01, R-05), [Security Controls Inventory](../security_controls_inventory.md), [`scripts/audit_secret_scanning.sh`](../../scripts/audit_secret_scanning.sh), [`scripts/branch_protection_candidates.txt`](../../scripts/branch_protection_candidates.txt), and the [SBOM case study](sbom_automation_case_study_fall2026.md).

---

## Appendix: Reproducing the Key Numbers

All commands use the GitHub CLI (`gh`), authenticated with `gh auth login`, and are run from the root of this repository. Results depend on the caller's access: a non-admin will reproduce the "Permission Required" figures, and an organization owner or security manager will see the real settings.

**A.1 Full candidate audit (§3.2, At a Glance).** Writes the compliance matrix and prints the summary line.

```bash
./scripts/audit_secret_scanning.sh
```

**A.2 Testbed audit (§3.2, §3.3).** Written to a separate file so it does not overwrite the organization matrix.

```bash
ORG=sprabhnoor OUT=/tmp/testbed_matrix.md ./scripts/audit_secret_scanning.sh secret-scan-test
```

**A.3 The two permission-barrier behaviors (§4.1).** Run against `civickit` from a non-admin account. The first prints `null` (or nothing), the second prints `HTTP/2.0 404 Not Found`.

```bash
gh api repos/oss-slu/civickit --jq '.security_and_analysis'
gh api -i "repos/oss-slu/civickit/secret-scanning/alerts?state=open" 2>&1 | head -1
```

**A.4 Secret Scanning and Push Protection status for one repository (admin access).**

```bash
gh api repos/oss-slu/REPO --jq '{secret_scanning: .security_and_analysis.secret_scanning.status, push_protection: .security_and_analysis.secret_scanning_push_protection.status}'
```

**A.5 Open alerts by token class (§3.4, admin or security manager access).**

```bash
gh api --paginate "repos/oss-slu/REPO/secret-scanning/alerts?state=open&per_page=100" --jq '.[].secret_type_display_name' | sort | uniq -c | sort -rn
```

**A.6 Candidate count and visibility (§3.1).** Counts the 22 unique candidates and prints the visibility of each.

```bash
grep -v '^#' scripts/branch_protection_candidates.txt | awk 'NF{print $1}' | wc -l
for r in $(grep -v '^#' scripts/branch_protection_candidates.txt | awk 'NF{print $1}'); do
  printf '%-28s %s\n' "$r" "$(gh api repos/oss-slu/$r --jq .visibility)"
done
```
