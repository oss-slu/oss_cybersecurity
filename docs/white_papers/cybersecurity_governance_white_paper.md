# Governing Open Source on a Semester Clock

## A Cybersecurity Governance Model for University Open-Source Programs, with Evidence from Open Source with SLU

*White paper · Security @ Open Source with SLU · November 2026*

**Author:** Kysen Krishnaswamy
**Evidence collected through:** November 14, 2026

---

## Abstract

University open-source programs build real software for real partners, but they run on a semester clock: contributors rotate every few months, most of them are learning as they go, and the few people with administrative rights are spread thin. Security tools alone don't solve this. A setting is only as strong as the person who can switch it off, and a workflow only helps if someone notices when it stops running.

This paper argues that **governance**, meaning who decides the rules, how they are enforced, how exceptions are handled, and how outcomes are verified, is the missing layer. It draws on two audits of Open Source with SLU (OSS-SLU) conducted this semester across 22 active candidate repositories.

The evidence shows a consistent gap between configuration and practice:

- 17 of 22 repositories meet a branch protection baseline on paper, yet unreviewed changes reached `main` in 21 of them.
- Software Bill of Materials (SBOM) automation went from 0 to 16 of 22 repositories in seven weeks, yet one carefully reviewed SBOM change was merged and never ran.
- No repository required CI to pass before merging, and an automated dependency update with a failing build merged itself.

From this evidence the paper derives eight governance principles and proposes a concrete model for OSS-SLU: roles and responsibilities, three policy tiers, a semester lifecycle, an exceptions process, metrics, and a three-phase roadmap for Spring 2027. The model is mapped to the NIST Secure Software Development Framework, SLSA, and OpenSSF Scorecard.

---

## Executive Summary

**Findings**

1. **Protection on paper is not protection in practice.** 179 of 738 pull requests merged between August 1 and November 13 (24%) had no approval from anyone but their author, and people pushed directly to `main` 200 times. 72 of these changes went around a ruleset that was already in force. The dominant cause is that administrators are not bound by the rules.
2. **No repository required CI before merging (0 of 22).** As a result, a Dependabot update whose build had failed was merged automatically and broke a container build without anyone noticing.
3. **Supply-chain transparency grew fast.** SBOM generation or attestation in CI went from 0 to 16 of 22 candidate repositories, and a central SLSA Build Level 3 workflow now serves five of them.
4. **Centralization concentrates risk.** All five consumers call the central workflow at `@main`, and 13 of the 19 pull requests merged in its repository since August had no independent approval.
5. **Governance works when it is specific.** The first repository to receive an evidence-backed audit issue fixed it within 20 hours and asked for its one remaining bypass to be recorded as a formal exception.

**Recommendations**

1. Enforce the baseline with an **organization-level ruleset** with an empty bypass list, and handle legitimate needs through a written **exceptions register** that expires each semester.
2. **Require CI checks** on every active repository, and gate Dependabot auto-merge on them.
3. **Guard the paved road:** pin consumers of central workflows to a tag or SHA, give `oss_cicd_automation` the strictest protection in the organization, and verify attestations against the signing workflow.
4. **Verify outcomes continuously:** extend the weekly audit from branch protection to SBOM and attestation presence, and define "done" for CI changes as "observed on `main`."
5. Run security on the **semester lifecycle**: least-privilege access granted at the start, exceptions reviewed at midterm, and access reviewed and handed off at the end.

---

## 1. Introduction

### 1.1 The Problem

Open-source software is now the main supply chain for the world's code, and attackers have noticed. In 2024 a backdoor was found in the xz compression library, inserted after a years-long effort to win a maintainer's trust [7]. In 2025, attackers moved the version tags of a popular GitHub Action to point at code that leaked CI secrets [8], and a self-replicating worm compromised more than 500 npm packages by stealing developers' tokens [9]. None of these attacks broke cryptography. Each one exploited **governance**: who is trusted, which references are trusted, and what is allowed to change without review.

University open-source program offices (OSPOs) are a growing part of this ecosystem. Open Source with SLU, Saint Louis University's open-source program office, builds and maintains software with student teams for nonprofits, researchers, and university units. Its software is used by real partners, so its security matters. But a student program differs from a company or a foundation in ways that break many standard assumptions about who maintains what and for how long.

### 1.2 Contributions

This paper makes five contributions:

1. It characterizes six features of university open-source programs that shape their security governance (§2).
2. It presents evidence from two organization-wide audits run this semester (§4).
3. It derives eight principles from that evidence (§5).
4. It proposes a governance model for OSS-SLU: roles, policy tiers, a semester lifecycle, an exceptions process, metrics, and a roadmap (§6).
5. It maps the model to NIST SSDF, SLSA, and OpenSSF Scorecard so that it can be compared and adopted elsewhere (§7).

### 1.3 Method and Sources

- **Branch protection audit** (oss_cybersecurity#66, merged in #73). Settings and practice on the default branch of the 22 candidate repositories. Practice covers August 1 to November 13, 2026, and the audit is now re-run weekly [11].
- **SBOM and CI audit** (conducted for this paper and the companion case study, November 14). Every workflow file on the 22 default branches was scanned for SBOM generation and attestation. The history of each matching file was traced to its first SBOM-related commit, and the recent runs of all 52 active workflows with at least five default-branch runs were classified.
- **Targeted reviews.** The central workflow repository (`oss_cicd_automation`) was audited with the same tool, and individual incidents were reconstructed from pull request timelines, commits, and Actions run history.
- **Organizational documents.** The security risk register [13], the Supply-Chain Security Baseline [12], the Dependency Pinning Guide, and the Branch Protection Guide.
- **External standards, guidance, and incident reports**, cited in the References.

**Terms.** In this paper, *governance* means the system of decisions, rules, roles, enforcement, exceptions, and verification. *Management* means the day-to-day work of running security tools.

---

## 2. The Setting: What Makes a University Open-Source Program Different

OSS-SLU's GitHub organization has existed since 2022. It holds more than 80 non-archived repositories, 33 of which received pushes between August 1 and November 14, 2026, and 186 members list their membership publicly. Student teams work on projects for partners under student tech leads and a faculty program director. Cross-cutting teams handle security (this repository) and CI/CD (`oss_cicd_automation`).

Six features of this setting shape every governance decision:

| # | Feature | Evidence at OSS-SLU | Governance implication |
|---|---|---|---|
| 1 | **Semester turnover.** Most contributors stay one or two semesters. | The risk register lists lost knowledge (R-14) and former members keeping access (R-04) as open risks [13]. | Controls must live in configuration and automation, not in people's memory. Access must be reviewed at every semester boundary. |
| 2 | **Permission asymmetry.** A few people hold admin rights; most contributors, including the security team, hold read access to most repositories. | The security team made every change to project repositories through forks. The branch protection audit had to be designed to work with read-only access [11]. | Central owners must hold the enforcement levers (organization rulesets), and verification must work without admin rights. |
| 3 | **Heterogeneous stacks.** | The 22 candidates span TypeScript web apps, Python services, Unity and VR projects, desktop releases, and mobile apps. | Standards should specify outcomes (MUST/SHOULD/MAY) and offer reference implementations, not one mandated toolchain. |
| 4 | **Learners as maintainers.** Student leads often hold admin rights on their project. | Two repositories require code-owner review but have no CODEOWNERS file, so the setting does nothing [11]. The first version of this team's risk register itself described CODEOWNERS as an approval control. | Guardrails must be hard to misconfigure, and their error messages and guides must teach. |
| 5 | **Real stakeholders.** Partners deploy and depend on the software. | Material Derailleur, for example, is built for a nonprofit's donation tracking. | Provenance, SBOMs, and incident response are deliverables, not extras. |
| 6 | **Heavy automation.** | Dependabot auto-merge, reusable workflows shared across repositories, and AI-assisted contributions (disclosed by convention in this team's documents). | Bots, shared workflows, and AI-assisted changes must pass the same gates as people. |

Companies have stable owners and enforce policy through employment. Foundations such as the Apache Software Foundation rely on long-term committers and formal votes. A university program has neither. It needs governance that **survives turnover by default**.

---

## 3. The External Landscape

### 3.1 Incidents That Define the Risk

| Incident | What happened | Governance lesson |
|---|---|---|
| **xz utils backdoor** (CVE-2024-3094, 2024) [7] | Malicious code was inserted into release tarballs of a ubiquitous compression library, after a long campaign to gain the maintainer's trust. | Maintainer succession and independent review are security controls. A single trusted person is a single point of failure. |
| **tj-actions/changed-files** (CVE-2025-30066, 2025) [8] | The version tags of a widely used GitHub Action were moved to a malicious commit that printed CI secrets into build logs. | Mutable references (tags, branches such as `@main`) are attack paths. Pin to full commit SHAs. |
| **"Shai-Hulud" npm worm** (2025) [9] | Self-replicating malware compromised more than 500 npm packages, harvesting credentials, including GitHub tokens, to publish further infected versions. | Dependency updates and long-lived tokens spread compromise. Gate automatic updates, delay brand-new versions, and limit token scope. |

### 3.2 Standards and Regulation

- **U.S. federal guidance.** Executive Order 14028 (2021) [4] led to the NIST **Secure Software Development Framework** (SSDF, SP 800-218) [1] and to the NTIA's **minimum elements for an SBOM** [2]. Organizations that sell software to the federal government are now expected to follow SSDF practices, and their suppliers, including open-source projects, are increasingly asked for SBOMs.
- **SLSA** [3] defines build levels for supply-chain integrity. At Build Level 3, provenance is generated by a hardened, isolated build platform that the project's own build steps cannot tamper with. GitHub documents how artifact attestations combined with reusable workflows reach this level [14].
- **OpenSSF Scorecard** [5] automatically checks open-source repositories for practices such as Branch-Protection, Code-Review, CI-Tests, Pinned-Dependencies, Token-Permissions, and Dangerous-Workflow. The **OpenSSF Best Practices Badge** [6] offers a self-certification checklist.
- **The EU Cyber Resilience Act** (Regulation (EU) 2024/2847) [10] entered into force in December 2024. Its vulnerability-reporting obligations apply from September 11, 2026, and most other obligations from December 11, 2027. It recognizes "open-source software stewards" with lighter duties. Non-commercial academic projects are likely outside its direct scope, but partners who build products on OSS-SLU code may need SBOMs and vulnerability information from upstream. *(This is a summary, not legal advice.)*

The common thread is that external expectations are moving from "do you have a policy?" to "**show the evidence**": signed provenance, machine-readable SBOMs, and records of review.

---

## 4. Evidence: OSS-SLU's Security Posture in Fall 2026

### 4.1 Change Control: Configured Rules vs. What Reached `main`

The branch protection audit [11] compared each candidate's default-branch settings with the actual history of changes, using only read-level access, and validated its read-only method against admin ground truth on a sandbox branch.

| Measure (Aug 1 – Nov 13, 2026) | Result |
|---|---|
| Repositories meeting the baseline (PR with ≥1 approval, force pushes blocked, deletion blocked) | **17 of 22** |
| Repositories where unreviewed changes reached `main` | **21 of 22** |
| Merged pull requests with no approval from anyone but the author | **179 of 738 (24%)** |
| Direct pushes to `main` without a pull request | 200, across 16 repositories |
| Changes that went around a ruleset already in force (confirmed bypasses) | **72, across 7 repositories** |
| Repositories requiring CI checks before merging | **0 of 22** |
| Admins bound by the rules (confirmed yes / confirmed no) | 1 / 5 (the rest are not visible without admin access) |
| CODEOWNERS file present / code-owner review enforced / file has errors | 12 / 9 / 2 |

**Interpretation.** The rules mostly exist, and the people who can bypass them often do. The only repository confirmed to bind its admins (dads) is also the only one where every change was reviewed. Protection is not missing so much as optional for the people who merge most changes.

### 4.2 Supply-Chain Transparency: Fast Adoption, Uneven Assurance

- **Adoption.** No SBOM or attestation workflow on the candidates' default branches predates September 28, 2026. By November 14, **16 of 22** generated SBOMs or attestations in CI: 12 through repository-specific workflows and 4 only through a central SLSA Build Level 3 reusable workflow published on November 11–13.
- **Assurance.** The companion case study [15] documents what happened between "merged" and "running." In RepoExplorer, the SBOM workflow passed all 71 of its executed runs and attested 23 builds, and those attestations were verified independently on November 14. In Material Derailleur, an approved SBOM change was merged but never reached `main`. On merge day, merging `main` into the branch resolved the conflicting files to `main`'s version, and the approval that this dismissed was not renewed before the merge. Nothing checked the outcome, so the gap lasted 32 days.

### 4.3 Automation Without Gates

On October 8, Dependabot proposed moving Material Derailleur's server from TypeScript 6 to TypeScript 7. The pull request's build check **failed**. Auto-merge merged it anyway, because no check was required. The break stayed invisible, because changes merged with GitHub Actions' built-in token [do not trigger new workflow runs](https://docs.github.com/en/actions/using-workflows/triggering-a-workflow), so the container build never ran on the broken commit. It was discovered two days later only because a contributor tested an unrelated change. This is the "0 of 22 require CI" finding in concrete form: automation multiplied a missing control.

### 4.4 Signal Quality

Material Derailleur's old build workflow last passed on `main` on April 25, 2026. Its next 149 runs all failed, 142 of them in a deployment job whose token was missing. When the SBOM steps silently disappeared, the workflow's status didn't change, because it was already red. A warning that is always on carries no information. Sociologist Diane Vaughan named this pattern *normalization of deviance* [16].

There is good news. On November 13, the CI/CD effort removed the obsolete failing workflows. As of November 14, **none** of the 52 active workflows across the 22 candidates that had at least five recent default-branch runs fails on every run.

### 4.5 Policy as Code That Worked

- **Automatic enforcement is fast.** In DADS, SonarCloud's quality gate blocked a pull request because a third-party action was referenced by a movable tag. The fix (pinning to a commit SHA) landed five minutes later. A written guideline had not achieved that across the organization: RepoExplorer's SBOM workflow, written three weeks earlier, still references the same action by tag.
- **Pinned shared workflows already exist.** This repository calls the shared Code Futures workflow at a release tag (`@v1.0.0`), not at a branch. That is the model recommended below for all central workflows.
- **Continuous auditing.** As of November 14, this repository runs a weekly branch-protection drift check that fails if protection gets weaker, plus scripts that audit secret scanning and lockfile hygiene. Together they form the start of a governance toolkit that works with read-only access.

### 4.6 The Paved Road Concentrates Risk

Centralizing build logic is the right direction. Five repositories adopted the central SLSA workflow in a single day, gaining SBOMs, signed provenance, and vulnerability scanning without each team writing its own. But every consumer calls it at **`@main`**. Anyone who can change `main` in `oss_cicd_automation` can therefore change how five projects are built and what their attestations vouch for, with no change in those projects' own repositories.

The audit of that repository for the same window found that it meets the baseline on paper. However, **13 of its 19 merged pull requests had no independent approval, and all 13 were merged after its approval rule was in force.** There was also one direct push after that date. This is not a criticism of the people involved: a small team with admin rights moving fast is normal, and it is how the central workflow shipped quickly. But because the most-reused code in the organization now lives there, that repository should carry the **strictest** protections in the organization, not the loosest.

### 4.7 Governance in Action

The branch protection audit ended with 21 specific, evidence-backed issues filed in the project repositories on November 13. Within 20 hours, civickit's maintainer had:

- added a CODEOWNERS file and made code-owner review effective;
- made the backend CI check required, making civickit the first of the 22 to require CI;
- disabled a ruleset that let the admin role and two contributors bypass the rules.

The maintainer kept one bypass for themselves, restricted to pull requests, and explained why: they are the project's sole maintainer, and small fixes sometimes can't wait. They asked for that bypass to be documented as an exception. They also noted that most of the flagged merges were teammates' pull requests that had been reviewed but merged without anyone clicking "Approve."

Three lessons follow:

1. Specific, evidence-backed findings get acted on quickly.
2. Legitimate exceptions exist, so governance needs an **exceptions process**, not a blanket ban.
3. Much "unreviewed" work is informally reviewed. The goal is to make real review **visible and recorded**, not to assume bad faith.

### 4.8 Summary of Gaps

| Evidence | Gap | Principle (§5) |
|---|---|---|
| 72 confirmed bypasses; admins not bound | Enforcement is optional for those who merge most | P1, P2, P6 |
| 0 of 22 required CI; failing Dependabot update auto-merged | Automation lacks gates | P6 |
| Approved SBOM change never ran; nobody noticed | Outcomes aren't verified | P4 |
| 149 consecutive failed runs | Untrustworthy signals | P5 |
| Central workflow at `@main`; 13 of 19 unapproved merges | The paved road isn't guarded | P3 |
| CODEOWNERS required without a file; CODEOWNERS mistaken for an approval control | Controls easy to misconfigure | P1, P8 |
| Turnover risks R-04 and R-14 | Access and knowledge depend on people | P7 |

---

## 5. Principles

**P1. Enforce, don't just document.** A control that depends on someone choosing to follow it is advice, not a control. Prefer settings that make the secure path the only path (rulesets, required checks) over guidelines. Describe controls exactly: a CODEOWNERS file nominates reviewers, but only branch protection makes their approval required.

**P2. Make exceptions explicit, owned, and expiring.** Some exceptions are legitimate, such as a sole maintainer or an emergency fix. Each exception should have a written reason, a named owner, a compensating control, and an expiry date no later than the end of the semester. An undocumented bypass is a vulnerability. A documented exception is a decision.

**P3. Build paved roads, then guard them.** Central reusable workflows and organization rulesets raise the floor for every project at once. They also become the organization's highest-value targets. Pin consumers to reviewed versions (tags or SHAs), protect the central repositories more strictly than any project, and verify that artifacts were signed by the expected workflow.

**P4. Verify outcomes, not intentions.** "Merged," "configured," and "closed as completed" are intentions. "The attestation verifies," "the rule blocked a push," and "the SBOM lists the dependency" are outcomes. Audit outcomes continuously and automatically, with tools that work under read-only access so that the people checking aren't the same people who could bypass.

**P5. Keep signals trustworthy.** A red check must mean something. Fix or remove any workflow that fails on every run within a week. Treat a "successful" job that produces an empty or missing output as a failure.

**P6. Apply the same gates to people, bots, and admins.** Required reviews and checks should bind administrators, automated dependency updates, and AI-assisted changes alike. Where an actor genuinely needs to bypass a rule, that is an exception (P2).

**P7. Grant least privilege on a semester clock.** Grant access by role at the start of each semester, and review and revoke it at the end. Every active repository should have a named maintainer and a named backup who continue past the semester, so that admin rights never rest with someone who has left.

**P8. Teach through the controls.** In a university program, most contributors are learning. Controls should explain themselves: link rule failures to guides, write standards with examples, and treat a misconfiguration as a documentation bug before treating it as a person's mistake. Disclose AI assistance, as this team's documents already do, so that reviewers know where to look harder.

---

## 6. A Governance Model for OSS-SLU

### 6.1 Roles and Responsibilities

R = responsible (does the work), A = accountable (signs off), C = consulted, I = informed.

| Activity | Program director | Org owners | Security team | CI/CD team | Tech leads | Project maintainers | Contributors |
|---|---|---|---|---|---|---|---|
| Set organization-wide security policy (Tier 1) | A | C | R | C | C | I | I |
| Maintain organization rulesets and org settings | I | A/R | C | C | I | I | I |
| Maintain central workflows (`oss_cicd_automation`) | I | C | C | A/R | C | I | I |
| Run weekly audits and file findings | I | I | A/R | C | I | I | I |
| Remediate findings in a repository | I | C | C | C | A | R | C |
| Approve exceptions | I | C | A | C | R | C | I |
| Grant and revoke access each semester | I | R | C | I | A | C | I |
| Review and merge pull requests | — | — | — | — | A | R | C |
| Respond to security incidents | I | R | A/R | C | R | R | I |

### 6.2 Policy Tiers

| Tier | Meaning | Enforced by | Contents |
|---|---|---|---|
| **1. MUST (organization-enforced)** | Applies to every active repository; repositories cannot opt out | Organization rulesets and org settings | Pull request with ≥1 approval on the default branch; stale approvals dismissed; force pushes and deletion blocked; **empty bypass list** except registered exceptions; secret-scanning push protection; workflow token permissions read-only by default |
| **2. SHOULD (project standard)** | Expected unless an exception is recorded | Standards documents, weekly audits, and filed issues | Required CI checks; valid CODEOWNERS with code-owner review; SBOM and attestation through the central workflow (or the Supply-Chain Baseline); third-party actions pinned to SHAs; lockfiles per the Dependency Pinning Guide; Dependabot auto-merge only behind required checks; `SECURITY.md` |
| **3. MAY (project choice)** | Encouraged where it fits | Project maintainers | Two approvals; merge queue; signed commits; fuzzing; per-component SBOMs; SLSA L3 for non-container artifacts |

### 6.3 The Semester Lifecycle

| When | Activity | Owner |
|---|---|---|
| **Before week 1** | Confirm the drift audit is green and central workflows are unchanged since review. Remove last semester's departed members. Archive inactive repositories. | Org owners, security team |
| **Week 1** | Grant access by role. Run onboarding: the Branch Protection Guide's student section, the Supply-Chain Baseline, and how to disclose AI assistance. Confirm every active repository has a named maintainer and backup. | Tech leads |
| **Weekly** | Automated audits: branch protection drift, secret scanning, and (proposed) SBOM and attestation presence on `main`. Findings become issues in project repositories. | Security team |
| **Midterm** | Review every exception. Run a tabletop incident exercise, for example: "a third-party action we use was retargeted to malicious code." | Security team, tech leads |
| **Final two weeks** | Access review, handoff notes, and an audit snapshot committed to `docs/audits/`. Update the risk register. | Tech leads, security team |
| **Semester close** | Revoke departing access. Transfer admin rights to continuing maintainers or staff. | Org owners |

### 6.4 Exceptions Process

1. **Request.** The maintainer opens an issue in this repository naming the control, the reason, the compensating control, the owner, and the expiry (no later than the end of the semester).
2. **Approve.** The security lead and the project's tech lead approve it in the issue.
3. **Register.** The exception is added to an exceptions register in `docs/audits/`, and the weekly audit reports it as *accepted*, not as a violation.
4. **Review.** Every exception is reviewed at midterm and expires at semester close unless renewed.

*Example.* civickit's maintainer keeps a pull-request-only bypass as sole maintainer. Compensating control: the tech lead reviews merged pull requests weekly. Expiry: end of the semester, or sooner if a second maintainer joins.

### 6.5 Metrics

| Metric | Fall 2026 (Nov 13 audit unless dated) | Spring 2027 target | Related check |
|---|---|---|---|
| Candidates meeting the branch baseline | 17 / 22 | 22 / 22 | Scorecard Branch-Protection |
| Merged PRs without independent approval | 179 / 738 (24%) | < 5%, excluding registered exceptions | Scorecard Code-Review |
| Confirmed bypasses outside registered exceptions | 72 in 7 repositories | 0 | Scorecard Branch-Protection |
| Repositories requiring CI before merge | 1 / 22 (Nov 14) | ≥ 18 / 22 | Scorecard CI-Tests |
| Repositories generating SBOMs or attestations in CI | 16 / 22 (Nov 14) | 21 / 22 | SLSA Build L2+; SSDF PS.3 |
| Central-workflow consumers pinned to a tag or SHA | 0 / 5 (Nov 14) | All | Scorecard Pinned-Dependencies |
| Active workflows failing on every recent run | 0 / 52 (Nov 14) | 0 | (signal hygiene) |
| Valid CODEOWNERS files | 10 / 22 | 22 / 22 | Scorecard Code-Review |
| Time to close an audit finding | First closed in < 1 day (Nov 14) | Median < 14 days | — |

These metrics should be published each semester as a governance scorecard next to the audit snapshots in `docs/audits/`.

### 6.6 Roadmap for Spring 2027

**Phase 1: Weeks 1–2 (set the floor)**

- Apply the baseline as an **organization ruleset** with an empty bypass list (`scripts/enforce-branch-protection.sh --all --org-ruleset --apply`, run by an org owner), and open the exceptions register.
- Protect `oss_cicd_automation` most strictly: CODEOWNERS for `.github/workflows/`, required review that admins cannot bypass, and required checks.
- Publish a release tag of the central SLSA workflow and move the five consumers from `@main` to it.
- Set the organization's default workflow token permissions to read-only.

**Phase 2: By midterm (close the gaps)**

- Require CI checks on every active repository, and gate Dependabot auto-merge on them, with Dependabot's `cooldown` setting [17] to delay brand-new releases.
- Move remaining container projects onto the central workflow. Document verification with `gh attestation verify --signer-workflow` [14].
- Add an "SBOM and attestation present on `main`" check to the weekly audit.
- Fix the end-of-life runtimes the new SBOMs revealed (both Material Derailleur images run end-of-life Node.js).

**Phase 3: Final weeks (prove it and hand it off)**

- Access review and handoff.
- Publish the governance scorecard (§6.5).
- Run the supply-chain tabletop exercise.
- Update the risk register (R-04, R-05, R-09, R-14) with measured results instead of descriptions.

---

## 7. Framework Alignment

| OSS-SLU control or practice | NIST SSDF [1] | SLSA [3] | OpenSSF Scorecard [5] | OSS-SLU artifact |
|---|---|---|---|---|
| Policy tiers, standards documents | PO.1 Define security requirements | — | Security-Policy | Standards in `docs/standards/`, `SECURITY.md` |
| Roles, semester lifecycle, exceptions | PO.2 Implement roles and responsibilities | — | — | This paper, §6 |
| Central workflows, audit tooling | PO.3 Implement supporting toolchains | Build L3 (isolated reusable workflow) | Dangerous-Workflow, Token-Permissions | `oss_cicd_automation`, `scripts/` |
| Required CI checks | PO.4 Define and use criteria for software security checks | — | CI-Tests | Branch Protection Guide |
| Required review, branch rules, no bypass | PS.1 Protect all forms of code from unauthorized access and tampering; PW.7 Review code | — | Branch-Protection, Code-Review | Baseline ruleset, weekly drift audit |
| Attestation and verification | PS.2 Provide a mechanism for verifying software release integrity | Build L2–L3 provenance | Signed-Releases | Supply-Chain Baseline, `gh attestation verify` |
| SBOMs preserved per build | PS.3 Archive and protect each software release (provenance data) | — | — | SBOM workflows, case study [15] |
| Pinning and controlled updates | PW.4 Reuse existing, well-secured software | — | Pinned-Dependencies, Dependency-Update-Tool | Dependency Pinning Guide |
| Vulnerability intake and response | RV.1 Identify vulnerabilities; RV.2 Assess, prioritize, remediate | — | Vulnerabilities | Incident Response Plan, `SECURITY.md` |

---

## 8. Limitations

- **One organization, one semester.** The evidence comes from OSS-SLU's 22 candidate repositories between August and November 2026. Other university programs differ in size, funding, and staffing.
- **Read-only vantage point.** Some settings, such as whether admins are bound in classic protection, are visible only to admins. The audit reports these as unknown rather than guessing.
- **Counting is not judging.** An "unapproved merge" may have been reviewed informally (§4.7), and a bypass may have been legitimate. The figures measure *recorded* review, which is what governance can verify.
- **Insider author.** The author is a member of the security team and built some of the audited automation. Conclusions are tied to recorded evidence to limit bias.
- **Standards and law.** Summaries of standards and regulation are for orientation only and are not legal advice.

---

## 9. Conclusion

OSS-SLU did not lack security tools this semester. It adopted SBOMs and signed provenance across most of its active projects in seven weeks, and nearly every repository has some form of branch protection. What it lacked was the governance layer that makes tools dependable:

- rules that bind everyone, including administrators and bots;
- exceptions that are written down and expire;
- central workflows that are pinned and guarded;
- verification that checks outcomes rather than intentions.

These are not expensive. Most are configuration changes, a register, and a calendar. The evidence also shows they work: given a specific, evidence-backed finding, a maintainer fixed their repository in less than a day and asked for their one exception to be documented. A university program will always run on a semester clock. With governance built into its configuration and its calendar, its security no longer has to reset when the clock does.

---

## References

1. NIST. *SP 800-218, Secure Software Development Framework (SSDF) Version 1.1,* February 2022. https://csrc.nist.gov/pubs/sp/800/218/final
2. NTIA. *The Minimum Elements for a Software Bill of Materials (SBOM),* July 2021. https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom
3. SLSA. *Security Levels, v1.0.* https://slsa.dev/spec/v1.0/levels
4. NIST. *Executive Order 14028, Improving the Nation's Cybersecurity.* https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity
5. OpenSSF. *Scorecard Checks.* https://github.com/ossf/scorecard/blob/main/docs/checks.md
6. OpenSSF. *Best Practices Badge Program.* https://www.bestpractices.dev/
7. NVD. *CVE-2024-3094 (xz utils).* https://nvd.nist.gov/vuln/detail/CVE-2024-3094
8. NVD. *CVE-2025-30066 (tj-actions/changed-files).* https://nvd.nist.gov/vuln/detail/CVE-2025-30066
9. CISA. *Widespread Supply Chain Compromise Impacting npm Ecosystem,* September 23, 2025. https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
10. European Union. *Regulation (EU) 2024/2847 (Cyber Resilience Act).* https://eur-lex.europa.eu/eli/reg/2024/2847/oj
11. OSS-SLU Security. *Branch Protection Compliance Matrix, Fall 2026.* [`docs/audits/branch_protection_compliance_matrix_fall2026.md`](../audits/branch_protection_compliance_matrix_fall2026.md)
12. OSS-SLU. *Supply-Chain Security Baseline: SBOM and Build Provenance.* https://github.com/oss-slu/oss_cicd_automation/blob/main/Docs/Supply_Chain_Security_Baseline.md
13. OSS-SLU Security. *Security Risk Assessment.* [`docs/risk_assessment.md`](../risk_assessment.md)
14. GitHub Docs. *Using artifact attestations and reusable workflows to achieve SLSA v1 Build Level 3.* https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3
15. OSS-SLU Security. *Case Study: Automating SBOMs and Build Attestation at Open Source with SLU,* Fall 2026. [`docs/case_studies/sbom_automation_case_study_fall2026.md`](../case_studies/sbom_automation_case_study_fall2026.md)
16. Vaughan, D. *The Challenger Launch Decision: Risky Technology, Culture, and Deviance at NASA.* University of Chicago Press, 1996.
17. GitHub Docs. *Dependabot options reference* (`cooldown`). https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference
18. GitHub Docs. *About rulesets.* https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets
19. GitHub Docs. *Security hardening for GitHub Actions.* https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions

---

## Appendix A: Reproducing the Evidence

```bash
# Branch protection and practice for the 22 candidates (read-only token is enough)
python3 scripts/audit_branch_protection.py --since 2026-08-01

# The same audit for the central workflow repository
python3 scripts/audit_branch_protection.py --repo oss_cicd_automation --since 2026-08-01 --json cicd.json

# Which repositories call the central workflow, and at what ref
for r in geo-enricher material-derailleur oss_dev_analytics repoexplorer shelter_volunteers; do
  gh api repos/oss-slu/$r/contents/.github/workflows/build-attest.yml --jq .content | base64 -d \
    | grep -o 'slsa-build-attest.yml@[^ ]*'
done

# The Dependabot update that merged with a failing build
gh pr view 750 -R oss-slu/material-derailleur --json mergedAt,mergedBy,statusCheckRollup
```

## Appendix B: Glossary

- **Attestation.** A signed statement binding information (such as build provenance or an SBOM) to an artifact's cryptographic digest.
- **Bypass list.** The actors a ruleset allows to skip its rules.
- **CODEOWNERS.** A file that nominates reviewers for paths. It requires their approval only when branch protection enables code-owner review.
- **Provenance.** A record of which repository, commit, and workflow built an artifact.
- **Reusable workflow.** A GitHub Actions workflow that other repositories call. It is the basis of the "paved road."
- **Ruleset.** GitHub's newer branch-protection mechanism [18]. It can be set per repository or across the organization, with an explicit bypass list.
- **SBOM.** Software Bill of Materials: a machine-readable inventory of the components in a piece of software.
- **SLSA.** Supply-chain Levels for Software Artifacts: a framework of build-integrity levels.
- **SSDF.** NIST's Secure Software Development Framework: a set of secure development practices.

---

Disclosure: partially drafted with AI assistance.

*Last updated 11/14/26 by Kysen Krishnaswamy*
