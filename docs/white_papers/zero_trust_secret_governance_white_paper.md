# Zero-Trust Secret Governance for University Open-Source Programs

## A Lifecycle Model for Academic OSPOs, with Evidence from Open Source with SLU

*White paper · Security @ Open Source with SLU · November 2026*

**Author:** Prabhnoor Singh
**Evidence collected through:** November 23, 2026

---

## Abstract

Commercial organizations protect their credentials with centralized secrets vaults, managed devices, and enterprise identity providers. University open-source programs have none of these by default. Their code is public, their contributors change every semester, many of those contributors are committing to a shared repository for the first time, and their CI/CD pipelines are spread across dozens of independently run projects. In this setting a single committed credential (an API token, a database password, an SSH private key) is published the moment it is pushed, and deleting the commit does not unpublish it.

This paper proposes a **Zero-Trust Secret Lifecycle Model** for academic open-source program offices (OSPOs). Its starting assumption is that no environment in the path of a secret is inherently trusted: not the student's laptop, not the git staging area, not the pull request, and not the CI runner. The model places a layer of defense at each of four stages: **(1) pre-commit** on the developer's machine, **(2) the push boundary**, where GitHub Push Protection blocks secrets before they enter history, **(3) CI/CD and central automation**, where tokens are least-privilege by default, and **(4) runtime**, where in-cluster secrets are encrypted and service accounts are narrowly scoped.

The model is grounded in a Fall 2026 audit of Open Source with SLU (OSS-SLU) across 22 active candidate repositories:

- All 22 candidates are **public**, so every committed secret is immediately exposed, and GitHub's Secret Scanning and Push Protection are **free** to enable on all of them.
- The organization's audit script returned **"Permission Required" for 22 of 22** candidates when run by the security team, so the status of the organization's primary defense against committed secrets **cannot currently be verified** by the people responsible for it.
- On a test repository where full results were visible, Secret Scanning was **enabled** but Push Protection was **disabled**: leaks would be detected after publication, not prevented.
- The organization already maintains a pre-commit template with Gitleaks and a reusable pull request secret scanning workflow, but **0 of 22** candidates use either one, and only **7 of 22** ship a `.env.example` template. The gap is adoption, not tooling.

From this evidence the paper derives a governance model for OSS-SLU: a RACI matrix, a three-tier MUST/SHOULD/MAY policy, an exceptions process, and a three-phase roadmap for Spring 2027. The model is mapped to the NIST Secure Software Development Framework (SP 800-218), OpenSSF Scorecard, and SLSA.

---

## Executive Summary

**Thesis.** Preventing secret leaks in university open source requires **layered defense-in-depth in which no environment is inherently trusted**. Training helps, but it cannot be the control: contributors change every 15 weeks, and the program has to stay safe while each new cohort is still learning. Each stage of a secret's path (local machine, git staging, pull request, CI runner, and cluster) needs its own check, so that a mistake missed at one stage is caught at the next.

**Findings**

1. **Exposure is total.** All 22 candidate repositories are public. A committed secret is visible to automated scrapers as soon as it is pushed, and it remains in git history, forks, and clones after the commit is deleted.
2. **The primary control cannot be verified.** The risk register names GitHub Secret Scanning as the protection against committed secrets (R-01), and the Security Controls Inventory lists its status as "TBD." When the security team ran the audit, GitHub withheld the results for 22 of 22 candidates because the team does not hold administrator access.
3. **Detection is configured without prevention.** The one repository with readable results had Secret Scanning on and Push Protection off. The organization's documented protection for R-01 also names detection only.
4. **Cost is not the barrier; access and process are.** Both controls are free for public repositories. What is missing is an organization-wide default, a sanctioned way for auditors to see results, and a defined path from detection to revocation.
5. **The tools exist but are not adopted.** OSS-SLU's own pre-commit template and PR secret scanning workflow are used by 0 of 22 candidates. Controls that each repository must opt into have not spread on their own.

**Recommendations**

1. **Enforce Push Protection organization-wide** as a MUST, with bypasses restricted to Tech Lead approval.
2. **Give the security team the organization security manager role**, so that compliance can be measured without granting general admin rights.
3. **Ship every project template with `.env.example` and a pre-commit secret scanner**, so that the first line of defense runs on the student's machine.
4. **Make CI tokens read-only by default** and route sensitive deployments through centralized, reviewed reusable workflows.
5. **Encrypt in-cluster secrets and scope service accounts**, replacing plaintext manifests and shared admin credentials.
6. **Treat revocation, not deletion, as the response to a leak**, and run the program on a three-phase roadmap: audit and baseline, push protection enforcement, then automated rotation.

---

## 1. Introduction and Problem Context

### 1.1 Why Secrets Are the Highest-Risk Failure Point

Most security failures in a software project are gradual. A vulnerable dependency waits for an attacker to find it. An unreviewed change still has to be merged, released, and deployed before it does harm. A committed secret is different in four ways, and together they make it the single highest-risk failure point for an academic OSPO:

- **It takes effect at push time, not at merge time.** In a public repository, pushing a commit to *any* branch, including a feature branch or a fork, publishes it. Code review, branch protection, and CI all act on the pull request, which arrives after the secret is already public. The controls that protect `main` do not protect a secret.
- **It takes one mistake by one person.** No attacker skill is involved. A single `git add .` that picks up a `.env` file is enough, and in a program where most contributors are new each semester, that mistake is certain to happen eventually.
- **It cannot be undone by deleting it.** The secret remains in git history, in every fork, and in every clone made before the deletion. The only real remedy is to **revoke or rotate** the credential, which requires someone to notice the leak and someone with access to the issuing service to act.
- **It bypasses everything else.** A leaked cloud key, database password, or SSH key gives an attacker direct access to the system it unlocks. Signed builds, SBOMs, and branch rules protect the code, but they do nothing once an attacker holds the credential.

The companion governance white paper for OSS-SLU [5] addresses change control and supply-chain integrity. This paper addresses the failure that those controls cannot reach.

### 1.2 The Consequences of Public Credential Leaks

| Consequence | What happens | Evidence |
|---|---|---|
| **Automated scraping** | Bots continuously clone public repositories and harvest credentials within minutes of a push. | A study of public GitHub found secret leakage in over 100,000 repositories, with thousands of new, unique secrets leaked every day [1]. GitGuardian counted 28.65 million new hardcoded secrets in public GitHub commits in 2025 alone [2]. |
| **Cloud cryptomining** | Stolen cloud keys are used to launch compute instances that mine cryptocurrency, billed to the key's owner. | In the EleKtra-Leak campaign, attackers automatically cloned public GitHub repositories, found exposed AWS IAM credentials, and used them **within five minutes** of exposure. Researchers observed 474 likely attacker-controlled miners on Amazon EC2 in about five weeks [3]. |
| **Database exposure** | A committed connection string or access key opens the data behind an application to anyone who finds it. | An access key to a customer data server sat in a public GitHub repository for nearly five years, exposing the email addresses and customer management numbers of 296,019 customers of Toyota's T-Connect service [4]. |
| **Loss of institutional trust** | Partners stop trusting the program with their data and deployments, and the university's name is attached to the breach. | Toyota disclosed the T-Connect exposure publicly, with an apology, nearly five years after the leak began [4]. For an OSPO, the equivalent cost is a community partner whose users' records were exposed by student code. |

For OSS-SLU these risks are not hypothetical. Its repositories are public (§4), its software is deployed by real partners, and its students work with cloud services, databases, and the organization's own infrastructure.

### 1.3 Contributions

This paper makes five contributions:

1. It identifies the structural features of university open-source programs that make them uniquely vulnerable to secret leakage (§2).
2. It proposes a four-stage **Zero-Trust Secret Lifecycle Model** in which no environment is inherently trusted (§3).
3. It presents a Fall 2026 baseline of secret governance at OSS-SLU, drawn from an organization-wide audit (§4).
4. It proposes operational governance for OSS-SLU: a RACI matrix, a three-tier MUST/SHOULD/MAY policy, and an exceptions process (§5).
5. It maps the model to NIST SSDF, OpenSSF Scorecard, and SLSA (§6), and sets out a phased roadmap with measurable Spring 2027 targets (§7).

### 1.4 Method and Sources

- **Secret scanning audit.** `scripts/audit_secret_scanning.sh` (PR #74) was run on November 23, 2026 against the 22 candidate repositories from a security-team account, and against a test repository with administrator access. The audit is documented in detail in the companion case study [6].
- **Organizational documents.** The Security Risk Register (R-01, R-05), the Security Controls Inventory, the Incident Response Plan, and the Access Control Policy.
- **Repository visibility check.** The visibility of all 22 candidates was confirmed on November 23, 2026.
- **External standards, documentation, incident reports, and research**, cited in the References.

**Terms.** A *secret* is any value that grants access: API tokens, passwords, private keys, database connection strings, and signing keys. *Zero-trust* here means that each stage verifies secrets for itself instead of assuming that an earlier stage has done so.

---

## 2. The Academic Setting: Unique Structural Vulnerabilities

Enterprise secret management assumes a stable workforce, managed devices, private repositories, and a central security team with administrative reach. A university open-source program typically has none of these. OSS-SLU's student teams build software for partners under student tech leads and a faculty program director, with cross-cutting teams for security (this repository) and CI/CD (`oss_cicd_automation`) [5]. Six features of this setting make secret leakage both more likely and more damaging:

| # | Characteristic | Evidence at OSS-SLU | Implication for secret governance |
|---|---|---|---|
| 1 | **The "Semester Clock."** Entire teams onboard and offboard every 15 weeks. | The risk register lists lost knowledge (R-14) and former members keeping access (R-04) as open risks [7]. | Secret hygiene cannot depend on what last semester's team remembers. Controls must live in templates and organization settings, and credentials must be rotated when the people who knew them leave. |
| 2 | **Varying security maturity.** Many contributors are junior developers working in a shared repository for the first time. | Contributors range from first-year students to experienced leads; most learn git on the job. Two common gaps are not knowing what `.gitignore` must exclude and not knowing that git history is effectively permanent. | The safe path must be the default path. A contributor should not have to know that `git rm` does not remove a secret from history in order to be protected. |
| 3 | **Heterogeneous workstations.** Students develop on personal laptops with no mobile device management (MDM), different operating systems, and unmanaged git configurations. | No organization-managed developer environment exists. The central pre-commit templates in `oss_cicd_automation` are opt-in and must be installed by each student on each machine [8]. | No local control can be assumed to be present. The local layer helps, but the push boundary must catch what a laptop misses. |
| 4 | **Dual-target architectures.** Open-source code is deployed to live, production infrastructure. | Project applications are built by the central SLSA workflow, pushed to the organization's on-premises Harbor registry with robot-account credentials, and deployed to the organization's Kubernetes cluster through a shared manifests repository, updated by a personal access token with write access [8][9]. | The same public repository that a new student commits to also feeds production. A leaked deployment credential is a path into shared infrastructure, not just one project. |
| 5 | **Public by default.** Repositories are public so that partners, students, and the community can use the code. | All 22 candidate repositories are public (§4). | Every push is a publication. Detection after the fact always comes too late to prevent exposure. |
| 6 | **Permission asymmetry.** A few people hold administrative rights; the security team and most contributors do not. | The secret scanning audit could not read results for any of the 22 candidates from a security-team account (§4). | Verification has to be designed into the governance model, through roles that let auditors see security data, rather than assumed. |

Companies solve most of these problems through employment: managed laptops, mandatory training, a security team with administrative access, and private code. Open-source foundations rely on long-term maintainers. A university program has neither. Its secret governance has to work **even when every contributor is new, every laptop is unmanaged, and every repository is public**. That is the reason for the zero-trust starting point of the model that follows.

---

## 3. The Zero-Trust Secret Lifecycle Model

### 3.1 Design Principles

The model rests on four principles:

1. **No stage is trusted.** Each stage assumes that the stage before it has failed. A laptop may have no hooks installed, a push may be bypassed, and a workflow may be misconfigured. Each layer must stand on its own.
2. **Prevent before you detect.** Controls that stop a secret before it is published are preferred over controls that report it afterward. Detection remains essential, but only as the next layer.
3. **Least privilege everywhere a secret lives.** Every token, robot account, and service credential should be able to do exactly one job, so that a leak at any stage has a small blast radius.
4. **Revocation is the remedy.** When a secret is exposed, the response is to revoke or rotate it. Deleting it from a file or rewriting history is cleanup, not remediation.

### 3.2 The Four Stages

```mermaid
flowchart LR
    A["Stage 1<br/>Pre-Commit<br/>(developer laptop)"] --> B["Stage 2<br/>Push Boundary<br/>(GitHub ingestion)"]
    B --> C["Stage 3<br/>CI/CD and<br/>Central Automation"]
    C --> D["Stage 4<br/>Runtime and<br/>In-Cluster Secrets"]
```

| Stage | Where | Trust assumption | Primary controls | What it cannot catch |
|---|---|---|---|---|
| 1. Pre-Commit | Student's laptop | The laptop is unmanaged, and hooks may not be installed | `.env.example` templates, local secret scanning hooks | Any machine without the hook; secrets added with `--no-verify` |
| 2. Push Boundary | GitHub, as the push is received | The contributor may not have Stage 1 | Organization-wide Push Protection with approval-only bypass | Secrets that match no supported pattern; approved bypasses |
| 3. CI/CD | GitHub Actions and central workflows | Any workflow may be compromised or misconfigured | Read-only `GITHUB_TOKEN` by default; centralized reusable workflows for sensitive steps; secret scanning on every pull request | Secrets already in use at runtime |
| 4. Runtime | The Kubernetes cluster and the registry | Any running workload may be compromised | Encrypted secrets in git (SealedSecrets or SOPS); scoped robot accounts | Compromise of the decryption key or the cluster itself |

### 3.3 Stage 1: Pre-Commit (Local Developer Environment)

**Threat.** A contributor stages a `.env` file, a test credential, or a key file along with their code.

**Controls.**

- **Mandatory `.env.example` templates with sanitized placeholders.** Every project that reads configuration from the environment ships a committed `.env.example` that lists each variable with a placeholder value (for example, `DATABASE_URL=postgres://user:password@localhost:5432/dev`), while `.env` itself is listed in `.gitignore`. A new contributor copies the example to `.env` and fills in real values locally. This makes the safe path the obvious path: the file that is meant to be committed and the file that must never be committed have different names.
- **Pre-commit hooks running locally before commits are formed.** A secret scanner such as `gitleaks`, installed through the `pre-commit` framework or a plain git hook, scans the staged diff and refuses to create the commit if it finds a secret. OSS-SLU already maintains a general pre-commit template with a Gitleaks hook in `oss_cicd_automation` [8].

**Limits.** Hooks run only on machines where they are installed, and a contributor can skip them with `git commit --no-verify`. On unmanaged laptops (§2), Stage 1 reduces mistakes but cannot be relied on. That is why Stage 2 exists.

### 3.4 Stage 2: Pre-Receive / Ingestion Gate (The Push Boundary)

**Threat.** A commit containing a secret reaches GitHub, from a laptop with no hook or after a hook was skipped.

**Controls.**

- **GitHub Push Protection as an organization-wide gate.** Push Protection scans each push as GitHub receives it and blocks pushes that contain supported secrets, so the secret never enters the repository's history [10]. It must be enabled through the organization's security configuration, so that every existing and new repository is covered, rather than repository by repository. It is free for public repositories [11].
- **Restricting overrides to Tech Lead approval.** By default, anyone with write access can bypass a Push Protection block by giving a reason [12]. **Delegated bypass** replaces this with a review cycle: contributors who are not on the bypass list must submit a bypass request, which designated reviewers approve or deny, and requests expire after seven days [12][13]. For OSS-SLU, the bypass list should contain the security team and each project's Tech Lead, and nobody else.

**Limits.** No gate is truly unbypassable. Organization owners and security managers can always bypass Push Protection [13], and Push Protection only recognizes supported patterns. Private keys and connection strings, for example, are non-provider patterns that must be enabled separately [14]. The aim of Stage 2 is that every bypass is **deliberate, approved, and recorded**, not that bypass is impossible.

### 3.5 Stage 3: CI/CD and Central Automation

**Threat.** A secret slips past Stages 1 and 2, or a workflow with broad permissions is used to steal or misuse the credentials that CI holds.

**Controls.**

- **Least privilege for repository tokens.** Organization administrators can set the default `GITHUB_TOKEN` permissions to **restricted**, which gives workflows read-only access to repository contents and no access to other scopes unless a workflow asks for them explicitly [15]. Each workflow then declares only the permissions it needs in a `permissions:` block. OSS-SLU's central workflows already follow this pattern: the reusable secret scanning workflow runs with `contents: read`, and the SLSA build workflow adds only `id-token: write` for signing [8].
- **Secret scanning on every pull request.** OSS-SLU's reusable Gitleaks workflow scans the full commit history of each pull request and fails the check when it finds a secret [8]. This is a detection control: in a public repository the commit is already visible once it is pushed. But it catches secrets that Push Protection does not recognize, before they reach `main`, and it acts as the "automated PR secret scanning check" in §7.
- **Centralized reusable workflows for sensitive deployments.** Steps that handle high-value credentials, such as building, signing, and pushing images to the Harbor registry, should run only in reviewed, central reusable workflows (the SLSA Build Level 3 workflow in `oss_cicd_automation`), not in each project's own workflow files [8]. Project repositories should call those workflows by tag or commit SHA, and pass only the specific secrets each one needs rather than `secrets: inherit`, which forwards every secret the caller has.
- **Short-lived credentials over long-lived ones.** Where a platform supports OpenID Connect (OIDC), workflows should exchange the job's identity token for short-lived credentials instead of storing long-lived keys as secrets. Long-lived personal access tokens with write access to shared repositories, such as the token that updates the shared Kubernetes manifests repository [9], should be replaced with narrowly scoped tokens or GitHub Apps and rotated at every semester boundary.

**Limits.** CI controls cannot protect a secret once it is deployed and in use. That is the role of Stage 4.

### 3.6 Stage 4: Runtime and In-Cluster Secrets Management

**Threat.** Deployment configuration containing credentials is committed to a repository, or a running workload's credentials are used to reach more of the infrastructure than it needs.

**Controls.**

- **SealedSecrets or SOPS instead of raw plaintext manifests.** A Kubernetes `Secret` manifest is not encrypted: its values are only base64-encoded, and the Kubernetes documentation warns that base64 is not an encryption method and provides no confidentiality over plain text [16]. A `ConfigMap` offers even less. Credentials must therefore never be committed as plain `Secret` or `ConfigMap` manifests. **Bitnami SealedSecrets** encrypts each secret with a key held only by a controller inside the cluster, so the encrypted `SealedSecret` can be committed safely and is decrypted only in the cluster [17]. **SOPS** encrypts the values in YAML or JSON files with keys from a key management service, age, or PGP [18]. Either approach allows GitOps deployment from a public or shared repository without publishing credentials. The cluster should also enable encryption at rest for Secrets in etcd, which Kubernetes does not do by default [16].
- **Isolated Harbor robot accounts with scoped permissions.** Each project should push to the registry with its own robot account, limited to push and pull on that project's repository only, never with a Harbor administrator credential [19]. OSS-SLU's SLSA workflow already uses per-project push robots (for example, a `robot$<project>+push` account) [8]. The same rule applies to cluster service accounts: one account per workload, with only the permissions that workload needs.

**Limits.** Stage 4 depends on the security of the cluster's decryption keys and administrative access. These are protected by the organization's infrastructure controls, which are outside the scope of this paper.

### 3.7 How the Stages Work Together

No single stage is sufficient, and each covers a failure of the one before:

| Failure | Caught by |
|---|---|
| Student's laptop has no pre-commit hook | Stage 2: Push Protection blocks the push |
| Secret is in a format Push Protection does not recognize | Stage 3: Gitleaks fails the pull request check before merge |
| A workflow is compromised | Stage 3: a read-only token and per-workflow secrets limit what it can reach |
| A deployment credential is committed in a manifest | Stage 4: only encrypted SealedSecrets or SOPS files are accepted in deployment repositories |
| A credential leaks anyway | Revocation (§5.2): the credential is rotated, and scoped accounts limit the damage |

---

## 4. Evidence and Baseline from OSS-SLU (Fall 2026)

### 4.1 Data Sources

The baseline combines three sources, all collected on November 23, 2026:

- **The secret scanning audit.** `scripts/audit_secret_scanning.sh` was run against the 22 candidate repositories from a security-team account (a member of the organization without repository admin rights), and against the test repository `sprabhnoor/secret-scan-test` with administrator access. The full analysis is in the companion case study [6].
- **The Security Controls Inventory and Risk Register** [7][20], which record what the organization expects of each control.
- **A read-only scan of repository files.** The default branch of each candidate was cloned without checking out code, and git metadata was used to check for the files that Stages 1 and 3 depend on: `.gitignore` rules for `.env`, `.env.example` templates, pre-commit configurations, secret scanning steps in workflows, and workflow `permissions:` blocks. Committed environment files were inspected by variable name only; no secret values were copied or recorded.

### 4.2 What the Organization Expects

| Document | What it says about secrets |
|---|---|
| Risk Register, R-01 [7] | Committed secrets are the first listed risk. The existing protection is GitHub Secret Scanning; the Incident Response Plan requires same-day rotation or revocation. Follow-up: confirm Secret Scanning is enabled on all active repositories. |
| Risk Register, R-05 [7] | Members must not hold more access than their role needs, including access to secrets and security alert dashboards. |
| Security Controls Inventory [20] | GitHub Secret Scanning is "Expected; whether it's enabled on all active repos is TBD." Individual repository security settings were not checked. Where Tier 3 access grants (including secrets) are logged is also TBD. |

The documents name only one technical control for secrets, Secret Scanning, which is a detection control at the end of Stage 2. None of the other layers in the model (§3) is yet part of documented policy.

### 4.3 Baseline by Stage

| Stage | Measure | Fall 2026 baseline |
|---|---|---|
| **Exposure** | Candidate repositories that are public | **22 / 22** |
| **1. Pre-Commit** | Repositories whose `.gitignore` excludes `.env` | **18 / 22**. Two more ignore only `.env.*.local` variants, which does not cover a plain `.env` file; two have no environment-file rule |
| | Repositories with a committed `.env.example` (or similar) template | **7 / 22** |
| | Repositories with a pre-commit configuration that runs a secret scanner | **0 / 22** (no candidate has a pre-commit configuration) |
| **2. Push Boundary** | Candidates whose Secret Scanning and Push Protection status the security team could read | **0 / 22** ("Permission Required" for all) |
| | Secret Scanning / Push Protection on the readable testbed | Enabled / **Disabled** |
| **3. CI/CD** | Repositories running a secret scanning check on pull requests | **0 / 22**, although a central reusable Gitleaks workflow exists [8] |
| | Workflow files that declare a top-level `permissions:` block | **45 / 80** (56%); all workflows declare one in **8 / 22** repositories |
| **4. Runtime** | Encrypted secret manifests (SealedSecrets or SOPS) in deployment repositories | **Not measurable**: the deployment manifests repository is not public |

Two results stand out. First, every layer that runs **automatically** for the whole organization (Push Protection and Secret Scanning) is unverifiable, and every layer that depends on **each repository opting in** (pre-commit hooks, PR scanning) has zero adoption. Second, OSS-SLU already **owns the tools** for both Stage 1 and Stage 3: a pre-commit template with Gitleaks and a reusable PR secret scanning workflow [8]. The gap is adoption, not capability.

### 4.4 Committed Environment Files

Four of the 22 candidates track a total of five environment files (named `.env.*`, excluding examples) on their default branch. Inspected by variable name and value shape only:

- Most contain **configuration that is not secret**: feature flags, build options, and OAuth client IDs, which are public by design.
- Several values appear to be **local test values** used by development or end-to-end test containers, for example database URLs that point to a local container.
- At least two files contain variables for **signing secrets or service tokens** whose values are not obviously placeholders. Whether those values are live cannot be determined from the files alone.

None of these files is necessarily a leak. They do show that the line between "configuration that is safe to commit" and "secrets" is currently drawn by each project, by hand. The `.env.example` convention (§3.3) makes that line explicit: real values go in an ignored `.env`, and only placeholders are committed. Each value that is not obviously a placeholder should be reviewed by its project's Tech Lead and, if it is real, rotated (§5).

### 4.5 Why Post-Hoc Deletion Fails Without History Purging

When a secret is found in a repository, the intuitive fix is to delete it and commit the change. That fix does almost nothing:

- **The secret stays in history.** `git rm` or an edit removes the secret from the latest version of the file, but every earlier commit still contains it, and anyone can check out or view those commits.
- **Purging history is not enough either.** History can be rewritten with tools such as `git filter-repo` or the BFG Repo-Cleaner, but GitHub documents that the secret can still be reached in any clones or forks, directly through cached views of the old commit hashes, and through pull requests that reference them [21]. Forks remain accessible until their owners clean them, and a collaborator with an old clone can push the secret back simply by pulling and pushing [21].
- **Purging can make it worse.** A history rewrite changes commit hashes, so anyone with an older clone can compare the two histories and find exactly what was removed [21].

GitHub's own guidance is therefore that **the first step is to revoke or rotate the secret**, and that GitHub Support will only help remove data when the risk cannot be mitigated by rotating the affected credentials [21]. Rotation makes the leaked copy worthless wherever it has spread. Purging history is optional cleanup after that. For OSS-SLU, this means the response process (§5) must be built around **who can revoke each credential**, not around who can edit the repository.

### 4.6 Summary of Gaps

| # | Gap | Stage | Addressed in |
|---|---|---|---|
| G1 | Secret Scanning and Push Protection status is unverifiable by the security team (0 / 22 readable) | 2 | §5.1 RACI, §7 Phase 1 |
| G2 | Push Protection is not documented or enforced as a required control; the readable testbed has it disabled | 2 | §5.2 MUST, §7 Phase 2 |
| G3 | No candidate runs a pre-commit secret scanner, and only 7 / 22 ship a `.env.example` | 1 | §5.2 MUST/SHOULD |
| G4 | Four candidates do not ignore a plain `.env` file | 1 | §5.2 MUST |
| G5 | No candidate calls the central PR secret scanning workflow | 3 | §5.2 SHOULD, §7 Phase 2 |
| G6 | 35 of 80 workflow files rely on the default token permissions instead of declaring their own | 3 | §5.2 MUST |
| G7 | Committed environment files mix configuration and possible secrets, with no review process | 1, 4 | §4.4, §5.2 MUST |
| G8 | No documented, time-bounded process for exceptions or for revoking leaked credentials | All | §5.2, §5.3 |

---

## 5. Governance and Operational Policy for OSS-SLU

A layered model only works if each layer has an owner. This section assigns those owners, sets the rules, and defines how rules can be set aside safely.

### 5.1 RACI Matrix

**R** = Responsible (does the work) · **A** = Accountable (owns the outcome; one per activity) · **C** = Consulted · **I** = Informed

| Activity | Student Developers | Tech Leads | Security Audit Leads | Faculty Advisors |
|---|---|---|---|---|
| Keep real secrets in an ignored `.env`; commit only `.env.example` | **R** | **A** | I | — |
| Install and run the pre-commit secret hook | **R** | **A** | C | — |
| Add `.env` rules, `.env.example`, and the PR secret scanning workflow to each repository | C | **R/A** | C | — |
| Enable Push Protection and Secret Scanning organization-wide | — | I | **R** | **A** |
| Maintain the delegated bypass list | — | C | **R/A** | I |
| Approve or deny a Push Protection bypass request | I | **R** | **A** | — |
| Run the semester audit (`audit_secret_scanning.sh`) and publish the matrix | — | I | **R/A** | I |
| Triage a secret scanning alert | I | **R** | **A** | I |
| Revoke or rotate a leaked credential | C | **R** | **A** | I |
| Approve an exception to this policy | C | **R** (requests) | **A** | I |
| Grant and review the security manager role and other Tier 3 access | — | — | C | **A** |
| Rotate shared credentials at the semester boundary | — | **R** | **A** | I |

Two notes on the matrix:

- **Organization-level settings** (security configurations, the bypass list, and roles) are changed by an organization owner. The Faculty Advisor is accountable for those changes, and the Security Audit Lead carries them out or requests them.
- **Revocation is owned by whoever can revoke.** A Tech Lead usually holds, or knows who holds, the account that issued a project's credential. The Security Audit Lead is accountable for making sure it happens the same day, as the Incident Response Plan requires.

### 5.2 Three-Tier Policy Framework

The policy uses the requirement levels of RFC 2119 [22]: **MUST** is an absolute requirement, **SHOULD** is expected unless there is a documented reason not to, and **MAY** is optional.

**MUST: required for every active repository**

| # | Requirement | Stage | Closes gap |
|---|---|---|---|
| M1 | **Push Protection is enabled** on all repositories through the organization's security configuration, with delegated bypass limited to Tech Leads and the security team. | 2 | G1, G2 |
| M2 | **`.env` is listed in `.gitignore`** (as `.env` or `*.env`, not only `.env.*.local`), and real configuration values live only in that ignored file. | 1 | G4, G7 |
| M3 | **Leaked secrets are revoked immediately upon detection**: acknowledged at once and rotated or revoked the same day, before any history cleanup, as required by the Incident Response Plan. Tokens with enterprise access are escalated immediately. | All | G8 |
| M4 | **Every workflow declares a `permissions:` block** with only the scopes it needs, and the organization's default `GITHUB_TOKEN` permission is set to restricted (read-only). | 3 | G6 |
| M5 | **No plaintext credentials in deployment manifests.** Kubernetes secrets are committed only as SealedSecrets or SOPS-encrypted files. | 4 | G7 |

**SHOULD: expected unless an exception is recorded**

| # | Requirement | Stage | Closes gap |
|---|---|---|---|
| S1 | **Pre-commit hooks are installed**, using the Gitleaks template in `oss_cicd_automation`, and documented in each project's contributing guide. | 1 | G3 |
| S2 | **A committed `.env.example`** lists every required variable with a placeholder value. | 1 | G3 |
| S3 | **Pull requests run the central secret scanning workflow**, pinned to a tag or commit SHA. | 3 | G5 |
| S4 | **Dummy token integration tests in CI**: once per semester, a test repository attempts to push a commit containing a well-known example token in a supported format, and the test passes only if the push is **blocked**. The same test checks that the PR secret scan fails on a committed dummy secret. | 2, 3 | G2, G5 |
| S5 | **Reusable workflows receive only the secrets they need**, passed by name rather than with `secrets: inherit`. | 3 | — |
| S6 | **Long-lived tokens are replaced** with OIDC, GitHub Apps, or fine-grained tokens with expiry, and any that remain are rotated at each semester boundary. | 3 | — |

**MAY: optional good practice**

| # | Practice |
|---|---|
| Y1 | **Local encrypted vault tooling.** Contributors may keep development secrets in a local encrypted store, such as their operating system's keychain, a password manager's command-line tool, or `sops`-encrypted local files, instead of a plaintext `.env`. |
| Y2 | Projects may add custom Gitleaks rules (`.gitleaks.toml`) for secret formats specific to their stack. |
| Y3 | Projects may enable non-provider pattern detection (private keys, connection strings) for their repository ahead of an organization-wide rollout. |

### 5.3 Exceptions Process

Some legitimate work conflicts with the policy: a security test that needs a real-looking token, a test fixture that matches a secret pattern, or a migration that cannot meet a MUST before a deadline. Exceptions are allowed, but they must be **requested, logged, and time-bounded**:

1. **Request.** The Tech Lead opens an issue in `oss_cybersecurity` using an exception label. The issue states the repository, the requirement being set aside, the reason, the compensating control (for example, a scoped dummy credential with no real access), and the requested end date.
2. **Review.** A Security Audit Lead approves or declines the request within one week. An exception to M3 (immediate revocation) is never granted.
3. **Log.** Approved exceptions are recorded in a single exceptions register in this repository, which addresses the open "TBD" for where grants and deviations are logged in the Security Controls Inventory [20]. For Push Protection, the approved bypass is also recorded by GitHub itself.
4. **Time-bound.** Every exception expires at the **end of the current semester** at the latest. Testing exceptions expire when the test ends. Expiry is checked during the semester audit.
5. **Renew or close.** An exception that is still needed must be requested again by the new Tech Lead. Nothing carries over silently from one cohort to the next, which keeps the policy aligned with the Semester Clock (§2).

---

## 6. Framework Alignment

The model is designed to put OSS-SLU's practice in line with established standards, so that the organization can show its secret governance against criteria that partners and funders recognize.

The same direction is set by U.S. government guidance: CISA and the FBI list hardcoded credentials in source code as a product security bad practice, and recommend secrets management tools together with scanning to detect secrets in code [29].

### 6.1 NIST Secure Software Development Framework (SP 800-218)

| SSDF task | Task (NIST wording) | How the model meets it |
|---|---|---|
| **PO.3.2** (Implement Supporting Toolchains) | "Follow recommended security practices to deploy, operate, and maintain tools and toolchains." [23] | Stage 3: restricted `GITHUB_TOKEN` defaults and per-workflow `permissions:` (M4); sensitive steps only in central, pinned, reviewed reusable workflows; secrets passed by name, not inherited (S5); short-lived OIDC credentials over long-lived tokens (S6). Stage 4: per-project Harbor robot accounts. |
| **PW.1.1** (Design Software to Meet Security Requirements and Mitigate Security Risks) | "Use forms of risk modeling – such as threat modeling, attack modeling, or attack surface mapping – to help assess the security risk for the software." [23] | §2 and §3 are a threat model of the secret lifecycle: each stage names its threat, trust assumption, and residual risk. Risk R-01 is the register entry it supports. |
| **PW.1.2** | "Track and maintain the software's security requirements, risks, and design decisions." [23] | The MUST/SHOULD/MAY policy (§5.2) records the requirements; the gap table (§4.6) and the semester audit (§7) track them; the exceptions register (§5.3) records deviations and design decisions. |
| **PW.2.1** (Review the Software Design to Verify Compliance with Security Requirements and Risk Information) | "Have 1) a qualified person (or people) who were not involved with the design and/or 2) automated processes instantiated in the toolchain review the software design to confirm and enforce that it meets all of the security requirements and satisfactorily addresses the identified risk information." [23] | Automated: Push Protection, the PR secret scanning workflow, and the semester dummy token test (S4) enforce the requirements in the toolchain. Human: the Security Audit Leads, who do not build the projects, run the semester audit and approve exceptions (§5.1). |

### 6.2 OpenSSF Scorecard

OpenSSF Scorecard automatically scores a repository's security practices with a set of heuristic checks [24]. Scorecard has **no check for committed secrets**, so it cannot confirm Stages 1 or 2. That gap is covered by OSPS Baseline control **OSPS-BR-07.01**, which requires a project to prevent the unintentional storage of secrets and credentials in version control [25]. The three checks named below protect the secrets that CI holds:

| Scorecard check | What it checks [24] | How the model meets it |
|---|---|---|
| **Token-Permissions** (risk: High) | Whether workflows declare the `GITHUB_TOKEN` as read-only by default | M4: every workflow declares a top-level `permissions:` block with read-only defaults. Baseline: 45 of 80 workflow files declare one today (§4.3). |
| **Dangerous-Workflow** (risk: Critical) | Dangerous GitHub Actions patterns, such as `pull_request_target` or `workflow_run` workflows that check out untrusted pull request code, and untrusted input used in scripts | Stage 3: these patterns can expose a repository's secrets and write token to code from a fork. Sensitive steps run only in central, reviewed workflows; project workflows that use `pull_request_target` must not check out pull request code. |
| **Vulnerabilities** (risk: High) | Whether the project has unfixed known vulnerabilities, using the OSV database | Indirect. This check is about known vulnerabilities in code and dependencies, not secrets. It matters here because a vulnerable or compromised dependency running in CI can read every secret available to that job, so it supports least privilege in Stage 3 rather than replacing it. |

### 6.3 SLSA

SLSA (Supply-chain Levels for Software Artifacts) version 1.0 defines a Build track with levels 1 to 3 [26]. The issue that commissioned this paper asks for "hermetic, authenticated builds without leaked secrets." Two clarifications keep that alignment accurate:

- **Authenticated builds.** At Build L3, any secret material used to authenticate provenance, such as the signing key, must be stored in a secure management system, must be accessible only to the build service account, and must not be accessible to the environment running the user-defined build steps [27]. That is the same principle as Stage 3 of this model: a build's own code must never be able to read the credentials that vouch for it. OSS-SLU's central SLSA workflow meets this by signing with a short-lived OIDC identity (`id-token: write`) instead of a stored key [8].
- **Hermetic builds.** "Hermetic" (a build with no network access and fully declared inputs) was a Level 4 requirement in SLSA v0.1. SLSA v1.0 deferred it to a future version [28]. The model therefore treats hermeticity as a direction of travel, not a current requirement. Its secret-related benefit, that a build cannot fetch or leak credentials it was not explicitly given, is approximated by passing secrets by name (S5) and keeping registry credentials scoped to one project (§3.6).

### 6.4 Summary

| Stage | NIST SSDF | OpenSSF | SLSA |
|---|---|---|---|
| 1. Pre-Commit | PW.1.2 (requirements tracked as policy) | OSPS-BR-07.01 | — |
| 2. Push Boundary | PW.2.1 (automated enforcement) | OSPS-BR-07.01 | — |
| 3. CI/CD | PO.3.2 | Token-Permissions, Dangerous-Workflow, Vulnerabilities | Build L3 secret isolation |
| 4. Runtime | PO.3.2 | OSPS-BR-07.01 | Scoped registry credentials |
| Governance | PW.1.1, PW.1.2, PW.2.1 | — | — |

---

## 7. Roadmap, Metrics and Conclusion

### 7.1 Phased Rollout

The rollout is ordered so that each phase makes the next one measurable. Enforcing a control the organization cannot see would repeat the problem in §4.

**Phase 1: Audit and Baseline (December 2026 to start of Spring 2027)**

| Action | Owner | Done when |
|---|---|---|
| Grant the organization security manager role to the Security Audit Leads, recorded as a Tier 3 grant | Faculty Advisor (A), Security Audit Lead (R) | `audit_secret_scanning.sh` returns 0 "Permission Required" |
| Run the full audit and commit the first readable compliance matrix | Security Audit Lead | Real Secret Scanning and Push Protection rates published for all 22 candidates |
| Run a full-history Gitleaks scan of all 22 candidates and record findings privately | Security Audit Lead | Every finding is assigned to a Tech Lead |
| Review the committed environment files from §4.4; rotate any live values | Tech Leads | Each file is confirmed as placeholders only, or its values are rotated |
| Update R-01 in the Risk Register to name Push Protection as well as Secret Scanning | Security Audit Lead | Register merged |

**Phase 2: Push Protection Enforcement (Spring 2027)**

| Action | Owner | Done when |
|---|---|---|
| Apply an organization security configuration enabling Secret Scanning, Push Protection, and non-provider patterns on all repositories | Faculty Advisor (A), Security Audit Lead (R) | 22 / 22 enabled in the audit matrix |
| Enable delegated bypass with Tech Leads and the security team on the bypass list | Security Audit Lead | Bypass list documented; first request reviewed |
| Set the organization's default `GITHUB_TOKEN` permission to restricted | Organization owner | Setting confirmed |
| Add `.env` rules, `.env.example`, the pre-commit template, and the PR secret scanning workflow to every candidate, and to the new-project template | Tech Leads, CI/CD team | Repository file scan (§4.3) shows each measure at 22 / 22 |
| Run the first dummy token test (S4) | Security Audit Lead | A blocked push and a failed PR check are recorded |

**Phase 3: Automated Rotation (late Spring 2027 onward)**

| Action | Owner | Done when |
|---|---|---|
| Replace long-lived personal access tokens in CI with GitHub Apps, OIDC, or fine-grained tokens with an expiry date | CI/CD team, Tech Leads | No CI secret without an expiry or owner |
| Give every Harbor robot account and service credential an expiry date and a named owner | CI/CD team | Credential inventory complete |
| Add a scheduled workflow that lists credentials nearing expiry and opens rotation issues at each semester boundary | Security Audit Lead, CI/CD team | First automated rotation issues opened |
| Move remaining deployment secrets to SealedSecrets or SOPS, and enable encryption at rest in the cluster | Infrastructure maintainers | No plaintext `Secret` manifests in deployment repositories |

### 7.2 Measurable Targets for Spring 2027

| Metric | Fall 2026 baseline | Spring 2027 target | Measured by |
|---|---|---|---|
| **Push Protection coverage** | Unknown (0 / 22 readable) | **100% (22 / 22)** | `audit_secret_scanning.sh` |
| **Committed secrets across all 22 repositories** | Unknown | **0** (0 open Secret Scanning alerts and 0 unresolved Gitleaks findings) | Audit matrix and full-history Gitleaks scan |
| Candidates readable by the security team | 0 / 22 | 22 / 22 | `audit_secret_scanning.sh` |
| `.gitignore` excludes `.env` | 18 / 22 | 22 / 22 | Repository file scan |
| `.env.example` present (where the project uses environment variables) | 7 / 22 | 22 / 22 | Repository file scan |
| Pre-commit secret hook configured | 0 / 22 | 22 / 22 | Repository file scan |
| PR secret scanning check | 0 / 22 | 22 / 22 | Repository file scan |
| Workflow files declaring `permissions:` | 45 / 80 (56%) | 100% | Repository file scan |
| Leaked credentials revoked the same day | Not tracked | 100% of incidents | Incident log |
| Dummy token test (S4) | Not run | Passed once per semester | Test repository record |

### 7.3 Conclusion

The central claim of this paper is that university open-source programs cannot protect their secrets by trusting any single place in the development path. The student's laptop is unmanaged. The repository is public. The pull request arrives after the push. The CI runner executes code from contributors who may have joined last week. In that setting the only reliable design is **defense-in-depth in which every stage checks for itself**: pre-commit hooks and `.env.example` templates on the laptop, Push Protection at the push boundary, least-privilege tokens and central workflows in CI, and encrypted, scoped credentials at runtime.

The Fall 2026 evidence from Open Source with SLU shows both why this matters and how close the organization already is. All 22 candidate repositories are public, the primary control for committed secrets cannot be verified by the team responsible for it, and the opt-in layers have no adoption yet. But the organization already owns most of the tooling the model requires (an audit script, a pre-commit template with Gitleaks, a reusable PR secret scanning workflow, a SLSA build workflow with keyless signing, and per-project registry robots), and the controls GitHub provides are free for every one of its repositories. The gap is governance: clear owners, a small set of firm rules, and a measurement loop that survives the Semester Clock. The RACI matrix, three-tier policy, exceptions process, and phased roadmap in this paper are designed to close that gap by Spring 2027.

---

## References

[1] M. Meli, M. R. McNiece, and B. Reaves, "How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories," *Network and Distributed System Security Symposium (NDSS)*, 2019. https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/

[2] GitGuardian, *The State of Secrets Sprawl 2026*, March 2026. https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/

[3] Palo Alto Networks Unit 42, "EleKtra-Leak Cryptojacking Campaign Targets AWS IAM Credentials Exposed on GitHub," October 2023. https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/

[4] TechCrunch, "Toyota says customer data exposed for five years after access key left on GitHub," October 2022. https://techcrunch.com/?p=2423591

[5] OSS-SLU Security, [Cybersecurity Governance for University Open-Source Programs](cybersecurity_governance_white_paper.md) (white paper), November 2026.

[6] OSS-SLU Security, [Case Study: Secret Scanning and Push Protection, Fall 2026](../case_studies/secret_scanning_push_protection_case_study_fall2026.md).

[7] OSS-SLU Security, [Security Risk Register](../risk_assessment.md) (R-01, R-04, R-05, R-14).

[8] OSS-SLU CI/CD, `oss_cicd_automation`: reusable secret scanning workflow, pre-commit templates, and SLSA build and attestation workflow. https://github.com/oss-slu/oss_cicd_automation

[9] OSS-SLU CI/CD, Kubernetes deployment documentation for DigitalBoneBox and PAO Surgery Simulator, `oss_cicd_automation/Docs/`. https://github.com/oss-slu/oss_cicd_automation/tree/main/Docs

[10] GitHub Docs, "About push protection." https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection

[11] GitHub Docs, "Choosing GitHub Secret Protection." https://docs.github.com/en/enterprise-cloud@latest/code-security/securing-your-organization/understanding-your-organizations-exposure-to-leaked-secrets/choosing-github-secret-protection

[12] GitHub Docs, "About bypass requests for push protection." https://docs.github.com/en/code-security/concepts/secret-security/about-bypass-requests-for-push-protection

[13] GitHub Docs, "Delegated bypass for push protection." https://docs.github.com/en/code-security/concepts/secret-security/delegated-bypass

[14] GitHub Docs, "Non-provider patterns." https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/non-provider-patterns

[15] GitHub Docs, "About the GITHUB_TOKEN" (default permissions, permissive vs. restricted). https://docs.github.com/en/actions/automating-your-workflow-with-github-actions/authenticating-with-the-github_token

[16] Kubernetes Documentation, "Good practices for Kubernetes Secrets." https://kubernetes.io/docs/concepts/security/secrets-good-practices/

[17] Bitnami Labs, *Sealed Secrets*. https://github.com/bitnami-labs/sealed-secrets

[18] CNCF, *SOPS: Secrets OPerationS*. https://github.com/getsops/sops

[19] Harbor Documentation, "Create Project Robot Accounts." https://goharbor.io/docs/main/working-with-projects/project-configuration/create-robot-accounts/

[20] OSS-SLU Security, [Security Controls Inventory](../security_controls_inventory.md).

[21] GitHub Docs, "Removing sensitive data from a repository." https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository

[22] S. Bradner, "Key words for use in RFCs to Indicate Requirement Levels," RFC 2119, IETF, March 1997. https://www.rfc-editor.org/rfc/rfc2119

[23] M. Souppaya, K. Scarfone, and D. Dodson, *Secure Software Development Framework (SSDF) Version 1.1*, NIST SP 800-218, February 2022, tasks PO.3.2, PW.1.1, PW.1.2, PW.2.1. https://doi.org/10.6028/NIST.SP.800-218

[24] OpenSSF, "Scorecard Checks" (Token-Permissions, Dangerous-Workflow, Vulnerabilities). https://github.com/ossf/scorecard/blob/main/docs/checks.md

[25] OpenSSF, *Open Source Project Security Baseline*, version 2026.08.28, control OSPS-BR-07.01. https://baseline.openssf.org/versions/2026-08-28

[26] SLSA, "Security levels," SLSA specification v1.0. https://slsa.dev/spec/v1.0/levels

[27] SLSA, "Producing artifacts: Build L3 requirements," SLSA specification v1.0. https://slsa.dev/spec/v1.0/requirements

[28] SLSA, "What's new in SLSA v1.0" (deferral of hermetic builds). https://slsa.dev/spec/v1.0/onepage

[29] CISA and FBI, *Product Security Bad Practices*, version 2.0, January 2025 (hardcoded credentials). https://www.cisa.gov/resources-tools/resources/product-security-bad-practices

---

## Appendix A: Reproducibility Commands

All commands use the GitHub CLI (`gh`), authenticated with `gh auth login`, and are run from the root of this repository. Results for A.1 and A.2 depend on the caller's access: a non-admin reproduces the "Permission Required" figures, and an organization owner or security manager sees the real settings.

**A.1 Secret scanning audit (§4.3, Stage 2).**

```bash
./scripts/audit_secret_scanning.sh
ORG=sprabhnoor OUT=/tmp/testbed_matrix.md ./scripts/audit_secret_scanning.sh secret-scan-test
```

**A.2 Permission barrier behavior (§4.3).** From a non-admin account, the first command prints `null` and the second prints `HTTP/2.0 404 Not Found`.

```bash
gh api repos/oss-slu/civickit --jq '.security_and_analysis'
gh api -i "repos/oss-slu/civickit/secret-scanning/alerts?state=open" 2>&1 | head -1
```

**A.3 Candidate visibility (§4.3, Exposure).**

```bash
for r in $(grep -v '^#' scripts/branch_protection_candidates.txt | awk 'NF{print $1}'); do
  printf '%-28s %s\n' "$r" "$(gh api repos/oss-slu/$r --jq .visibility)"
done
```

**A.4 Repository file scan (§4.3, Stages 1 and 3).** Clones each candidate's default branch without checking out or running any code, then reads git metadata only.

```bash
mkdir -p /tmp/cands && cd /tmp/cands
for r in $(grep -v '^#' "$OLDPWD/scripts/branch_protection_candidates.txt" | awk 'NF{print $1}'); do
  [ -d "$r" ] || git clone -q --depth 1 --no-checkout "https://github.com/oss-slu/$r" "$r"
  files=$(git -C "$r" ls-tree -r --name-only HEAD)
  ignore=$(for f in $(echo "$files" | grep '\.gitignore$'); do git -C "$r" show "HEAD:$f"; done \
           | grep -cxE '/?(\*\*/)?(\.env|\*\.env|\.env\*|\*\.env\*)/?')
  example=$(echo "$files" | grep -ciE '(^|/)\.env[._-]?(example|sample|template)')
  precommit=$(echo "$files" | grep -cE '(^|/)\.pre-commit-config\.ya?ml$')
  wf=$(echo "$files" | grep -cE '^\.github/workflows/.*\.ya?ml$')
  prscan=0; perms=0
  for f in $(echo "$files" | grep -E '^\.github/workflows/.*\.ya?ml$'); do
    t=$(git -C "$r" show "HEAD:$f")
    echo "$t" | grep -qE 'reusable-secret-scan|gitleaks|trufflehog' && prscan=1
    echo "$t" | grep -qE '^permissions:' && perms=$((perms+1))
  done
  printf '%-26s env_ignored=%s example=%s precommit=%s pr_scan=%s workflows=%s with_permissions=%s\n' \
    "$r" "$([ "$ignore" -gt 0 ] && echo yes || echo no)" "$([ "$example" -gt 0 ] && echo yes || echo no)" \
    "$([ "$precommit" -gt 0 ] && echo yes || echo no)" "$([ "$prscan" -eq 1 ] && echo yes || echo no)" "$wf" "$perms"
done
cd - >/dev/null
```

**A.5 Committed environment files (§4.4).** Lists tracked `.env.*` files that are not examples. Inspect values only privately, and never paste them into issues or chat.

```bash
for r in /tmp/cands/*; do
  git -C "$r" ls-tree -r --name-only HEAD | grep -E '(^|/)\.env(\.[^/]*)?$' \
    | grep -viE 'example|sample|template' | sed "s|^|$(basename "$r"): |"
done
```

**A.6 Organization default token permission (§5.2 M4, organization owner only).**

```bash
gh api orgs/oss-slu/actions/permissions/workflow --jq '.default_workflow_permissions'
```

A result of `read` means the restricted default is in place.

---

## Appendix B: Glossary of Terms

| Term | Definition |
|---|---|
| **Secret** | Any value that grants access to a system: API token, password, private key, database connection string, or signing key. |
| **Zero-trust** | A design principle in which no environment is trusted by default; each stage verifies for itself instead of relying on an earlier one. |
| **Defense-in-depth** | Layering independent controls so that a failure of one is caught by the next. |
| **Secret Scanning** | A GitHub feature that scans repository content and history for known secret patterns and raises alerts. A detection control. |
| **Push Protection** | A GitHub feature that blocks a push containing a supported secret before it enters the repository. A prevention control. |
| **Delegated bypass** | A Push Protection setting that requires contributors to request approval from a designated bypass list before pushing a blocked secret. |
| **Provider / non-provider pattern** | Provider patterns match a specific service's token format (for example, a cloud access key). Non-provider patterns match generic secrets such as private keys and connection strings, and are off by default. |
| **Pre-commit hook** | A script that runs on the developer's machine before a commit is created, and can refuse the commit. |
| **Gitleaks** | An open-source secret scanner used in OSS-SLU's pre-commit template and reusable PR workflow. |
| **`.env` / `.env.example`** | `.env` holds real local configuration and must be ignored by git. `.env.example` is a committed template with placeholder values. |
| **`GITHUB_TOKEN`** | A short-lived token GitHub Actions creates for each workflow job. Its permissions can be permissive or restricted (read-only) by default. |
| **Reusable workflow** | A GitHub Actions workflow defined once, in a central repository, and called by other repositories. |
| **OIDC (OpenID Connect)** | A standard that lets a workflow prove its identity and receive short-lived credentials instead of using a stored secret. |
| **Personal access token (PAT)** | A long-lived GitHub token tied to one person's account. |
| **Kubernetes Secret** | A Kubernetes object for sensitive data. Values are base64-encoded, not encrypted, unless encryption at rest is configured. |
| **SealedSecrets** | A Kubernetes controller and CLI that encrypt secrets so that only the target cluster can decrypt them, allowing encrypted secrets to be committed to git. |
| **SOPS** | A tool that encrypts values in YAML, JSON, and other files using KMS, age, or PGP keys. |
| **Harbor robot account** | A non-human Harbor registry account with permissions limited to specific projects and actions, such as push and pull. |
| **Rotation / revocation** | Replacing a credential with a new one (rotation) or disabling it permanently (revocation), so that a leaked copy no longer works. |
| **History purging** | Rewriting git history (for example, with `git filter-repo`) to remove a file or value. Cleanup only; it does not undo exposure. |
| **RACI** | Responsible, Accountable, Consulted, Informed: a matrix that assigns roles for each activity. |
| **SSDF** | NIST's Secure Software Development Framework (SP 800-218). |
| **OpenSSF Scorecard** | An automated tool that scores a repository's security practices with a set of checks. |
| **OSPS Baseline** | The OpenSSF Open Source Project Security Baseline, a set of security controls for open-source projects. |
| **SLSA** | Supply-chain Levels for Software Artifacts, a framework of levels for build integrity and provenance. |
| **Hermetic build** | A build with no network access whose inputs are all declared in advance. Deferred to a future version of SLSA. |
| **Semester Clock** | The 15-week cycle in which university teams onboard and offboard. |
