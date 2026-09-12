# Security Risk Register

------------------
## Purpose

This register lists common security risks affecting Open Source w/ SLU. It is a starting point for future security planning, not a complete assessment. Every risk below comes from the existing cybersecurity documentation in this repository (see [Sources](#sources)).

## How to Use This Register

Each risk records:

- ID: a stable identifier for referencing the risk in issues and discussions
- Risk: a short description of what could go wrong
- Affected area: the systems, repositories, or processes involved
- Existing protection: controls already in place, if known
- Priority: not yet assigned; marked TL review until the Tech Lead sets it
- Notes / follow-up: open questions, known gaps, and follow-up work

Items marked TL review need a priority or decision from the Tech Lead.

This register is public. Do not record details of specific unpatched vulnerabilities here. Those belong in the internal repository, per the Team Working Agreement.

## Register

| ID | Risk | Affected area | Existing protection | Priority | Notes / follow-up |
|---|---|---|---|---|---|
| R-01 | Secrets (API keys, tokens, passwords, private keys) are committed to a repository | All repositories | GitHub Secret Scanning. The Incident Response Plan requires immediate acknowledgement and same-day rotation or revocation, and immediate escalation for tokens with enterprise access. | TL review | TL review: confirm Secret Scanning is enabled on all active repositories. |
| R-02 | Dependencies with known vulnerabilities go unpatched | Active project repositories | Dependabot alerts. The Incident Response Plan requires review within one week. The target is fewer than 5 open alerts per active repository. | TL review | The roadmap notes that alert counts are rising. TL review: decide how alerts on inactive repositories are handled (accept, archive, or patch). |
| R-03 | Vulnerable code patterns in project code are missed or patched incorrectly | Active project repositories | Code Scanning alerts, triaged within 1–2 business days. Copilot autofixes must be reviewed with the project's Tech Lead before being applied. | TL review | Scanner findings are not definitive and can be false positives, so each one needs investigation before a fix. |
| R-04 | Former members keep access after leaving the organization | GitHub organization membership and repository permissions | SAML/Okta SSO is required for org members. The Access Control Policy requires removal within 48 hours of leaving, plus access reviews at semester start and end. | TL review | Sprint 2 SAML testing found that blocking a user at the IdP stops access to internal repositories but does not remove their org membership. Removal must be done explicitly. |
| R-05 | Members hold more access than their role needs, or access grants are not documented | Repository admin settings, security alert dashboards, secrets | The Access Control Policy requires least privilege and documented Tier 3 grants that lapse each semester. Grants outside a project boundary need security team approval. | TL review | TL review: decide where access grants and deviations are recorded. The policy requires a log but does not name a location. |
| R-06 | Outside collaborators get repository access that is not covered by SSO | Repositories with outside collaborators | Only org owners and repository admins can add outside collaborators. The Access Control Policy's least-privilege principle applies. | TL review | Per the SAML Impact Report, outside collaborators are added per repository without the IdP, so Okta revocation does not remove them. TL review: decide whether outside collaborators are explicitly included in semester access reviews. |
| R-07 | SAML or enterprise GitHub settings are misconfigured or changed without documentation | GitHub Enterprise and organization settings, SAML configuration | SAML configuration is a Tier 3 resource. Changes are made by the Security Team Lead in coordination with SLU ITS and must be documented. Undocumented org-wide changes count as deviations. | TL review | The Access Control Policy lists audit log review as a detection method. TL review: decide how often the audit log is reviewed and by whom. |
| R-08 | Security controls prevent outside contributions, costing the organization its open source compliance | Organization-wide access settings | Open source compliance is the first guiding principle of the Access Control Policy and the top priority in the Incident Response Plan. The SAML Impact Report confirmed fork-and-pull contributions still work under SAML. | TL review | Re-test the external contribution flow whenever SAML or enterprise settings change. |
| R-09 | Unreviewed or malicious changes reach a project's main branch | Active project repositories | External contributors use the fork-and-pull request flow and have no direct write access. Write access requires an explicit grant. This repository defines `CODEOWNERS` approval. | TL review | TL review: confirm required reviews and branch protection on active project repositories. This is not covered by current documentation. |
| R-10 | Vulnerability details are disclosed publicly before a fix is available | Vulnerability reporting process, team communication channels | `SECURITY.md` directs reports to private GitHub Security Advisories and asks reporters not to disclose publicly before a fix. Confidential discussion stays in the internal repository and internal Slack channel. Only the Security Team Lead communicates outward during an incident. | TL review | Advisories should be filed in this repository; reports filed elsewhere may be delayed. TL review: confirm every active project repository has a `SECURITY.md`. |
| R-11 | The team responds slowly or inconsistently to a real incident | Incident response process | The Incident Response Plan defines roles, response times, escalation paths, pause conditions, and incident log fields. | TL review | Gaps: the SLU ITS points of contact are "to be filled in," the response phases list topics rather than concrete steps, and no location is named for the incident log. |
| R-12 | Threat models are missing or out of date | Active projects, especially mission critical projects (e.g., GradEval360) | Projects in active development created threat models in a previous semester. The Access Control Policy and Incident Response Plan require a threat model for mission critical projects before external access is granted. | TL review | Reviewing project threat models is Iteration 2 roadmap work. TL review: confirm the current status of each project's threat model. |
| R-13 | The public-facing organization website is compromised or defaced | oss_slu_website | It is a static site with a lower attack surface. The Incident Response Plan prioritizes its alerts even though the project is inactive. | TL review | Public visibility means reputational impact even if a technical issue is minor. |
| R-14 | Security knowledge is lost or documentation goes stale as team members change each semester | Security team documentation in this repository | Documentation is published in this repository. The Access Control Policy and Incident Response Plan are reviewed each semester and after significant incidents. | TL review | Several documents are dated Spring 2026 and are due for their semester review. TL review: assign an owner for each document and confirm the contacts listed in the README are current. |

Disclosure: This issue was partially drafted with AI assistance and manually reviewed before pushing

Last updated 9/12/26 by Kysen Krishnaswamy
