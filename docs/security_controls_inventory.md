# Security Controls Inventory — Open Source w/ SLU

This document lists the security controls currently documented for Open Source w/ SLU, based
on the Access Control Policy, Incident Response Plan, Team Working Agreement, SAML Impact
Report, and Spring 2026 Roadmap. It's a starting point for future team members, not a full
audit — individual repository settings (branch protection, Secret Scanning toggles, etc.) were
not checked directly. Anything not confirmed against actual settings is marked TBD.

| Control | Description | Status |
|---|---|---|
| Three-tier resource classification (public, organizational, restricted) | Sets default access and authentication requirements by resource sensitivity | Documented |
| Role-based access model (external contributor, tech lead, security team member, etc.) | Defines what each role can access at each tier | Documented |
| Least privilege principle | Access should match assigned work, nothing more | Documented |
| Fork-and-pull model for external contributors | Lets outside contributors submit PRs without organization-level access | Documented |
| Tier 3 access grants (secrets, admin settings, SAML config) | Requires documented approval and semester renewal | Documented; where grants/deviations are actually logged is TBD |
| Mission-critical project controls (RBAC and Threat Model required) | Extra protections for important projects | Documented; current threat-model status is TBD |
| Access reviews (start of semester, end of semester, and after incidents) | Catches accounts no longer matching active members | Documented; whether outside collaborators are included is TBD |
| 48-hour offboarding requirement | Limits access window after a member leaves | Documented; not independently verified as followed |
| CODEOWNERS file | Maps file paths to required reviewers | Present in repo; does not by itself enforce review |
| Branch protection / required PR reviews | Stops unreviewed changes from reaching main | TBD — not covered by current documentation |
| SAML SSO | Centralizes identity verification for internal members | Tested in isolated test org; whether it's enforced on the live org is TBD |
| No SAML requirement for external contributors | Preserves ability to accept outside contributions | Documented, tested |
| GitHub Secret Scanning | Detects committed API keys, tokens, passwords | Expected; whether it's enabled on all active repos is TBD |
| GitHub Dependabot | Flags dependencies with known vulnerabilities | Documented; aim for fewer than 5 open alerts per active repo |
| GitHub Security Advisories | Private channel for outside researchers to report issues | Documented and active |
| GitHub Code Scanning | Flags code patterns resembling known vulnerabilities | Documented; requires tech lead review before patching |
| 7-phase incident response lifecycle | Structured process from detection through post-incident review | Documented |
| Escalation path to SLU ITS | Routes SAML or credential incidents to the right people | Documented; points of contact left blank in the source plan |
| Incident logging requirements | Standard fields to capture for every incident | Documented; whether a live log currently exists is TBD |
| Incident communication protocol | Controls who can speak externally during an active incident | Documented |
| Private communication (Slack and GitHub) | Keeps security discussion out of public channels | Documented |
| Document review (each semester and after incidents) | Keeps policies from going stale | Documented |
| Document ownership | Assigns accountability for keeping a document current | TBD — no owner assigned per document |
| NIST Cybersecurity Framework adoption | Would standardize existing controls into one framework | Not started |
