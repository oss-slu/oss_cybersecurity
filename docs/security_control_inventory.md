Security Controls Inventory — OpDownen Source w/ SLU
This document lists the security controls currently documented for Open Source w/ SLU, based on the Access Control Policy, Incident Response Plan, Team Working Agreement, SAML Impact Report, and Spring 2026 Roadmap. It's a starting point for future team members, not a full audit — individual repository settings (branch protection, Secret Scanning toggles, etc.) were not checked directly. Anything not confirmed against actual settings is marked TBD.

Controls
Description
Status
Three-tier resource classification (public, organization, restricted)
Sets default access and authentication requirement by resource sensitivity 
Documented 
Role-based access model like external contributor, tech lead, security team member, etc.
Defines what each role can access at each tier
Documented 
Least privilege principle
Access should match assigned work, nothing more
Documented
Fork-and-pull model for external contributors
Lets outside contributors submit PRs without organization level access
Documented
Tire 3 access grants (secrets, admin settings, SAML config)
Requires documented approval and semester renewal
Documented but where grants/deviation are actually logged is TBD
Critical project controls (RBAC and Threat model required)
Extra protections for important projects
Documented but TBD current threat-model status
Access reviews start to the end of semester and after incident
Its when they catches accounts no longer matching active members 
Documented; TBD whether outside collaborators are included
48-hour offboarding requirement
Limits access window after member leaves
Documented; not independently verified as followed
CODEOWNERS file
Maps file paths to require reviews 
Present in repo; does not by itself implement review
Branch protection / required PR reviews
Stops unreviewed changes from reaching main
TBD - not covered by current documentation 
SAML SSO 
Centralizes identity verification for internal members
Tested in isolated test org; TBD whether enforced on the live org
No SAML requirement for external contributors
Preserves ability to accept outside contributions
Documented, tested
Github secret scanning 
Detects committed AOP keys, tokens, passwords
Expected but TBD on whether enabled on all active repo 
Github Dependabot
Flags dependencies with known vulnerabilities 
Documented; aim for at less than 5 open alerts per active repo
Github security advisories
Private channel for outside researchers to report issues 
Documented and active


Github Code Scanning
Flags code patterns resembling known vulnerabilities
Documented; requires tech lead review before patching
7-phase incident response lifecycle
Structured process from detection through post-incident review
Documented


Escalation path to SLU ITS
Routes SAML or credentials incidents to the right people 
Documented; points of contacts left blank in the source plan
Incident logging requirements
Standard fields to capture for every incident
Documented; TBD whether a live log currently exists
Incident communication protocol
Controls who can speak externally during an active incident
Documented
Private Communication( Slack and github)
Keeps the security discussion out of the public channel
Documented
Document review in each semester and after incidents
Keeps policies from going stale
Documented
Document ownership 
Assigns accountability for keeping a document current
TBD - no owner assigned per document
NIST cybersecurity Framework adoption 
Would standardize existing controls into one framework
Not Started 


