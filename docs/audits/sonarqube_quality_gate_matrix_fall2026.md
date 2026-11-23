# SonarQube Quality Gate Matrix - Fall 2026

Audit of SonarCloud Quality Gate compliance and technical debt across candidate OSS SLU repositories.
*NOTE: As of November 22, 2026, SonarQube has deemed the concept of Security Hotspots as deprecated, meaning that Security Hotspots are no longer recorded in their own category, but have been merged into the Issues page, appearing as security issues or vulnerabilities.

| Repository | Project Key | Gate Status | Vulnerabilities | Security Hotspots | Technical Debt | Trend |
|------------|------------|------------|------------|------------|------------|------------|
| CivicKit | oss-slu_civickit | PASSED | 51 | 3 | 2h 42min | Decreasing |
| CoreDesk | oss-slu_core_desk | FAILED | 217 | 43 | 6h 27m | Increasing |
| cv_zebrafish | oss-slu_cv_zebrafish | PASSED | 19 | 6 | 53min | Increasing | 
| dads |oss-slu_dads | FAILED | 145 | 28 | 5h 25min | Decreasing |
| DigitalBoneBox | oss-slu_DigitalBoneBox | PASSED | 63 | 27 | 25min | Decreasing |
| enroll-dash | MISSING REPOSITORY | NOT CONFIGURED | TBD | TBD | TBD | TBD |
| GradEval360 | oss-slu_GradEval360 | PASSED | 10 | 3 | 0 | Decreasing |
| lrda_mobile | MISSING REPOSITORY | NOT CONFIGURED | TBD | TBD | TBD | TBD |
| lrda_website | MISSING REPOSITORY | NOT CONFIGURED | TBD | TBD | TBD | TBD |
| material-derailleur | oss-slu_material-derailleur | PASSED | 237 | 36 | 1d 5h | Increasing |
| MechatronicsVR | oss-slu_mechatronics-vr | PASSED | 19 | 2 | 44min | Decreasing |
| mithridatium | oss-slu_mithridatium | PASSED | 30 | 15 | 45min | Increasing |
| oss_dev_analytics | oss-slu_oss_dev_analytics | FAILED | 65 | 35 | 2h 6min | Decreasing |
| oss-orb | oss-slu_oss-orb | NOT COMPUTED | 12 | 11 | 0 | Increasing |
| oss-slu.github.io | oss-slu.github.io | PASSED | 5 | 3 | 0 | Decreasing |
| pao_surgery_simulator | oss-slu_pao_surgery_simulator | PASSED | 31 | 13 | 50min | Increasing |
| PilotDataSynchronization | oss-slu_PilotDataSynchronization | PASSED | 19 | 15 | 3h 5min | Decreasing |
| repoexplorer | oss-slu_repoexplorer | FAILED | 23 | 11 | 1h | Increasing |
| SALTIFY | MISSING REPOSITORY | NOT CONFIGURED | TBD | TBD | TBD | TBD |
| shelter_volunteers | oss-slu_shelter_volunteers | PASSED | 143 | 38 | 3h 18min | Decreasing |
| TheHealthApp | oss-slu_TheHealthApp | PASSED | 55 | 20 | 2h 42min | Increasing |
| TULIP | oss-slu_TULIP | PASSED | 7 | 4 | 25min | Increasing |

---

# PR Warning Drift Analysis

| Repository | PR Reviewed | Sonar Status | Merged? | Notes |
|------------|------------|------------|------------|------------|
| CivicKit |#237| FAILED | No | N/A |
| CoreDesk |#288 | FAILED | No | N/A
| CoreDesk |#269 | FAILED | Yes | Merged by khushi-c22 |
| dads |#336 | FAILED | Yes | Quality Gate Failed, changes approved by abhishekghimire40 |
| dads |#335 | FAILED | No | N/A |
| dads |#319 | FAILED | No | N/A |
| GradEval360 |#67 | FAILED | Yes | Changes approved by bellao314 |
| GradEval360 |#66 | FAILED | No | N/A |
| oss_dev_analytics |#246 | FAILED | No | N/A |
| oss-orb |#11 | FAILED | Yes | Security Rating Rated C |
| pao_surgery_simulator|#152 | FAILED | No | N/A |
|PilotDataSynchronization|#273| FAILED | Yes | Quality Gate Failed - Approved by Sanjana-Siddani

Based on this data, we see that about 10% of Quality Gate warnings are bypassed without comment or remediation.




---

# Recommended Enforcement Policy

## Proposed Baseline

1. Block merges when SonarCloud Quality Gates fail on New Code.
2. Require documented maintainer justification for overrides.
3. Review all Security Hotspots before merge.
4. Require zero new Vulnerabilities on pull requests.
5. Monitor override frequency each semester.

## Merge Decision Matrix

| Sonar Result | Action |
|-------------|----------|
| PASS | Merge Allowed |
| WARNING | Maintainer Justification Required |
| FAIL | Block Merge or Document Exception |