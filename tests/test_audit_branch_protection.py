"""Unit tests for scripts/audit_branch_protection.py (oss-slu/oss_cybersecurity#66).

Fixtures use the real API response shapes observed while auditing the candidate
repositories and while validating against an admin-controlled sandbox branch.
Run with:  python3 -m unittest discover -s tests -v
"""

import datetime as dt
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audit", ROOT / "scripts" / "audit_branch_protection.py")
audit = importlib.util.module_from_spec(spec)
sys.modules["audit"] = audit
spec.loader.exec_module(audit)

NOW = dt.datetime(2026, 11, 13, tzinfo=dt.timezone.utc)
SINCE = dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc)


def ref_update_rule(count=1, force=False, deletions=False, code_owners=False):
    return {
        "source": "graphql",
        "payload": {
            "pattern": "main",
            "allowsDeletions": deletions,
            "allowsForcePushes": force,
            "requiredApprovingReviewCount": count,
            "requiredStatusCheckContexts": [],  # always empty for non-admins
            "requiresCodeOwnerReviews": code_owners,
        },
    }


def branch_summary(level="off", contexts=()):
    return {
        "protected": True,
        "protection": {"enabled": True, "required_status_checks": {"enforcement_level": level, "contexts": list(contexts), "checks": []}},
    }


def pr_rule(count=1, stale=False, code_owners=False, ruleset_id=1):
    return {
        "type": "pull_request",
        "ruleset_id": ruleset_id,
        "parameters": {
            "required_approving_review_count": count,
            "dismiss_stale_reviews_on_push": stale,
            "require_code_owner_review": code_owners,
        },
    }


def simple_rule(kind, ruleset_id=1):
    return {"type": kind, "ruleset_id": ruleset_id}


def make_raw(**overrides):
    raw = {
        "org": "oss-slu",
        "repo": "demo",
        "exists": True,
        "full_name": "oss-slu/demo",
        "html_url": "https://github.com/oss-slu/demo",
        "archived": False,
        "visibility": "public",
        "pushed_at": "2026-11-10T00:00:00Z",
        "default_branch": "main",
        "viewer_is_admin": False,
        "branch": {"protected": False, "protection": {"enabled": False}},
        "classic": {"source": "graphql", "payload": None},
        "rules": [],
        "rulesets_meta": [],
        "codeowners": {"present": True, "error_count": 0},
        "workflow_count": 2,
        "activity": [],
        "merged_prs": [],
        "errors": [],
    }
    raw.update(overrides)
    return raw


def evaluate(**overrides):
    return audit.evaluate(make_raw(**overrides), SINCE, NOW)


class ClassicReadOnlyTests(unittest.TestCase):
    def test_classic_one_review_passes(self):
        r = evaluate(branch=branch_summary("everyone"), classic=ref_update_rule(count=1))
        self.assertEqual(r["verdict"], "PASS")
        self.assertEqual(r["protection_source"], "Classic")
        self.assertEqual(r["effective"]["required_reviews"], 1)
        self.assertIsNone(r["effective"]["dismiss_stale"], "stale dismissal is hidden from non-admins")
        self.assertTrue(r["effective"]["admins_enforced"])

    def test_zero_count_is_ambiguous_and_fails(self):
        r = evaluate(branch=branch_summary(), classic=ref_update_rule(count=0))
        self.assertIsNone(r["effective"]["pr_required"])
        self.assertEqual(r["effective"]["required_reviews"], 0)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertIn("approving review", r["baseline_gaps"][0])

    def test_status_checks_come_from_branch_summary(self):
        r = evaluate(branch=branch_summary("non_admins", ["build"]), classic=ref_update_rule())
        self.assertEqual(r["effective"]["status_checks"], ["build"])
        self.assertFalse(r["effective"]["admins_enforced"])

    def test_enforcement_level_off_means_unknown_admins(self):
        r = evaluate(branch=branch_summary("off"), classic=ref_update_rule())
        self.assertIsNone(r["effective"]["admins_enforced"])

    def test_force_push_and_deletion_allowed(self):
        r = evaluate(branch=branch_summary(), classic=ref_update_rule(force=True, deletions=True))
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(len(r["baseline_gaps"]), 2)


class ClassicAdminTests(unittest.TestCase):
    def test_rest_payload_is_authoritative(self):
        payload = {
            "required_status_checks": {"contexts": ["build"], "checks": [{"context": "lint"}]},
            "enforce_admins": {"enabled": True},
            "required_pull_request_reviews": {
                "required_approving_review_count": 2,
                "dismiss_stale_reviews": True,
                "require_code_owner_reviews": True,
            },
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
        }
        r = evaluate(branch=branch_summary("everyone", ["build"]), classic={"source": "rest", "payload": payload}, viewer_is_admin=True)
        e = r["effective"]
        self.assertEqual(r["access"], "admin")
        self.assertEqual((e["required_reviews"], e["dismiss_stale"], e["code_owner_review"]), (2, True, True))
        self.assertEqual(e["status_checks"], ["build", "lint"])
        self.assertTrue(e["admins_enforced"])

    def test_rest_without_pr_requirement(self):
        payload = {"required_pull_request_reviews": None, "allow_force_pushes": {"enabled": False}, "allow_deletions": {"enabled": True}}
        r = evaluate(branch=branch_summary(), classic={"source": "rest", "payload": payload}, viewer_is_admin=True)
        self.assertFalse(r["effective"]["pr_required"])
        self.assertIsNone(r["effective"]["required_reviews"])
        self.assertEqual(r["verdict"], "FAIL")


class RulesetTests(unittest.TestCase):
    def test_ruleset_only_passes(self):  # repoexplorer
        rules = [simple_rule("deletion"), simple_rule("non_fast_forward"), pr_rule(1, code_owners=True)]
        r = evaluate(branch=branch_summary(), rules=rules)
        self.assertEqual(r["protection_source"], "Ruleset")
        self.assertEqual(r["verdict"], "PASS")
        self.assertFalse(r["effective"]["dismiss_stale"])
        self.assertTrue(r["effective"]["code_owner_review"])

    def test_ruleset_without_force_or_delete_rules_fails(self):  # TULIP
        rules = [{"type": "code_scanning", "ruleset_id": 1}, pr_rule(1, stale=True)]
        r = evaluate(branch=branch_summary(), rules=rules)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["baseline_gaps"], ["Block force pushes", "Block deletion of `main`"])

    def test_ruleset_with_zero_approvals_fails(self):  # geo-enricher
        rules = [simple_rule("deletion"), simple_rule("non_fast_forward"), pr_rule(0)]
        r = evaluate(branch=branch_summary(), rules=rules)
        self.assertTrue(r["effective"]["pr_required"])
        self.assertEqual(r["verdict"], "FAIL")

    def test_required_status_checks_rule(self):
        rules = [{"type": "required_status_checks", "ruleset_id": 1, "parameters": {"required_status_checks": [{"context": "test"}]}}]
        r = evaluate(branch=branch_summary(), rules=rules)
        self.assertEqual(r["effective"]["status_checks"], ["test"])


class CombinationTests(unittest.TestCase):
    def test_most_restrictive_wins(self):  # civickit: classic asks 0, ruleset asks 1
        rules = [simple_rule("deletion"), simple_rule("non_fast_forward"), pr_rule(1)]
        r = evaluate(branch=branch_summary("non_admins"), classic=ref_update_rule(count=0), rules=rules)
        self.assertEqual(r["protection_source"], "Classic + ruleset")
        self.assertEqual(r["effective"]["required_reviews"], 1)
        self.assertEqual(r["verdict"], "PASS")

    def test_baseline_ruleset_keeps_stricter_classic_settings(self):  # sandbox layering test
        rules = [simple_rule("deletion"), simple_rule("non_fast_forward"), pr_rule(1, stale=True)]
        r = evaluate(branch=branch_summary("non_admins", ["build"]), classic=ref_update_rule(count=2), rules=rules)
        e = r["effective"]
        self.assertEqual((e["required_reviews"], e["status_checks"], e["dismiss_stale"]), (2, ["build"], True))

    def test_disabled_ruleset_is_a_quick_fix(self):  # cv_zebrafish
        meta = [{"id": 3, "name": "main", "enforcement": "disabled", "source_type": "Repository", "target": "branch",
                 "include": ["~ALL"], "rule_types": ["deletion", "non_fast_forward", "pull_request"]},
                {"id": 4, "name": "Prod", "enforcement": "disabled", "source_type": "Repository", "target": "branch",
                 "include": ["refs/heads/production"], "rule_types": ["deletion"]}]
        r = evaluate(rulesets_meta=meta)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertTrue(r["recommendations"][0].startswith("Quick fix: ruleset “main”"))
        self.assertFalse(any("Prod" in x for x in r["recommendations"]), "rulesets for other branches are ignored")

    def test_code_owner_review_without_codeowners_file(self):  # civickit
        rules = [simple_rule("deletion"), simple_rule("non_fast_forward"), pr_rule(1, code_owners=True)]
        r = evaluate(branch=branch_summary(), rules=rules, codeowners={"present": False, "error_count": 0})
        self.assertTrue(any("has no effect" in x for x in r["recommendations"]))
        self.assertEqual(audit.summary_counts([r])["codeowners_enforced"], 0)

    def test_force_push_blocked_by_either_source(self):
        r = evaluate(branch=branch_summary(), classic=ref_update_rule(force=True), rules=[simple_rule("non_fast_forward")])
        self.assertTrue(r["effective"]["force_push_blocked"])

    def test_unprotected_fails_everything(self):
        r = evaluate(codeowners={"present": False, "error_count": 0}, workflow_count=0)
        self.assertEqual(r["protection_source"], "None")
        self.assertEqual(len(r["baseline_gaps"]), 3)
        self.assertTrue(any("CODEOWNERS" in x for x in r["recommendations"]))
        self.assertTrue(any("Add a CI workflow" in x for x in r["recommendations"]))

    def test_protected_but_invisible_is_unknown(self):
        r = evaluate(branch=branch_summary(), classic={"source": "graphql", "payload": None}, rules=[])
        self.assertEqual(r["verdict"], "UNKNOWN")

    def test_collection_failure_is_unknown(self):
        r = evaluate(branch=branch_summary(), classic=None, rules=None)
        self.assertEqual(r["verdict"], "UNKNOWN")

    def test_missing_repo(self):
        r = audit.evaluate({"repo": "CoreDesk", "exists": False}, SINCE, NOW)
        self.assertEqual(r["verdict"], "NOT FOUND")

    def test_inactive_repo(self):
        r = evaluate(pushed_at="2025-01-01T00:00:00Z")
        self.assertFalse(r["active"])


class PracticeTests(unittest.TestCase):
    def test_independent_approval(self):
        pr = {"author": "alice", "merged_at": "2026-10-01T12:00:00Z"}
        self.assertFalse(audit.has_independent_approval({**pr, "approvals": []}))
        self.assertFalse(audit.has_independent_approval({**pr, "approvals": [{"author": "alice", "submitted_at": "2026-10-01T11:00:00Z"}]}))
        self.assertFalse(audit.has_independent_approval({**pr, "approvals": [{"author": "bob", "submitted_at": "2026-10-02T00:00:00Z"}]}))
        self.assertTrue(audit.has_independent_approval({**pr, "approvals": [{"author": "bob", "submitted_at": "2026-10-01T11:59:59Z"}]}))

    def test_counts_and_confirmed_bypasses(self):
        rules = [simple_rule("deletion", 7), simple_rule("non_fast_forward", 7), pr_rule(1, ruleset_id=7)]
        meta = [{"id": 7, "enforcement": "active", "updated_at": "2026-09-12T09:00:00-05:00"}]
        activity = [
            {"timestamp": "2026-09-01T00:00:00Z", "activity_type": "push", "actor_login": "lead", "actor_type": "User"},
            {"timestamp": "2026-10-01T00:00:00Z", "activity_type": "push", "actor_login": "lead", "actor_type": "User"},
            {"timestamp": "2026-10-02T00:00:00Z", "activity_type": "push", "actor_login": "github-actions[bot]", "actor_type": "Bot"},
            {"timestamp": "2026-10-03T00:00:00Z", "activity_type": "force_push", "actor_login": "lead", "actor_type": "User"},
            {"timestamp": "2026-10-04T00:00:00Z", "activity_type": "pr_merge", "actor_login": "lead", "actor_type": "User"},
        ]
        prs = [
            {"number": 1, "author": "a", "merged_by": "lead", "merged_at": "2026-09-05T00:00:00Z", "approvals": []},
            {"number": 2, "author": "a", "merged_by": "a", "merged_at": "2026-10-05T00:00:00Z", "approvals": []},
            {"number": 3, "author": "a", "merged_by": "lead", "merged_at": "2026-10-06T00:00:00Z",
             "approvals": [{"author": "lead", "submitted_at": "2026-10-05T00:00:00Z"}]},
        ]
        r = evaluate(branch=branch_summary(), rules=rules, rulesets_meta=meta, activity=activity, merged_prs=prs)
        p = r["practice"]
        self.assertEqual((p["direct_pushes"], p["bot_pushes"], p["force_pushes"]), (2, 1, 1))
        self.assertEqual((p["pr_merges"], p["unapproved_merges"], p["unapproved_pr_numbers"]), (3, 2, [1, 2]))
        self.assertEqual(p["confirmed_bypass_pushes"], 1)  # only the push after 2026-09-12
        self.assertEqual(p["confirmed_bypass_merges"], 1)  # only PR #2
        self.assertTrue(r["unreviewed_changes"])
        self.assertNotIn("direct_push_actors", p, "logins stay out of reports unless --include-actors")

    def test_zero_approval_ruleset_does_not_confirm_merge_bypass(self):
        rules = [pr_rule(0, ruleset_id=9)]
        meta = [{"id": 9, "enforcement": "active", "updated_at": "2026-08-02T00:00:00Z"}]
        prs = [{"number": 5, "author": "a", "merged_by": "a", "merged_at": "2026-09-01T00:00:00Z", "approvals": []}]
        p = evaluate(branch=branch_summary(), rules=rules, rulesets_meta=meta, merged_prs=prs)["practice"]
        self.assertIsNone(p["approval_rule_in_force_since"])
        self.assertNotIn("confirmed_bypass_merges", p)

    def test_include_actors(self):
        activity = [{"timestamp": "2026-10-01T00:00:00Z", "activity_type": "push", "actor_login": "lead", "actor_type": "User"}]
        r = audit.evaluate(make_raw(activity=activity), SINCE, NOW, include_actors=True)
        self.assertEqual(r["practice"]["direct_push_actors"], ["lead"])


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.results = [
            evaluate(branch=branch_summary("everyone"), classic=ref_update_rule()),
            audit.evaluate(make_raw(repo="open-repo"), SINCE, NOW),
            audit.evaluate({"repo": "CoreDesk", "exists": False}, SINCE, NOW),
        ]
        self.meta = {"org": "oss-slu", "generated_at": "2026-11-13T00:00:00Z", "window_start": "2026-08-01T00:00:00Z",
                     "window_end": "2026-11-13T00:00:00Z"}

    def test_matrix_rows_and_summary(self):
        text = audit.render_matrix(self.results, self.meta)
        self.assertIn("**1 of 2**", text)
        self.assertIn("| 3 | CoreDesk |", text)
        self.assertIn("❌ Fail", text)
        self.assertIn("Observed practice since 2026-08-01", text)

    def test_write_markdown_only_replaces_generated_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "matrix.md"
            path.write_text(f"# Title\n\nIntro stays.\n\n{audit.BEGIN_MARK}\nold\n{audit.END_MARK}\n\n## Footer stays\n")
            audit.write_markdown(path, "new block\n")
            text = path.read_text()
            self.assertIn("Intro stays.", text)
            self.assertIn("## Footer stays", text)
            self.assertIn("new block", text)
            self.assertNotIn("old", text)

    def test_issue_draft_for_failing_repo(self):
        draft = audit.render_issue_draft(self.results[1], "oss-slu", note="Note line.")
        self.assertTrue(draft.startswith("# Security: enable baseline branch protection on `main`"))
        self.assertIn("- [ ] Block force pushes", draft)
        self.assertIn("scripts/enforce-branch-protection.sh --repo open-repo --apply", draft)
        self.assertIn("Note line.", draft)

    def test_issue_draft_quick_fix_and_pr_numbers(self):
        meta = [{"id": 3, "name": "main", "enforcement": "disabled", "source_type": "Repository", "target": "branch",
                 "include": ["~ALL"], "rule_types": ["pull_request"]}]
        prs = [{"number": 112, "author": "a", "merged_by": "a", "merged_at": "2026-09-01T00:00:00Z", "approvals": []}]
        draft = audit.render_issue_draft(evaluate(rulesets_meta=meta, merged_prs=prs), "oss-slu")
        self.assertIn("**Fastest fix:** ruleset “main”", draft)
        self.assertIn("`#112`", draft)
        self.assertNotIn(" #112", draft.replace("`#112`", ""))
        self.assertTrue(draft.rstrip().endswith("Disclosure: partially drafted with AI assistance."))

    def test_issue_draft_for_passing_repo_with_bypass(self):
        activity = [{"timestamp": "2026-10-01T00:00:00Z", "activity_type": "push", "actor_login": "lead", "actor_type": "User"}]
        r = evaluate(branch=branch_summary("non_admins"), classic=ref_update_rule(), activity=activity)
        self.assertTrue(r["recommendations"][0].startswith("Bind admins to the rules"))
        draft = audit.render_issue_draft(r, "oss-slu")
        self.assertTrue(draft.startswith("# Security: unreviewed changes are reaching `main`"))
        self.assertNotIn("## Required", draft)
        self.assertNotIn("lead", draft.replace("tech lead", ""), "no logins in issue text")

    def test_unknown_admin_binding_suggests_checking_bypass(self):
        activity = [{"timestamp": "2026-10-01T00:00:00Z", "activity_type": "push", "actor_login": "x", "actor_type": "User"}]
        r = evaluate(branch=branch_summary("off"), classic=ref_update_rule(), activity=activity)
        self.assertTrue(r["recommendations"][0].startswith("Unreviewed changes got past the rules"))

    def test_regressions(self):
        old = [evaluate(branch=branch_summary("everyone", ["build"]), classic=ref_update_rule(count=2))]
        new = [evaluate(branch=branch_summary(), classic=ref_update_rule(count=1, force=True))]
        found = audit.find_regressions(old, new)
        self.assertTrue(any("no longer meets the baseline" in x for x in found))
        self.assertTrue(any("force pushes" in x for x in found))
        self.assertTrue(any("dropped from 2 to 1" in x for x in found))
        self.assertTrue(any("build" in x for x in found))
        self.assertEqual(audit.find_regressions(old, old), [])

    def test_load_repo_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "repos.txt"
            path.write_text("# header\nalpha\n\nbeta   # renamed\n")
            self.assertEqual(audit.load_repo_list(path), ["alpha", "beta"])

    def test_candidate_list_has_22_repos(self):
        self.assertEqual(len(audit.load_repo_list(audit.DEFAULT_REPOS_FILE)), 22)


if __name__ == "__main__":
    unittest.main()
