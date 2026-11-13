#!/usr/bin/env python3
"""
audit_branch_protection.py - OSS-SLU Branch Protection Compliance Auditor

Checks default-branch protection on the OSS-SLU candidate repositories against the
OSS-SLU baseline: at least 1 approving review, force pushes blocked, and branch
deletion blocked. It also reports what actually happened on each default branch
(direct pushes, force pushes, and PRs merged without an independent approval),
because a rule that people bypass is not working as a control.

Read-only access is enough:
  * Classic branch protection is read from the GraphQL `Ref.refUpdateRule` field plus
    the REST branch summary (required status checks, and whether admins are bound).
    Stale-approval dismissal is hidden from non-admins and is reported as Unknown.
  * Rulesets are read from GET /repos/{owner}/{repo}/rules/branches/{branch}, and their
    last-changed dates from GET /repos/{owner}/{repo}/rulesets.
  * Practice comes from the repository activity log and merged pull requests.
  * When the token has admin access to a repository, the full REST branch
    protection endpoint is used instead.
  The read-only signals were checked against admin ground truth on a sandbox branch;
  see normalize_classic() for the details.

Requires Python 3.9+ and a logged-in GitHub CLI (`gh auth status`). In GitHub
Actions, set GH_TOKEN to the job token.

Usage:
  python3 scripts/audit_branch_protection.py                       # console report
  python3 scripts/audit_branch_protection.py --since 2026-08-01 \\
      --json docs/audits/branch_protection_audit_fall2026.json \\
      --markdown docs/audits/branch_protection_compliance_matrix_fall2026.md
  python3 scripts/audit_branch_protection.py --compare docs/audits/branch_protection_audit_fall2026.json \\
      --fail-on-regression                                        # drift check

Exit codes: 0 = ok, 1 = error, 2 = baseline violations (with --fail-on-violation),
            3 = regressions against --compare snapshot (with --fail-on-regression).

Ref: oss-slu/oss_cybersecurity#66
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import quote

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_REPOS_FILE = SCRIPT_DIR / "branch_protection_candidates.txt"
DEFAULT_ORG = "oss-slu"
DEFAULT_WINDOW_DAYS = 90
ACTIVE_WITHIN_DAYS = 180
MIN_REVIEWS = 1
SCHEMA_VERSION = 1
GUIDE_URL = "https://github.com/oss-slu/oss_cybersecurity/blob/main/docs/standards/branch-protection-guide.md"
BEGIN_MARK = "<!-- BEGIN GENERATED: scripts/audit_branch_protection.py -->"
END_MARK = "<!-- END GENERATED: scripts/audit_branch_protection.py -->"

REF_UPDATE_RULE_QUERY = """
query($owner: String!, $name: String!, $ref: String!) {
  repository(owner: $owner, name: $name) {
    ref(qualifiedName: $ref) {
      refUpdateRule {
        pattern
        allowsDeletions
        allowsForcePushes
        requiredApprovingReviewCount
        requiredStatusCheckContexts
        requiresCodeOwnerReviews
        requiresConversationResolution
        requiresLinearHistory
        requiresSignatures
      }
    }
  }
}
"""

MERGED_PRS_QUERY = """
query($q: String!, $after: String) {
  search(type: ISSUE, query: $q, first: 100, after: $after) {
    issueCount
    pageInfo { hasNextPage endCursor }
    nodes {
      ... on PullRequest {
        number
        mergedAt
        author { login }
        mergedBy { login }
        reviews(states: APPROVED, first: 50) { nodes { author { login } submittedAt } }
      }
    }
  }
}
"""


# --------------------------------------------------------------------------- #
# GitHub access
# --------------------------------------------------------------------------- #
class GhError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class GhClient:
    """Minimal GitHub API client built on the GitHub CLI, so auth is identical locally and in CI."""

    def _run(self, args: list[str], stdin: Optional[str] = None) -> str:
        proc = subprocess.run(["gh", "api", *args], input=stdin, capture_output=True, text=True)
        if proc.returncode != 0:
            match = re.search(r"HTTP (\d{3})", proc.stderr)
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            raise GhError(detail[-1] if detail else "gh api failed", int(match.group(1)) if match else None)
        return proc.stdout

    def rest(self, path: str, paginate: bool = False) -> Any:
        args = ["-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28", path]
        if paginate:
            pages = json.loads(self._run(["--paginate", "--slurp", *args]) or "[]")
            return [item for page in pages for item in (page if isinstance(page, list) else [page])]
        return json.loads(self._run(args) or "null")

    def graphql(self, query: str, **variables: Any) -> dict:
        body = json.dumps({"query": query, "variables": variables})
        data = json.loads(self._run(["graphql", "--input", "-"], stdin=body))
        if data.get("errors"):
            raise GhError("; ".join(e.get("message", "?") for e in data["errors"]))
        return data["data"]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def parse_ts(value: Optional[str]) -> Optional[dt.datetime]:
    if not value:
        return None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def login(node: Optional[dict]) -> Optional[str]:
    return (node or {}).get("login")


def load_repo_list(path: Path) -> list[str]:
    repos = []
    for line in path.read_text().splitlines():
        name = line.split("#", 1)[0].strip()
        if name:
            repos.append(name)
    return repos


# --------------------------------------------------------------------------- #
# Collection: talks to GitHub, returns raw evidence
# --------------------------------------------------------------------------- #
def collect_repo(client: GhClient, org: str, name: str, since: dt.datetime, now: dt.datetime,
                 branch_override: Optional[str] = None, read_only: bool = False) -> dict:
    raw: dict[str, Any] = {"org": org, "repo": name, "exists": False, "errors": []}
    try:
        meta = client.rest(f"repos/{org}/{name}")
    except GhError as err:
        if err.status == 404:
            return raw
        raise
    owner, real_name = meta["full_name"].split("/", 1)
    branch = branch_override or meta["default_branch"]
    raw.update(
        exists=True,
        full_name=meta["full_name"],
        html_url=meta.get("html_url"),
        archived=bool(meta.get("archived")),
        visibility=meta.get("visibility"),
        pushed_at=meta.get("pushed_at"),
        default_branch=branch,
        viewer_is_admin=bool((meta.get("permissions") or {}).get("admin")) and not read_only,
    )
    if read_only and (meta.get("permissions") or {}).get("admin"):
        # refUpdateRule describes the rule as it applies to the viewer: an admin who is not
        # bound by the rule sees 0 required reviews. Non-admin viewers always see the real rule.
        raw["errors"].append("--read-only with an admin token: review counts can read as 0 when admins are not bound")
    base = f"repos/{owner}/{real_name}"
    enc_branch = quote(branch, safe="")

    def attempt(key: str, fn: Callable[[], Any]) -> None:
        try:
            raw[key] = fn()
        except GhError as err:
            raw[key] = None
            raw["errors"].append(f"{key}: {err}")

    def branch_summary() -> dict:
        data = client.rest(f"{base}/branches/{enc_branch}")
        return {"protected": bool(data.get("protected")), "protection": data.get("protection")}

    def classic() -> dict:
        if raw["viewer_is_admin"]:
            try:
                return {"source": "rest", "payload": client.rest(f"{base}/branches/{enc_branch}/protection")}
            except GhError as err:
                if err.status == 404:  # "Branch not protected"
                    return {"source": "rest", "payload": None}
                raise
        data = client.graphql(REF_UPDATE_RULE_QUERY, owner=owner, name=real_name, ref=f"refs/heads/{branch}")
        ref = (data.get("repository") or {}).get("ref") or {}
        return {"source": "graphql", "payload": ref.get("refUpdateRule")}

    def codeowners() -> dict:
        try:
            errors = client.rest(f"{base}/codeowners/errors").get("errors") or []
            return {"present": True, "error_count": len(errors)}
        except GhError as err:
            if err.status == 404:  # no CODEOWNERS file in any supported location
                return {"present": False, "error_count": 0}
            raise

    def workflows() -> int:
        data = client.rest(f"{base}/actions/workflows?per_page=100")
        return sum(
            1
            for wf in data.get("workflows") or []
            if wf.get("state") == "active" and not str(wf.get("path", "")).startswith("dynamic/")
        )

    def activity() -> list[dict]:
        period = "&time_period=year" if (now - since).days <= 365 else ""
        events = client.rest(f"{base}/activity?ref={quote('refs/heads/' + branch, safe='/')}&per_page=100{period}", paginate=True)
        out = []
        for ev in events:
            ts = parse_ts(ev.get("timestamp"))
            if ts and ts >= since:
                actor = ev.get("actor") or {}
                out.append(
                    {
                        "timestamp": ev.get("timestamp"),
                        "activity_type": ev.get("activity_type"),
                        "actor_login": actor.get("login"),
                        "actor_type": actor.get("type"),
                    }
                )
        return out

    def merged_prs() -> list[dict]:
        query = f"repo:{owner}/{real_name} is:pr is:merged base:{branch} merged:>={since.date().isoformat()}"
        prs: list[dict] = []
        after = None
        while True:
            search = client.graphql(MERGED_PRS_QUERY, q=query, after=after)["search"]
            for node in search["nodes"]:
                if not node:
                    continue
                prs.append(
                    {
                        "number": node["number"],
                        "merged_at": node["mergedAt"],
                        "author": login(node.get("author")),
                        "merged_by": login(node.get("mergedBy")),
                        "approvals": [
                            {"author": login(r.get("author")), "submitted_at": r.get("submittedAt")}
                            for r in node["reviews"]["nodes"]
                        ],
                    }
                )
            if not search["pageInfo"]["hasNextPage"] or len(prs) >= 1000:
                return prs
            after = search["pageInfo"]["endCursor"]

    def rulesets_meta() -> list[dict]:
        data = client.rest(f"{base}/rulesets?includes_parents=true&per_page=100", paginate=True)
        keys = ("id", "name", "source_type", "source", "enforcement", "created_at", "updated_at")
        out = [{k: rs.get(k) for k in keys} for rs in data]
        for meta_entry in out:
            # Inactive rulesets do not show up in rules/branches; fetch them so the report can
            # point out protection that already exists but is switched off.
            if meta_entry["enforcement"] != "active" and meta_entry["source_type"] == "Repository":
                detail = client.rest(f"{base}/rulesets/{meta_entry['id']}")
                meta_entry["target"] = detail.get("target")
                meta_entry["include"] = ((detail.get("conditions") or {}).get("ref_name") or {}).get("include") or []
                meta_entry["rule_types"] = sorted({r.get("type") for r in detail.get("rules") or []})
        return out

    attempt("branch", branch_summary)
    attempt("classic", classic)
    attempt("rules", lambda: client.rest(f"{base}/rules/branches/{enc_branch}", paginate=True))
    attempt("rulesets_meta", rulesets_meta)
    attempt("codeowners", codeowners)
    attempt("workflow_count", workflows)
    attempt("activity", activity)
    attempt("merged_prs", merged_prs)
    return raw


# --------------------------------------------------------------------------- #
# Evaluation: pure functions over raw evidence (unit tested)
# --------------------------------------------------------------------------- #
def normalize_classic(classic: Optional[dict], branch_summary: Optional[dict] = None) -> Optional[dict]:
    """Turn classic protection (REST admin payload or GraphQL refUpdateRule) into one shape.

    Returns None when the branch has no classic protection rule.
    Values of None mean "not visible to this token".

    Read-only behaviour, verified against admin ground truth on a sandbox branch
    (see docs/audits/branch_protection_compliance_matrix_fall2026.md, Methodology):
      * refUpdateRule describes the rule as it applies to the viewer. Non-admin viewers
        are always bound, so they see the configured values (the case this path is for).
      * refUpdateRule.requiredApprovingReviewCount is 0 both when a PR is required
        with 0 approvals and when no PR is required, so 0 means "PR requirement unknown".
      * refUpdateRule.requiredStatusCheckContexts is always empty for non-admins; the
        REST branch summary (GET /branches/{branch}) lists the real contexts.
      * The branch summary's required_status_checks.enforcement_level is "everyone"
        when admins are bound by the rule, "non_admins" when they are not, and "off"
        when status checks are disabled (then admin enforcement is not visible).
    """
    if not classic or not classic.get("payload"):
        return None
    p = classic["payload"]
    if classic["source"] == "rest":
        reviews = p.get("required_pull_request_reviews")
        checks = p.get("required_status_checks") or {}
        contexts = set(checks.get("contexts") or []) | {c.get("context") for c in checks.get("checks") or []}
        return {
            "pr_required": reviews is not None,
            "required_reviews": reviews.get("required_approving_review_count", 0) if reviews is not None else None,
            "dismiss_stale": bool(reviews.get("dismiss_stale_reviews")) if reviews is not None else False,
            "code_owner_review": bool((reviews or {}).get("require_code_owner_reviews")),
            "force_push_blocked": not (p.get("allow_force_pushes") or {}).get("enabled", False),
            "deletion_blocked": not (p.get("allow_deletions") or {}).get("enabled", False),
            "status_checks": sorted(c for c in contexts if c),
            "admins_enforced": bool((p.get("enforce_admins") or {}).get("enabled")),
        }
    count = p.get("requiredApprovingReviewCount") or 0
    summary_checks = ((branch_summary or {}).get("protection") or {}).get("required_status_checks") or {}
    contexts = set(summary_checks.get("contexts") or []) | {c.get("context") for c in summary_checks.get("checks") or []}
    contexts |= set(p.get("requiredStatusCheckContexts") or [])
    level = summary_checks.get("enforcement_level")
    return {
        "pr_required": True if count >= 1 else None,  # 0 is ambiguous for non-admins
        "required_reviews": count,
        "dismiss_stale": None if count >= 1 else False,  # hidden from non-admins
        "code_owner_review": bool(p.get("requiresCodeOwnerReviews")),
        "force_push_blocked": not p.get("allowsForcePushes", False),
        "deletion_blocked": not p.get("allowsDeletions", False),
        "status_checks": sorted(c for c in contexts if c),
        "admins_enforced": {"everyone": True, "non_admins": False}.get(level),
    }


def normalize_rules(rules: Optional[list]) -> Optional[dict]:
    """Collapse the active ruleset rules for a branch into the same shape as normalize_classic."""
    if not rules:
        return None
    out: dict[str, Any] = {
        "pr_required": False,
        "required_reviews": None,
        "dismiss_stale": False,
        "code_owner_review": False,
        "force_push_blocked": False,
        "deletion_blocked": False,
        "status_checks": set(),
        "admins_enforced": None,  # bypass lists are hidden from non-admins
        "ruleset_ids": set(),
    }
    for rule in rules:
        params = rule.get("parameters") or {}
        if rule.get("ruleset_id") is not None:
            out["ruleset_ids"].add(rule["ruleset_id"])
        kind = rule.get("type")
        if kind == "pull_request":
            out["pr_required"] = True
            out["required_reviews"] = max(out["required_reviews"] or 0, params.get("required_approving_review_count", 0))
            out["dismiss_stale"] = out["dismiss_stale"] or bool(params.get("dismiss_stale_reviews_on_push"))
            out["code_owner_review"] = out["code_owner_review"] or bool(params.get("require_code_owner_review"))
        elif kind == "non_fast_forward":
            out["force_push_blocked"] = True
        elif kind == "deletion":
            out["deletion_blocked"] = True
        elif kind == "required_status_checks":
            out["status_checks"] |= {c.get("context") for c in params.get("required_status_checks") or [] if c.get("context")}
    out["status_checks"] = sorted(out["status_checks"])
    out["ruleset_ids"] = sorted(out["ruleset_ids"])
    return out


def combine(classic: Optional[dict], rules: Optional[dict]) -> dict:
    """GitHub enforces classic protection and rulesets together; the most restrictive value wins."""
    sources = [s for s in (classic, rules) if s]
    pr_sources = [s for s in sources if s["pr_required"]]

    def tri_state(key: str, pool: list[dict]) -> Optional[bool]:
        values = [s[key] for s in pool]
        if any(v is True for v in values):
            return True
        if any(v is None for v in values):
            return None
        return False

    if pr_sources:
        pr_required: Optional[bool] = True
        required_reviews: Optional[int] = max((s["required_reviews"] or 0) for s in pr_sources)
    elif any(s["pr_required"] is None for s in sources):
        pr_required, required_reviews = None, 0  # "0 approvals" seen read-only: PR requirement unknown
    else:
        pr_required, required_reviews = False, None

    return {
        "pr_required": pr_required,
        "required_reviews": required_reviews,
        "dismiss_stale": tri_state("dismiss_stale", pr_sources) if pr_sources else False,
        "code_owner_review": any(s["code_owner_review"] for s in pr_sources),
        "force_push_blocked": any(s["force_push_blocked"] for s in sources),
        "deletion_blocked": any(s["deletion_blocked"] for s in sources),
        "status_checks": sorted({c for s in sources for c in s["status_checks"]}),
        "admins_enforced": tri_state("admins_enforced", sources) if sources else False,
    }


def has_independent_approval(pr: dict) -> bool:
    merged_at = parse_ts(pr.get("merged_at"))
    for review in pr.get("approvals") or []:
        submitted = parse_ts(review.get("submitted_at"))
        if review.get("author") and review["author"] != pr.get("author") and submitted and (not merged_at or submitted <= merged_at):
            return True
    return False


def ruleset_in_force_since(raw: dict, min_approvals: int = 0) -> Optional[dt.datetime]:
    """Earliest time from which an active ruleset requiring PRs (with >= min_approvals) has been unchanged.

    Rulesets expose updated_at to read-only users, so a direct push (or, with
    min_approvals >= 1, an unapproved merge) after this moment went around a rule
    that was already in force. Classic protection exposes no date, so this returns
    None for classic-only branches.
    """
    ids = {
        r.get("ruleset_id")
        for r in raw.get("rules") or []
        if r.get("type") == "pull_request"
        and (r.get("parameters") or {}).get("required_approving_review_count", 0) >= min_approvals
    }
    dates = [
        parse_ts(m.get("updated_at"))
        for m in raw.get("rulesets_meta") or []
        if m.get("id") in ids and m.get("enforcement") == "active" and m.get("updated_at")
    ]
    dates = [d for d in dates if d]
    return min(dates) if dates else None


def summarize_practice(raw: dict, include_actors: bool = False) -> dict:
    activity = raw.get("activity")
    prs = raw.get("merged_prs")
    pr_rule_since = ruleset_in_force_since(raw)
    approval_rule_since = ruleset_in_force_since(raw, MIN_REVIEWS)
    out: dict[str, Any] = {
        "activity_visible": activity is not None,
        "prs_visible": prs is not None,
        "review_rule_in_force_since": iso(pr_rule_since) if pr_rule_since else None,
        "approval_rule_in_force_since": iso(approval_rule_since) if approval_rule_since else None,
    }
    if activity is not None:
        human = [a for a in activity if a["activity_type"] == "push" and a.get("actor_type") != "Bot"]
        if pr_rule_since:
            out["confirmed_bypass_pushes"] = sum(1 for a in human if parse_ts(a["timestamp"]) > pr_rule_since)
        bots = [a for a in activity if a["activity_type"] == "push" and a.get("actor_type") == "Bot"]
        force = [a for a in activity if a["activity_type"] == "force_push"]
        out.update(
            direct_pushes=len(human),
            bot_pushes=len(bots),
            force_pushes=len(force),
            branch_deletions=sum(1 for a in activity if a["activity_type"] == "branch_deletion"),
            direct_push_dates=sorted({a["timestamp"][:10] for a in human}),
            force_push_dates=sorted({a["timestamp"][:10] for a in force}),
        )
        if include_actors:
            out["direct_push_actors"] = sorted({a["actor_login"] for a in human if a.get("actor_login")})
            out["force_push_actors"] = sorted({a["actor_login"] for a in force if a.get("actor_login")})
    if prs is not None:
        unapproved_prs = [pr for pr in prs if not has_independent_approval(pr)]
        unapproved = sorted(pr["number"] for pr in unapproved_prs)
        out.update(pr_merges=len(prs), unapproved_merges=len(unapproved), unapproved_pr_numbers=unapproved)
        if approval_rule_since:
            out["confirmed_bypass_merges"] = sum(
                1 for pr in unapproved_prs if (parse_ts(pr.get("merged_at")) or approval_rule_since) > approval_rule_since
            )
    return out


def evaluate(raw: dict, since: dt.datetime, now: dt.datetime, include_actors: bool = False) -> dict:
    result: dict[str, Any] = {"repo": raw["repo"], "exists": raw.get("exists", False)}
    if not raw.get("exists"):
        result.update(verdict="NOT FOUND", baseline_gaps=[], recommendations=[], observations=[], active=False)
        return result

    branch = raw["default_branch"]
    pushed = parse_ts(raw.get("pushed_at"))
    active = not raw.get("archived") and pushed is not None and (now - pushed).days <= ACTIVE_WITHIN_DAYS
    classic = normalize_classic(raw.get("classic"), raw.get("branch"))
    rules = normalize_rules(raw.get("rules"))
    protected = bool((raw.get("branch") or {}).get("protected"))
    effective = combine(classic, rules)
    source = {(True, True): "Classic + ruleset", (True, False): "Classic", (False, True): "Ruleset"}.get(
        (classic is not None, rules is not None), "None"
    )
    visible = raw.get("classic") is not None and raw.get("rules") is not None
    if (protected and source == "None") or not visible:
        source = "Unknown"

    result.update(
        full_name=raw.get("full_name"),
        html_url=raw.get("html_url"),
        default_branch=branch,
        archived=raw.get("archived"),
        active=active,
        pushed_at=raw.get("pushed_at"),
        access="admin" if raw.get("viewer_is_admin") else "read",
        protection_source=source,
        classic=classic,
        rulesets=rules,
        effective=effective,
        codeowners=raw.get("codeowners"),
        workflow_count=raw.get("workflow_count"),
        rulesets_meta=raw.get("rulesets_meta"),
        practice=summarize_practice(raw, include_actors),
        collection_errors=raw.get("errors", []),
    )

    gaps: list[str] = []
    if source == "Unknown":
        result.update(verdict="UNKNOWN", baseline_gaps=["Protection details could not be read; re-run with admin access"])
    else:
        if not effective["pr_required"] or (effective["required_reviews"] or 0) < MIN_REVIEWS:
            gaps.append(f"Require a pull request with at least {MIN_REVIEWS} approving review before merging")
        if not effective["force_push_blocked"]:
            gaps.append("Block force pushes")
        if not effective["deletion_blocked"]:
            gaps.append(f"Block deletion of `{branch}`")
        result.update(verdict="FAIL" if gaps else "PASS", baseline_gaps=gaps)

    recs: list[str] = []
    baseline_types = {"pull_request", "non_fast_forward", "deletion"}
    for rs in raw.get("rulesets_meta") or []:
        targets_branch = any(p in ("~ALL", "~DEFAULT_BRANCH", f"refs/heads/{branch}") for p in rs.get("include") or [])
        useful = baseline_types & set(rs.get("rule_types") or [])
        if rs.get("enforcement") != "active" and rs.get("target", "branch") == "branch" and targets_branch and useful:
            recs.insert(0, f"Quick fix: ruleset “{rs.get('name')}” ({', '.join(sorted(useful))}) already covers `{branch}` but its "
                           f"enforcement is `{rs.get('enforcement')}`; set it to Active (Settings → Rules → Rulesets)")
    if effective["pr_required"] and effective["dismiss_stale"] is False:
        recs.append("Dismiss stale approvals when new commits are pushed")
    elif effective["pr_required"] and effective["dismiss_stale"] is None:
        recs.append("Confirm stale-approval dismissal is on (only repo admins can see this setting)")
    owners = raw.get("codeowners") or {}
    if owners.get("present") is False and effective["code_owner_review"]:
        recs.append("Code owner review is required but there is no CODEOWNERS file, so the requirement has no effect; add one")
    elif owners.get("present") is False:
        recs.append("Add a CODEOWNERS file so reviews route to the project's tech lead")
    elif owners.get("present") and not effective["code_owner_review"]:
        recs.append("Require review from code owners (a CODEOWNERS file exists but is not enforced)")
    if owners.get("error_count"):
        recs.append(f"Fix {owners['error_count']} CODEOWNERS syntax/user error(s)")
    if not effective["status_checks"]:
        wf = raw.get("workflow_count")
        if wf:
            recs.append(f"Require the repository's CI checks to pass before merging ({wf} active workflow(s), none required)")
        elif wf == 0:
            recs.append("Add a CI workflow (none found) and require it before merging")
    result["recommendations"] = recs

    obs: list[str] = []
    practice = result["practice"]
    window = since.date().isoformat()
    if practice.get("direct_pushes"):
        text = f"{practice['direct_pushes']} direct push(es) to `{branch}` by people since {window}, without a pull request"
        if practice.get("confirmed_bypass_pushes"):
            text += (f"; {practice['confirmed_bypass_pushes']} came after the pull request ruleset was last changed on "
                     f"{practice['review_rule_in_force_since'][:10]}, so they went around a rule already in force "
                     "(check the ruleset's bypass list)")
        obs.append(text)
    if practice.get("force_pushes"):
        obs.append(f"{practice['force_pushes']} force push(es) to `{branch}` since {window}")
    if practice.get("unapproved_merges"):
        nums = ", ".join(f"#{n}" for n in practice["unapproved_pr_numbers"][:10])
        more = "" if practice["unapproved_merges"] <= 10 else f" and {practice['unapproved_merges'] - 10} more"
        text = f"{practice['unapproved_merges']} PR(s) merged without an approval from someone other than the author ({nums}{more})"
        if practice.get("confirmed_bypass_merges"):
            text += (f"; {practice['confirmed_bypass_merges']} merged after the approval ruleset was last changed on "
                     f"{practice['approval_rule_in_force_since'][:10]}")
        obs.append(text)
    result["observations"] = obs
    result["unreviewed_changes"] = bool(obs)
    if obs and source not in ("None", "Unknown"):
        # A rule exists, yet unreviewed changes got through: almost always admin or bypass-list access.
        at = 1 if recs and recs[0].startswith("Quick fix") else 0
        if effective["admins_enforced"] is False:
            recs.insert(at, "Bind admins to the rules: turn on “Do not allow bypassing the above settings” so admins "
                            "cannot push or merge without a review")
        elif effective["admins_enforced"] is None:
            recs.insert(at, "Unreviewed changes got past the rules: check who can bypass them (“Do not allow bypassing "
                            "the above settings” in classic rules, the bypass list in rulesets) and remove that bypass")
    return result


def find_regressions(old_results: list[dict], new_results: list[dict]) -> list[str]:
    """Compare two audit snapshots and list controls that got weaker."""
    previous = {r["repo"]: r for r in old_results}
    regressions: list[str] = []
    for new in new_results:
        old = previous.get(new["repo"])
        if not old or old.get("verdict") not in ("PASS", "FAIL") or new.get("verdict") not in ("PASS", "FAIL"):
            continue
        name = new["repo"]
        before, after = old.get("effective") or {}, new.get("effective") or {}
        if old["verdict"] == "PASS" and new["verdict"] == "FAIL":
            regressions.append(f"{name}: no longer meets the baseline ({'; '.join(new['baseline_gaps'])})")
        if before.get("force_push_blocked") and not after.get("force_push_blocked"):
            regressions.append(f"{name}: force pushes are no longer blocked")
        if before.get("deletion_blocked") and not after.get("deletion_blocked"):
            regressions.append(f"{name}: branch deletion is no longer blocked")
        if (after.get("required_reviews") or 0) < (before.get("required_reviews") or 0):
            regressions.append(f"{name}: required reviews dropped from {before.get('required_reviews')} to {after.get('required_reviews') or 0}")
        removed = sorted(set(before.get("status_checks") or []) - set(after.get("status_checks") or []))
        if removed:
            regressions.append(f"{name}: required status check(s) removed: {', '.join(removed)}")
        if before.get("code_owner_review") and not after.get("code_owner_review"):
            regressions.append(f"{name}: code owner review is no longer required")
    return regressions


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _yes_no(value: Optional[bool], unknown: str = "Unknown¹") -> str:
    return unknown if value is None else ("Yes" if value else "No")


def _repo_link(result: dict, org: str) -> str:
    url = result.get("html_url") or f"https://github.com/{org}/{result['repo']}"
    label = result["repo"]
    if result.get("full_name") and result["full_name"].split("/", 1)[1] != result["repo"]:
        label += f" → {result['full_name'].split('/', 1)[1]}"
    return f"[{label}]({url})"


def summary_counts(results: list[dict]) -> dict:
    found = [r for r in results if r["exists"]]
    active = [r for r in found if r.get("active")]
    return {
        "candidates": len(results),
        "found": len(found),
        "not_found": len(results) - len(found),
        "active": len(active),
        "pass": sum(1 for r in found if r["verdict"] == "PASS"),
        "fail": sum(1 for r in found if r["verdict"] == "FAIL"),
        "unknown": sum(1 for r in found if r["verdict"] == "UNKNOWN"),
        "active_pass": sum(1 for r in active if r["verdict"] == "PASS"),
        "reviews_required": sum(1 for r in found if (r.get("effective") or {}).get("required_reviews")),
        "force_blocked": sum(1 for r in found if (r.get("effective") or {}).get("force_push_blocked")),
        "deletion_blocked": sum(1 for r in found if (r.get("effective") or {}).get("deletion_blocked")),
        "checks_required": sum(1 for r in found if (r.get("effective") or {}).get("status_checks")),
        "stale_dismissed": sum(1 for r in found if (r.get("effective") or {}).get("dismiss_stale") is True),
        "stale_unknown": sum(1 for r in found if r.get("effective") and r["effective"].get("pr_required") and r["effective"].get("dismiss_stale") is None),
        "codeowners_enforced": sum(
            1 for r in found
            if (r.get("effective") or {}).get("code_owner_review") and (r.get("codeowners") or {}).get("present")
        ),
        "codeowners_present": sum(1 for r in found if (r.get("codeowners") or {}).get("present")),
        "admins_bound": sum(1 for r in found if (r.get("effective") or {}).get("admins_enforced") is True),
        "admins_not_bound": sum(1 for r in found if r.get("protection_source") != "None" and (r.get("effective") or {}).get("admins_enforced") is False),
        "unreviewed_changes": sum(1 for r in found if r.get("unreviewed_changes")),
        "direct_pushes": sum((r.get("practice") or {}).get("direct_pushes", 0) for r in found),
        "force_pushes": sum((r.get("practice") or {}).get("force_pushes", 0) for r in found),
        "pr_merges": sum((r.get("practice") or {}).get("pr_merges", 0) for r in found),
        "unapproved_merges": sum((r.get("practice") or {}).get("unapproved_merges", 0) for r in found),
        "confirmed_bypasses": sum(
            (r.get("practice") or {}).get("confirmed_bypass_pushes", 0) + (r.get("practice") or {}).get("confirmed_bypass_merges", 0)
            for r in found
        ),
        "confirmed_bypass_repos": sum(
            1 for r in found
            if (r.get("practice") or {}).get("confirmed_bypass_pushes") or (r.get("practice") or {}).get("confirmed_bypass_merges")
        ),
        "admin_access": sum(1 for r in found if r.get("access") == "admin"),
    }


def render_matrix(results: list[dict], meta: dict) -> str:
    org = meta["org"]
    c = summary_counts(results)
    window = meta["window_start"][:10]
    lines = [
        f"_Generated {meta['generated_at']} by `scripts/audit_branch_protection.py`. "
        f"Practice window: {window} to {meta['window_end'][:10]}. "
        f"Token access: admin on {c['admin_access']} of {c['found']} repositories, read-only on the rest._",
        "",
        "### Summary",
        "",
        "| Measure | Result |",
        "|---|---|",
        f"| Candidate repositories | {c['candidates']} ({c['found']} found, {c['not_found']} not found) |",
        f"| Active (pushed within {ACTIVE_WITHIN_DAYS} days, not archived) | {c['active']} |",
        f"| **Meet the baseline** (≥{MIN_REVIEWS} review, force pushes blocked, deletion blocked) | **{c['pass']} of {c['found']}** ({c['active_pass']} of {c['active']} active) |",
        f"| Require at least one approving review | {c['reviews_required']} of {c['found']} |",
        f"| Block force pushes | {c['force_blocked']} of {c['found']} |",
        f"| Block branch deletion | {c['deletion_blocked']} of {c['found']} |",
        f"| Require CI status checks | {c['checks_required']} of {c['found']} |",
        f"| Dismiss stale approvals | {c['stale_dismissed']} confirmed, {c['stale_unknown']} not visible without admin |",
        f"| CODEOWNERS file present / code owner review enforced | {c['codeowners_present']} / {c['codeowners_enforced']} |",
        f"| Admins bound by the rules (confirmed yes / confirmed no) | {c['admins_bound']} / {c['admins_not_bound']} (the rest are not visible without admin) |",
        f"| Repositories where unreviewed changes reached the default branch in the window | {c['unreviewed_changes']} of {c['found']} |",
        f"| PRs merged in window / merged without an independent approval | {c['pr_merges']} / {c['unapproved_merges']} |",
        f"| Direct pushes by people / force pushes to default branches in window | {c['direct_pushes']} / {c['force_pushes']} |",
        f"| Confirmed bypasses of a ruleset already in force² | {c['confirmed_bypasses']} across {c['confirmed_bypass_repos']} repositories |",
        "",
        "### Compliance matrix",
        "",
        "| # | Repository | Default branch | Protection | Required reviews | Dismiss stale approvals | CODEOWNERS review required | Force pushes | Deletions | Required CI status checks | Admins bound by rules | Baseline | Remediation status |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(results, 1):
        if not r["exists"]:
            lines.append(f"| {i} | {r['repo']} | — | — | — | — | — | — | — | — | — | ⚪ Not found | Confirm the repository name |")
            continue
        e = r["effective"]
        if e["pr_required"]:
            reviews = str(e["required_reviews"])
        elif e["pr_required"] is None:
            reviews = "0"
        else:
            reviews = "None"
        stale = "n/a" if not e["pr_required"] else _yes_no(e["dismiss_stale"])
        admins = "n/a" if r["protection_source"] == "None" else _yes_no(e["admins_enforced"])
        owners = r.get("codeowners") or {}
        if owners.get("present") is False:
            cor = "Yes, but no CODEOWNERS file" if e["code_owner_review"] else "No (no CODEOWNERS file)"
        else:
            cor = "Yes" if e["code_owner_review"] else "No"
        checks = f"Enforced ({len(e['status_checks'])})" if e["status_checks"] else "None"
        verdict = {"PASS": "✅ Pass", "FAIL": "❌ Fail", "UNKNOWN": "⚠️ Unknown"}[r["verdict"]]
        if r["verdict"] == "PASS":
            status = "Compliant" + (" — unreviewed changes observed" if r.get("unreviewed_changes") else "")
        elif r["verdict"] == "FAIL":
            status = "Open — needs repo admin"
        else:
            status = "Needs admin to verify"
        if not r.get("active"):
            status += " (inactive)"
        lines.append(
            f"| {i} | {_repo_link(r, org)} | `{r['default_branch']}` | {r['protection_source']} | {reviews} | {stale} | {cor} | "
            f"{'Blocked' if e['force_push_blocked'] else 'Allowed'} | {'Blocked' if e['deletion_blocked'] else 'Allowed'} | "
            f"{checks} | {admins} | {verdict} | {status} |"
        )
    lines += [
        "",
        "¹ Not visible without admin access. Classic protection hides “dismiss stale approvals” from read-only accounts. "
        "“Include administrators” is visible only when the classic rule also requires status checks, and ruleset bypass "
        "lists are admin-only. A repository admin can confirm these settings in Settings → Branches / Rules, or re-run this "
        "script with an admin token. A required review count of 0 means the rule asks for no approvals, so the baseline is not met.",
        "",
        f"### Observed practice since {window}",
        "",
        "Configuration only shows what is supposed to happen. These counts come from the repository activity log and merged pull "
        "requests, and show what actually reached each default branch. A non-zero count on a protected branch means someone "
        "with admin or bypass rights went around the rule, or the rule was added later in the window.",
        "",
        "| Repository | PRs merged | Merged without independent approval | Direct pushes (people) | Direct pushes (bots) | Force pushes | Confirmed ruleset bypasses² |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        if not r["exists"]:
            continue
        p = r["practice"]
        dash = "—"
        parts = []
        if p.get("review_rule_in_force_since") and "confirmed_bypass_pushes" in p:
            parts.append(f"{p['confirmed_bypass_pushes']} push(es) after {p['review_rule_in_force_since'][:10]}")
        if p.get("approval_rule_in_force_since") and "confirmed_bypass_merges" in p:
            parts.append(f"{p['confirmed_bypass_merges']} merge(s) after {p['approval_rule_in_force_since'][:10]}")
        confirmed = "; ".join(parts) or dash
        lines.append(
            f"| {r['repo']} | {p.get('pr_merges', dash)} | {p.get('unapproved_merges', dash)} | {p.get('direct_pushes', dash)} | "
            f"{p.get('bot_pushes', dash)} | {p.get('force_pushes', dash)} | {confirmed} |"
        )
    lines += [
        "",
        "² Only countable for repositories whose review rule is a ruleset, because GitHub shows when a ruleset was last changed. "
        "A direct push, or a merge with no independent approval, after that date went around a rule already in force. "
        "Admins and the ruleset's bypass list can do this. Classic protection shows no date, so those rows show —.",
        "",
        "### Remediation actions by repository",
        "",
    ]
    for r in results:
        if not r["exists"]:
            lines.append(f"- **{r['repo']}**: not found under `{org}`. Confirm the repository name or remove it from the candidate list.")
            continue
        items = [f"**Baseline:** {g}" for g in r["baseline_gaps"]] + list(r["recommendations"]) + [f"**Observed:** {o}" for o in r["observations"]]
        if not items:
            lines.append(f"- **{r['repo']}**: no action needed.")
            continue
        lines.append(f"- **{r['repo']}**")
        lines += [f"  - {item}" for item in items]
        if r.get("collection_errors"):
            lines.append(f"  - _Collection warnings: {'; '.join(r['collection_errors'])}_")
    return "\n".join(lines) + "\n"


def write_markdown(path: Path, block: str) -> None:
    generated = f"{BEGIN_MARK}\n{block}{END_MARK}\n"
    if path.exists():
        text = path.read_text()
        if BEGIN_MARK in text and END_MARK in text:
            head, rest = text.split(BEGIN_MARK, 1)
            tail = rest.split(END_MARK, 1)[1].lstrip("\n")
            path.write_text(head + generated + ("\n" + tail if tail else ""))
            return
        path.write_text(text.rstrip("\n") + "\n\n" + generated)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Branch Protection Compliance Matrix\n\n" + generated)


def issue_title(result: dict) -> str:
    branch = result["default_branch"]
    if result["verdict"] != "PASS":
        return f"Security: enable baseline branch protection on `{branch}`"
    return f"Security: unreviewed changes are reaching `{branch}`; tighten branch protection"


def render_issue_draft(result: dict, org: str, note: str = "") -> str:
    """Markdown issue for one repository. The first line is '# <title>'; the rest is the body."""
    branch, repo = result["default_branch"], result["repo"]
    failing = result["verdict"] != "PASS"
    matrix_url = GUIDE_URL.replace("standards/branch-protection-guide.md", "audits/branch_protection_compliance_matrix_fall2026.md")
    lines = [
        f"# {issue_title(result)}",
        "",
        f"The OSS-SLU security team audited branch protection on the default branch of 22 project repositories, "
        f"including this one (oss-slu/oss_cybersecurity#66). The baseline for every active project is: changes reach "
        f"`{branch}` through a pull request with at least 1 approving review, force pushes are blocked, and the branch "
        "cannot be deleted.",
        "",
        "**Result for this repository:** "
        + ("does **not** meet the baseline." if failing else "meets the baseline on paper, but unreviewed changes still reached "
           f"`{branch}` during the audit window, so the rules are not working as a control yet."),
    ]
    quick = [r for r in result["recommendations"] if r.startswith("Quick fix")]
    others = [r for r in result["recommendations"] if not r.startswith("Quick fix")]
    if failing:
        lines += ["", "## Required"] + [f"- [ ] {g}" for g in result["baseline_gaps"]]
        lines += [f"\n**Fastest fix:** {q[len('Quick fix: '):]}" for q in quick]
    else:
        others = quick + others
    if others:
        lines += ["", "## Recommended" if failing else "## What to change"] + [f"- [ ] {r}" for r in others]
    if result["observations"]:
        # PR numbers go in code spans so the issue does not add cross-reference events to old PRs.
        lines += ["", "## What the audit observed (counts only; no individuals are named)"]
        lines += ["- " + re.sub(r"#(\d+)", r"`#\1`", o) for o in result["observations"]]
    lines += ["", "## How to fix it (needs a repository admin, about 5 minutes)", ""]
    if failing:
        lines += [
            f"The [Branch Protection Guide]({GUIDE_URL}) has step-by-step instructions. The quickest option is to import the "
            "baseline ruleset in **Settings → Rules → Rulesets → New ruleset → Import a ruleset**. Alternatively, from a "
            "clone of [oss-slu/oss_cybersecurity](https://github.com/oss-slu/oss_cybersecurity):",
            "",
            "```bash",
            f"scripts/enforce-branch-protection.sh --repo {repo}           # dry run: shows the change",
            f"scripts/enforce-branch-protection.sh --repo {repo} --apply   # applies it (undo with --remove)",
            "```",
            "",
            "The baseline is added as a separate ruleset, so existing protection and required checks are left alone.",
        ]
    else:
        lines += [
            f"Section 3.4 of the [Branch Protection Guide]({GUIDE_URL}) covers each item above. The most important one is "
            "making sure admins can't skip review. Pull requests from students and outside contributors are unaffected.",
        ]
    lines += [
        "",
        f"To check the result: `python3 scripts/audit_branch_protection.py --repo {repo}` (from oss_cybersecurity). "
        f"Full results for all 22 repositories: [compliance matrix]({matrix_url}).",
    ]
    if note:
        lines += ["", note]
    lines += ["", "Disclosure: partially drafted with AI assistance."]
    return "\n".join(lines) + "\n"


def print_console(results: list[dict]) -> None:
    for r in results:
        if not r["exists"]:
            print(f"[MISS] {r['repo']}: not found")
            continue
        e = r["effective"]
        tag = {"PASS": "[PASS]", "FAIL": "[FAIL]", "UNKNOWN": "[????]"}[r["verdict"]]
        print(
            f"{tag} {r['repo']} ({r['default_branch']}, {r['protection_source']}, {r['access']}): "
            f"reviews={e['required_reviews'] if e['pr_required'] is not False else 'none'} "
            f"force-push={'blocked' if e['force_push_blocked'] else 'ALLOWED'} "
            f"deletion={'blocked' if e['deletion_blocked'] else 'ALLOWED'} "
            f"checks={len(e['status_checks'])}"
            + (" unreviewed-changes" if r.get("unreviewed_changes") else "")
        )
        for g in r["baseline_gaps"]:
            print(f"       [GAP] {g}")
    c = summary_counts(results)
    print(f"\n[SUMMARY] {c['pass']}/{c['found']} repositories meet the baseline ({c['active_pass']}/{c['active']} active); "
          f"{c['not_found']} not found; unreviewed changes reached the default branch in {c['unreviewed_changes']}.")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Audit default-branch protection against the OSS-SLU baseline (#66).")
    parser.add_argument("--org", default=DEFAULT_ORG)
    parser.add_argument("--repos-file", type=Path, default=DEFAULT_REPOS_FILE, help="candidate list, one repo per line")
    parser.add_argument("--repo", action="append", help="audit only this repository (repeatable)")
    parser.add_argument("--since", help="start of the practice window, YYYY-MM-DD (default: %d days ago)" % DEFAULT_WINDOW_DAYS)
    parser.add_argument("--json", type=Path, help="write full results as JSON")
    parser.add_argument("--markdown", type=Path, help="write or update the generated block in this Markdown file")
    parser.add_argument("--summary", type=Path, help="append the matrix to this file (e.g. $GITHUB_STEP_SUMMARY)")
    parser.add_argument("--issue-drafts", type=Path, help="write a remediation issue draft per non-compliant repo into this directory")
    parser.add_argument("--issue-note", default="", help="extra line appended to every issue draft")
    parser.add_argument("--compare", type=Path, help="previous --json snapshot to check for regressions")
    parser.add_argument("--fail-on-violation", action="store_true", help="exit 2 if any active repository fails the baseline")
    parser.add_argument("--fail-on-regression", action="store_true", help="exit 3 if any control got weaker since --compare")
    parser.add_argument("--include-actors", action="store_true", help="include GitHub logins for direct/force pushes (kept out of published reports by default)")
    parser.add_argument("--branch", help="audit this branch instead of each repository's default branch (testing)")
    parser.add_argument("--read-only", action="store_true", help="use only read-level APIs even if the token has admin access")
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args(argv)

    now = dt.datetime.now(dt.timezone.utc)
    since = (
        dt.datetime.fromisoformat(args.since).replace(tzinfo=dt.timezone.utc)
        if args.since
        else now - dt.timedelta(days=DEFAULT_WINDOW_DAYS)
    )
    repos = args.repo or load_repo_list(args.repos_file)
    client = GhClient()

    print(f"[*] Auditing {len(repos)} repositories in {args.org} (practice window from {since.date()})\n")
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            raws = list(pool.map(
                lambda name: collect_repo(client, args.org, name, since, now, args.branch, args.read_only), repos
            ))
    except GhError as err:
        print(f"[ERROR] GitHub API call failed: {err}", file=sys.stderr)
        return 1
    results = [evaluate(raw, since, now, include_actors=args.include_actors) for raw in raws]
    print_console(results)

    meta = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": iso(now),
        "org": args.org,
        "window_start": iso(since),
        "window_end": iso(now),
        "baseline": {"min_approving_reviews": MIN_REVIEWS, "force_pushes": "blocked", "deletions": "blocked"},
    }
    block = render_matrix(results, meta)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({**meta, "summary": summary_counts(results), "results": results}, indent=2) + "\n")
        print(f"[*] Wrote {args.json}")
    if args.markdown:
        write_markdown(args.markdown, block)
        print(f"[*] Updated {args.markdown}")
    if args.summary:
        with args.summary.open("a") as fh:
            fh.write("## Branch protection audit\n\n" + block + "\n")
    if args.issue_drafts:
        args.issue_drafts.mkdir(parents=True, exist_ok=True)
        count = 0
        for r in results:
            if r["exists"] and (r["verdict"] != "PASS" or r["observations"]):
                (args.issue_drafts / f"{r['repo']}.md").write_text(render_issue_draft(r, args.org, args.issue_note))
                count += 1
        print(f"[*] Wrote {count} issue draft(s) to {args.issue_drafts}")

    exit_code = 0
    if args.compare:
        previous = json.loads(args.compare.read_text())
        regressions = find_regressions(previous.get("results", []), results)
        if regressions:
            print("\n[REGRESSION] Branch protection got weaker since the last snapshot:")
            for line in regressions:
                print(f"  - {line}")
            if args.summary:
                with args.summary.open("a") as fh:
                    fh.write("### Regressions since last snapshot\n\n" + "\n".join(f"- {x}" for x in regressions) + "\n")
            if args.fail_on_regression:
                exit_code = 3
        else:
            print("\n[OK] No regressions since the last snapshot.")
    if args.fail_on_violation and any(r.get("active") and r.get("verdict") == "FAIL" for r in results):
        print("[ERROR] At least one active repository does not meet the baseline.")
        exit_code = exit_code or 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
