#!/usr/bin/env bash
# enforce-branch-protection.sh - apply the OSS-SLU baseline branch protection ruleset
#
# Adds (or updates) one repository ruleset named "oss-slu-baseline" on the default branch:
#   - pull request required, at least 1 approving review, stale approvals dismissed on push
#   - force pushes blocked (non_fast_forward)
#   - branch deletion blocked
#
# Why a ruleset: GitHub enforces rulesets and classic branch protection together, and the
# stricter setting wins. Adding a separate ruleset therefore never removes or loosens a
# repository's existing protection, required status checks, or other rulesets, and the
# change can be undone by deleting that one ruleset (--remove).
#
# Dry run is the default. Nothing changes unless --apply (or --remove) is given.
# Applying needs admin access on each target repository (or org owner for --org-ruleset).
#
# Requires: gh (logged in) and jq. Works with macOS bash 3.2.
# Ref: oss-slu/oss_cybersecurity#66

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ORG="oss-slu"
RULESET_FILE="$REPO_ROOT/docs/standards/branch-protection-baseline.ruleset.json"
CANDIDATES="$SCRIPT_DIR/branch_protection_candidates.txt"
MODE="plan"          # plan | apply | remove
BRANCH=""            # empty = ~DEFAULT_BRANCH
ORG_RULESET=0
REQUIRE_CODE_OWNERS=0
REPOS=()

usage() {
  cat <<'EOF'
Usage: scripts/enforce-branch-protection.sh (--repo NAME ... | --all) [options]

Targets
  --repo NAME             repository to protect (repeatable)
  --all                   every repository in scripts/branch_protection_candidates.txt
  --org ORG               organization or user that owns the repositories (default: oss-slu)

Actions (default is a dry run that only prints the plan)
  --apply                 create or update the "oss-slu-baseline" ruleset
  --remove                delete the "oss-slu-baseline" ruleset (rollback)

Options
  --branch NAME           protect this branch instead of the default branch (useful for testing)
  --require-code-owners   also require code owner review on repositories that have a CODEOWNERS file
  --ruleset FILE          ruleset definition (default: docs/standards/branch-protection-baseline.ruleset.json)
  --org-ruleset           plan or apply ONE organization ruleset that covers all target repositories
                          (needs an org owner token with the admin:org scope)
  -h, --help              show this help

Examples
  scripts/enforce-branch-protection.sh --all                       # what would change, everywhere
  scripts/enforce-branch-protection.sh --repo TULIP --apply        # protect one repository
  scripts/enforce-branch-protection.sh --repo TULIP --remove       # undo
  scripts/enforce-branch-protection.sh --all --org-ruleset         # preview the single org-level ruleset

Exit codes: 0 = ok, 1 = error, 2 = one or more repositories were skipped (missing admin access or not found)
EOF
}

die() { echo "[ERROR] $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) [ $# -ge 2 ] || die "--repo needs a value"; REPOS+=("$2"); shift 2 ;;
    --all) while IFS= read -r line; do
             name="${line%%#*}"; name="$(echo "$name" | tr -d '[:space:]')"
             [ -n "$name" ] && REPOS+=("$name")
           done < "$CANDIDATES"; shift ;;
    --org) [ $# -ge 2 ] || die "--org needs a value"; ORG="$2"; shift 2 ;;
    --apply) MODE="apply"; shift ;;
    --remove) MODE="remove"; shift ;;
    --branch) [ $# -ge 2 ] || die "--branch needs a value"; BRANCH="$2"; shift 2 ;;
    --require-code-owners) REQUIRE_CODE_OWNERS=1; shift ;;
    --ruleset) [ $# -ge 2 ] || die "--ruleset needs a value"; RULESET_FILE="$2"; shift 2 ;;
    --org-ruleset) ORG_RULESET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

[ ${#REPOS[@]} -gt 0 ] || { usage >&2; die "choose --repo NAME or --all"; }
command -v gh >/dev/null || die "the GitHub CLI (gh) is required"
command -v jq >/dev/null || die "jq is required"
[ -f "$RULESET_FILE" ] || die "ruleset file not found: $RULESET_FILE"
gh auth status >/dev/null 2>&1 || die "gh is not logged in (run: gh auth login)"
RULESET_NAME="$(jq -r .name "$RULESET_FILE")"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# jq helper: true when every key/value in the desired ruleset is already present in the live one.
JQ_SUBSET='
def subset($b):
  if type == "object" then
    (($b | type) == "object") and (. as $a | all(keys[]; . as $k | ($b | has($k)) and ($a[$k] | subset($b[$k]))))
  elif type == "array" then
    (($b | type) == "array") and (length == ($b | length)) and all(.[]; . as $x | any($b[]; . as $y | $x | subset($y)))
  else . == $b end;
'

# Build the payload for one repository: $1 = include CODEOWNERS review (0/1)
build_payload() {
  local code_owners="$1"
  jq --arg branch "$BRANCH" --argjson co "$code_owners" '
    {name, target, enforcement, conditions, rules, bypass_actors}
    | if $branch != "" then .conditions.ref_name.include = ["refs/heads/" + $branch] else . end
    | if $co == 1 then .rules |= map(if .type == "pull_request" then .parameters.require_code_owner_review = true else . end) else . end
  ' "$RULESET_FILE"
}

# One-line view of what protects the branch today.
# Admins read the authoritative REST endpoint. Everyone else reads GraphQL refUpdateRule, which
# shows the rule as it applies to the viewer (accurate for non-admins, who are always bound by it).
current_state() {
  local repo="$1" branch="$2" admin="$3" rules classic
  rules="$(gh api "repos/$ORG/$repo/rules/branches/$branch" --jq '[.[].type] | unique | join(",")' 2>/dev/null || echo "?")"
  if [ "$admin" = "true" ]; then
    classic="$(gh api "repos/$ORG/$repo/branches/$branch/protection" \
      --jq '"reviews=\(.required_pull_request_reviews.required_approving_review_count // "none") force-push=\(if .allow_force_pushes.enabled then "allowed" else "blocked" end) deletion=\(if .allow_deletions.enabled then "allowed" else "blocked" end)"' 2>/dev/null || echo "none")"
  else
    classic="$(gh api graphql -f query="query { repository(owner: \"$ORG\", name: \"$repo\") { ref(qualifiedName: \"refs/heads/$branch\") { refUpdateRule { requiredApprovingReviewCount allowsForcePushes allowsDeletions } } } }" \
      --jq '.data.repository.ref.refUpdateRule | if . == null then "none" else "reviews=\(.requiredApprovingReviewCount // "none") force-push=\(if .allowsForcePushes then "allowed" else "blocked" end) deletion=\(if .allowsDeletions then "allowed" else "blocked" end)" end' 2>/dev/null || echo "?")"
  fi
  echo "classic[$classic] rulesets[${rules:-none}]"
}

# Confirm the live rules on the branch now meet the baseline.
verify_branch() {
  local repo="$1" branch="$2"
  gh api "repos/$ORG/$repo/rules/branches/$branch" --jq '
    ([.[] | select(.type == "deletion")] | length > 0) and
    ([.[] | select(.type == "non_fast_forward")] | length > 0) and
    ([.[] | select(.type == "pull_request" and .parameters.required_approving_review_count >= 1)] | length > 0)'
}

org_ruleset() {
  local payload="$TMP_DIR/org-ruleset.json" names existing_id
  names="$(printf '%s\n' "${REPOS[@]}" | jq -R . | jq -s .)"
  build_payload 0 | jq --argjson names "$names" '.conditions.repository_name = {include: $names, exclude: [], protected: true}' > "$payload"
  echo "[*] Organization ruleset \"$RULESET_NAME\" for $ORG covering ${#REPOS[@]} repositories:"
  jq . "$payload"
  if [ "$MODE" = "plan" ]; then
    echo "[DRY RUN] Re-run with --apply as an org owner (gh auth refresh -s admin:org) to create it."
    return 0
  fi
  existing_id="$(gh api "orgs/$ORG/rulesets" --paginate --jq ".[] | select(.name == \"$RULESET_NAME\") | .id")" \
    || die "cannot read org rulesets; this needs an org owner token with the admin:org scope"
  existing_id="${existing_id%%$'\n'*}"
  if [ "$MODE" = "remove" ]; then
    [ -n "$existing_id" ] || { echo "[OK] No org ruleset named $RULESET_NAME; nothing to remove."; return 0; }
    gh api --method DELETE "orgs/$ORG/rulesets/$existing_id" >/dev/null && echo "[REMOVED] org ruleset $existing_id"
  elif [ -n "$existing_id" ]; then
    gh api --method PUT "orgs/$ORG/rulesets/$existing_id" --input "$payload" >/dev/null && echo "[UPDATED] org ruleset $existing_id"
  else
    gh api --method POST "orgs/$ORG/rulesets" --input "$payload" --jq '"[CREATED] org ruleset \(.id)"'
  fi
}

if [ "$ORG_RULESET" -eq 1 ]; then
  org_ruleset
  exit 0
fi

echo "[*] Mode: $MODE | ruleset: $RULESET_NAME | org: $ORG | target: ${BRANCH:-default branch} | repositories: ${#REPOS[@]}"
[ "$MODE" = "plan" ] && echo "[*] Dry run: nothing will be changed. Add --apply to make changes."
echo

skipped=0 changed=0 unchanged=0
for repo in "${REPOS[@]}"; do
  meta="$TMP_DIR/meta.json"
  if ! gh api "repos/$ORG/$repo" > "$meta" 2>/dev/null; then
    echo "[SKIP] $repo: repository not found under $ORG"; skipped=$((skipped + 1)); continue
  fi
  if [ "$(jq -r .archived "$meta")" = "true" ]; then
    echo "[SKIP] $repo: archived (read-only)"; continue
  fi
  real_repo="$(jq -r '.name' "$meta")"
  branch="${BRANCH:-$(jq -r .default_branch "$meta")}"
  is_admin="$(jq -r '.permissions.admin // false' "$meta")"
  has_codeowners=0
  gh api "repos/$ORG/$real_repo/codeowners/errors" >/dev/null 2>&1 && has_codeowners=1
  co_flag=0
  [ "$REQUIRE_CODE_OWNERS" -eq 1 ] && [ "$has_codeowners" -eq 1 ] && co_flag=1

  payload="$TMP_DIR/$real_repo.json"
  build_payload "$co_flag" > "$payload"
  echo "== $ORG/$real_repo ($branch)"
  echo "   now:     $(current_state "$real_repo" "$branch" "$is_admin")"

  existing_id=""
  if [ "$is_admin" = "true" ]; then
    existing_id="$(gh api "repos/$ORG/$real_repo/rulesets" --paginate \
      --jq ".[] | select(.name == \"$RULESET_NAME\" and .source_type == \"Repository\") | .id")"
    existing_id="${existing_id%%$'\n'*}"
  fi

  if [ "$MODE" = "remove" ]; then
    if [ "$is_admin" != "true" ]; then
      echo "   [SKIP] needs admin access to remove rulesets"; skipped=$((skipped + 1))
    elif [ -z "$existing_id" ]; then
      echo "   [OK] no $RULESET_NAME ruleset; nothing to remove"; unchanged=$((unchanged + 1))
    else
      gh api --method DELETE "repos/$ORG/$real_repo/rulesets/$existing_id" >/dev/null
      echo "   [REMOVED] ruleset $existing_id"; changed=$((changed + 1))
    fi
    continue
  fi

  action="CREATE"
  if [ -n "$existing_id" ]; then
    gh api "repos/$ORG/$real_repo/rulesets/$existing_id" > "$TMP_DIR/live.json"
    if jq -e --slurpfile live "$TMP_DIR/live.json" "$JQ_SUBSET"' subset($live[0])' "$payload" >/dev/null; then
      action="NOOP"
    else
      action="UPDATE"
    fi
  fi

  if [ "$is_admin" != "true" ]; then
    echo "   [SKIP] needs admin access (planned action: CREATE or UPDATE the $RULESET_NAME ruleset)"
    skipped=$((skipped + 1)); continue
  fi
  echo "   plan:    $action ruleset \"$RULESET_NAME\"$( [ "$co_flag" -eq 1 ] && echo " (with code owner review)")"
  if [ "$MODE" = "plan" ] || [ "$action" = "NOOP" ]; then
    [ "$action" = "NOOP" ] && unchanged=$((unchanged + 1))
    continue
  fi

  if [ "$action" = "CREATE" ]; then
    new_id="$(gh api --method POST "repos/$ORG/$real_repo/rulesets" --input "$payload" --jq .id)"
    echo "   [CREATED] ruleset $new_id"
  else
    gh api --method PUT "repos/$ORG/$real_repo/rulesets/$existing_id" --input "$payload" >/dev/null
    echo "   [UPDATED] ruleset $existing_id"
  fi
  changed=$((changed + 1))
  if [ "$(verify_branch "$real_repo" "$branch")" = "true" ]; then
    echo "   [VERIFIED] $branch now requires a reviewed PR and blocks force pushes and deletion"
  else
    die "$real_repo: ruleset was written but the branch does not show the baseline rules"
  fi
done

echo
echo "[SUMMARY] mode=$MODE changed=$changed unchanged=$unchanged skipped=$skipped"
if [ "$skipped" -gt 0 ]; then
  echo "[NOTE] Skipped repositories need a repository admin (or an org owner using --org-ruleset)."
  exit 2
fi
