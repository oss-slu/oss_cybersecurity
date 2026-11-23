#!/usr/bin/env python3
"""
diff-code-futures.py - compare two Code Futures snapshots and report practice drift.

A Code Futures snapshot (schema `code-futures/v1`, from oss-slu/code-futures) records,
for each repository, one outcome per probe: enforced, present, absent or unreadable.
This script compares an older snapshot with a newer one and lists:

  * practices that improved   (absent -> present -> enforced)
  * practices that regressed  (the same steps in reverse)
  * findings that became readable or unreadable (a change in what the tool could see,
    not a change in the repository)
  * hotspot migrations        (files that newly became, or stopped being, hotspots)
  * repositories that appear in only one of the two snapshots

Three rules come from the Code Futures schema and are easy to get wrong:

  1. `unreadable` describes the tool, not the repository. A move to or from
     `unreadable` is never counted as an improvement or a regression.
  2. For the Structure probes and `deps.known_vulnerabilities`, `absent` is the good
     outcome ("nothing found"). For those probes present -> absent is an improvement.
  3. `lint` and `format` are answered once per language, so a finding is identified
     by (repository, probe id, language), not by probe id alone.

Requires Python 3.9+. Standard library only.

Every path given on the command line must be inside this repository. Relative paths
are resolved against the repository root.

Usage:
  python3 scripts/diff-code-futures.py OLD.json NEW.json              # Markdown to stdout
  python3 scripts/diff-code-futures.py OLD.json NEW.json -o drift.md
  python3 scripts/diff-code-futures.py OLD.json NEW.json --json drift.json
  python3 scripts/diff-code-futures.py OLD.json NEW.json --fail-on-regression
  python3 scripts/diff-code-futures.py OLD.json NEW.json --rename enroll-dash=geo-enricher

Exit codes: 0 = ok, 1 = error, 3 = regressions found (with --fail-on-regression).

Ref: oss-slu/oss_cybersecurity#69
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = str(Path(__file__).resolve().parent.parent)
SCHEMA = "code-futures/v1"
OUTCOMES = ("enforced", "present", "absent", "unreadable")

# Probes where `absent` means "the analysis found nothing", which is the good result.
INVERTED_PREFIXES = ("structure.",)
INVERTED_IDS = frozenset({"deps.known_vulnerabilities"})

NORMAL_RANK = {"absent": 0, "present": 1, "enforced": 2}
INVERTED_RANK = {"present": 0, "absent": 1}

Key = tuple  # (probe id, language or None)


class SnapshotError(ValueError):
    """The file is not a usable code-futures/v1 snapshot."""


def safe_path(path: Any, root: Optional[str] = None) -> str:
    """Resolve a path given on the command line and refuse anything outside the repository.

    Relative paths are resolved against the repository root. The scripts only ever need
    files inside the repository, so a path that resolves elsewhere is an error.
    """
    base = os.path.realpath(root or REPO_ROOT)
    resolved = os.path.realpath(os.path.join(base, str(path)))
    if resolved != base and not resolved.startswith(base + os.sep):
        raise SnapshotError(f"{path}: path must be inside {base}")
    return resolved


def read_text(path: Any, root: Optional[str] = None) -> str:
    with open(safe_path(path, root), encoding="utf-8") as fh:
        return fh.read()


def write_text(path: Any, text: str, root: Optional[str] = None) -> None:
    with open(safe_path(path, root), "w", encoding="utf-8") as fh:
        fh.write(text)


def is_inverted(probe_id: str) -> bool:
    return probe_id in INVERTED_IDS or probe_id.startswith(INVERTED_PREFIXES)


def load_snapshot(path: Any, root: Optional[str] = None) -> dict[str, Any]:
    try:
        data = json.loads(read_text(path, root))
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"{path}: cannot read snapshot ({exc})") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        got = data.get("schema") if isinstance(data, dict) else None
        raise SnapshotError(f"{path}: expected schema {SCHEMA}, got {got!r}")
    if not isinstance(data.get("reports"), list):
        raise SnapshotError(f"{path}: snapshot has no 'reports' list")
    return data


def parse_renames(pairs: Optional[list[str]]) -> dict[str, str]:
    """`OLD=NEW` pairs for repositories renamed between snapshots (names without the owner)."""
    out: dict[str, str] = {}
    for pair in pairs or []:
        old, sep, new = pair.partition("=")
        if not sep or not old.strip() or not new.strip():
            raise SnapshotError(f"--rename expects OLD=NEW, got {pair!r}")
        out[old.strip().lower()] = new.strip()
    return out


def index_reports(snapshot: dict[str, Any], renames: Optional[dict[str, str]] = None) -> dict[str, dict[str, Any]]:
    """Reports keyed by lower-cased repository name. GitHub names are case-insensitive.

    A repository listed under an old name is re-keyed (and relabelled) to its current
    name, so a rename does not show up as one repository vanishing and another appearing.
    """
    out: dict[str, dict[str, Any]] = {}
    for r in snapshot["reports"]:
        owner, _, name = r["repository"].rpartition("/")
        new = (renames or {}).get(name.lower())
        if new:
            r = dict(r, repository=f"{owner}/{new}" if owner else new)
        out[r["repository"].lower()] = r
    return out


def index_probes(report: dict[str, Any]) -> dict[Key, dict[str, Any]]:
    out: dict[Key, dict[str, Any]] = {}
    for p in report.get("probes", []):
        if p.get("outcome") not in OUTCOMES:
            raise SnapshotError(f"{report.get('repository')}: unknown outcome {p.get('outcome')!r} on {p.get('id')}")
        out[(p["id"], p.get("language"))] = p
    return out


def classify(probe_id: str, old: Optional[str], new: Optional[str]) -> str:
    """One of: unchanged, improved, regressed, became_readable, became_unreadable, added, removed."""
    if old is None:
        return "added"
    if new is None:
        return "removed"
    if old == new:
        return "unchanged"
    if old == "unreadable":
        return "became_readable"
    if new == "unreadable":
        return "became_unreadable"
    rank = INVERTED_RANK if is_inverted(probe_id) else NORMAL_RANK
    if old not in rank or new not in rank:
        # e.g. `enforced` on a probe where absent is the good result. Not comparable.
        return "unchanged"
    return "improved" if rank[new] > rank[old] else "regressed"


def hotspot_files(probes: dict[Key, dict[str, Any]]) -> Optional[tuple[list[str], Optional[str]]]:
    """(hotspot files, top hotspot) or None when the probe is missing or unreadable."""
    p = probes.get(("structure.hotspots", None))
    if p is None or p["outcome"] == "unreadable":
        return None
    files = list(p.get("evidence", []))
    top = (p.get("attributes") or {}).get("top") or (files[0] if files else None)
    return files, top


def diff_snapshots(
    old: dict[str, Any], new: dict[str, Any], renames: Optional[dict[str, str]] = None
) -> dict[str, Any]:
    old_reports, new_reports = index_reports(old, renames), index_reports(new, renames)
    changes: list[dict[str, Any]] = []
    hotspots: list[dict[str, Any]] = []

    for name in sorted(old_reports.keys() & new_reports.keys()):
        repo = new_reports[name]["repository"]
        op, np_ = index_probes(old_reports[name]), index_probes(new_reports[name])
        for key in sorted(op.keys() | np_.keys(), key=lambda k: (k[0], k[1] or "")):
            o = op[key]["outcome"] if key in op else None
            n = np_[key]["outcome"] if key in np_ else None
            kind = classify(key[0], o, n)
            if kind == "unchanged":
                continue
            changes.append(
                {
                    "repository": repo,
                    "probe": key[0],
                    "language": key[1],
                    "old": o,
                    "new": n,
                    "change": kind,
                    "tool": (np_.get(key) or op.get(key) or {}).get("tool"),
                }
            )
        oh, nh = hotspot_files(op), hotspot_files(np_)
        if oh is not None and nh is not None:
            entered = [f for f in nh[0] if f not in oh[0]]
            left = [f for f in oh[0] if f not in nh[0]]
            if entered or left or oh[1] != nh[1]:
                hotspots.append(
                    {"repository": repo, "entered": entered, "left": left, "old_top": oh[1], "new_top": nh[1]}
                )

    def of(kind: str) -> list[dict[str, Any]]:
        return [c for c in changes if c["change"] == kind]

    return {
        "schema": "code-futures-drift/v1",
        "old_collected_at": old.get("collected_at"),
        "new_collected_at": new.get("collected_at"),
        "repositories_compared": len(old_reports.keys() & new_reports.keys()),
        "only_in_old": sorted(old_reports[n]["repository"] for n in old_reports.keys() - new_reports.keys()),
        "only_in_new": sorted(new_reports[n]["repository"] for n in new_reports.keys() - old_reports.keys()),
        "improved": of("improved"),
        "regressed": of("regressed"),
        "became_readable": of("became_readable"),
        "became_unreadable": of("became_unreadable"),
        "added": of("added"),
        "removed": of("removed"),
        "hotspot_migrations": hotspots,
    }


def _short(repository: str) -> str:
    return repository.split("/", 1)[-1]


def _probe_label(c: dict[str, Any]) -> str:
    return f"`{c['probe']}`" + (f" ({c['language']})" if c.get("language") else "")


def _table(rows: list[dict[str, Any]]) -> list[str]:
    out = ["| Repository | Probe | Was | Now |", "|---|---|---|---|"]
    for c in rows:
        out.append(f"| `{_short(c['repository'])}` | {_probe_label(c)} | {c['old'] or '-'} | {c['new'] or '-'} |")
    return out


def render_markdown(d: dict[str, Any]) -> str:
    lines = [
        "# Code Futures Drift Summary",
        "",
        f"**From:** {d['old_collected_at']}  ",
        f"**To:** {d['new_collected_at']}  ",
        f"**Repositories compared:** {d['repositories_compared']}",
        "",
        "| Improved | Regressed | Became readable | Became unreadable | Hotspot migrations |",
        "|---|---|---|---|---|",
        f"| {len(d['improved'])} | {len(d['regressed'])} | {len(d['became_readable'])} "
        f"| {len(d['became_unreadable'])} | {len(d['hotspot_migrations'])} |",
        "",
        "A move to or from `unreadable` is a change in what the tool could see. It is not counted as an "
        "improvement or a regression. For Structure probes and `deps.known_vulnerabilities`, `absent` is "
        "the good outcome.",
        "",
    ]
    sections = (
        ("Practices that regressed", "regressed", "No practice regressed."),
        ("Practices that improved", "improved", "No practice improved."),
        ("Became readable", "became_readable", ""),
        ("Became unreadable", "became_unreadable", ""),
    )
    for title, key, empty in sections:
        if not d[key] and not empty:
            continue
        lines += [f"## {title}", ""]
        lines += _table(d[key]) if d[key] else [empty]
        lines.append("")

    lines += ["## Hotspot migrations", ""]
    if d["hotspot_migrations"]:
        for h in d["hotspot_migrations"]:
            lines.append(f"**`{_short(h['repository'])}`**")
            if h["old_top"] != h["new_top"]:
                lines.append(f"- Top hotspot moved from `{h['old_top']}` to `{h['new_top']}`")
            lines += [f"- New hotspot: `{f}`" for f in h["entered"]]
            lines += [f"- No longer a hotspot: `{f}`" for f in h["left"]]
            lines.append("")
    else:
        lines += ["No hotspot changed.", ""]

    for title, key in (("Only in the older snapshot", "only_in_old"), ("Only in the newer snapshot", "only_in_new")):
        if d[key]:
            lines += [f"## {title}", ""] + [f"- `{r}`" for r in d[key]] + [""]
    for title, key in (("Findings new in this snapshot", "added"), ("Findings no longer reported", "removed")):
        if d[key]:
            lines += [f"## {title}", ""] + _table(d[key]) + [""]
    return "\n".join(lines).rstrip() + "\n"


def main(argv: Optional[list[str]] = None, root: Optional[str] = None) -> int:
    ap = argparse.ArgumentParser(description="Compare two Code Futures snapshots and report practice drift.")
    ap.add_argument("old", type=Path, help="older snapshot (code-futures/v1 JSON)")
    ap.add_argument("new", type=Path, help="newer snapshot (code-futures/v1 JSON)")
    ap.add_argument("-o", "--output", type=Path, help="write the Markdown summary here instead of stdout")
    ap.add_argument("--json", type=Path, dest="json_out", help="also write the drift as JSON")
    ap.add_argument(
        "--rename",
        action="append",
        metavar="OLD=NEW",
        help="treat repository OLD as NEW (renamed between snapshots); repeatable",
    )
    ap.add_argument("--fail-on-regression", action="store_true", help="exit 3 if any practice regressed")
    args = ap.parse_args(argv)

    try:
        drift = diff_snapshots(load_snapshot(args.old, root), load_snapshot(args.new, root), parse_renames(args.rename))
    except SnapshotError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    md = render_markdown(drift)
    try:
        if args.output:
            write_text(args.output, md, root)
        else:
            sys.stdout.write(md)
        if args.json_out:
            write_text(args.json_out, json.dumps(drift, indent=2) + "\n", root)
    except (OSError, SnapshotError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 3 if args.fail_on_regression and drift["regressed"] else 0


if __name__ == "__main__":
    sys.exit(main())
