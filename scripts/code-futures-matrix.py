#!/usr/bin/env python3
"""
code-futures-matrix.py - build the per-repository practice table from a Code Futures snapshot.

Reads a `code-futures/v1` snapshot (oss-slu/code-futures) and prints one Markdown table
row per candidate repository: outcome counts, the top hotspot file, and, when a
directory of rendered Code Futures reports is given, each report's "Where to start"
suggestion and the first follow-up item.

The counts are an index for finding your place in a report. They are not a score:
`unreadable` is the tool's gap, and for Structure probes `absent` is the good outcome.

Requires Python 3.9+. Standard library only.

The snapshot, fill, candidates and output paths must be inside this repository.
Relative paths are resolved against the repository root.

Usage:
  python3 scripts/code-futures-matrix.py SNAPSHOT.json
  python3 scripts/code-futures-matrix.py SNAPSHOT.json --fill NEWER.json \\
      --rename enroll-dash=geo-enricher --reports DIR [--reports DIR2] -o table.md

  --fill     a second snapshot used only for candidates missing from SNAPSHOT;
             those rows are marked with the fill snapshot's date
  --reports  directory of rendered reports named <owner>_<repository>.md; repeatable,
             earlier directories win

Exit codes: 0 = ok, 1 = error.

Ref: oss-slu/oss_cybersecurity#69
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = str(Path(__file__).resolve().parent.parent)
SCHEMA = "code-futures/v1"
OUTCOMES = ("enforced", "present", "absent", "unreadable")
DEFAULT_CANDIDATES = Path(__file__).resolve().parent / "branch_protection_candidates.txt"

LEAD_RE = re.compile(r"Our suggestion here is \*\*(.+?)\*\*")
THEN_RE = re.compile(r"^1\. \*\*(.+?)\*\*", re.MULTILINE)
NOTHING = "Nothing in this report needs action"


def safe_path(path: Any, root: Optional[str] = None) -> str:
    """Resolve a path given on the command line and refuse anything outside the repository.

    Relative paths are resolved against the repository root. The scripts only ever need
    files inside the repository, so a path that resolves elsewhere is an error.
    """
    base = os.path.realpath(root or REPO_ROOT)
    resolved = os.path.realpath(os.path.join(base, str(path)))
    if resolved != base and not resolved.startswith(base + os.sep):
        raise ValueError(f"{path}: path must be inside {base}")
    return resolved


def read_text(path: Any, root: Optional[str] = None) -> str:
    with open(safe_path(path, root), encoding="utf-8") as fh:
        return fh.read()


def write_text(path: Any, text: str, root: Optional[str] = None) -> None:
    with open(safe_path(path, root), "w", encoding="utf-8") as fh:
        fh.write(text)


def load_snapshot(path: Any, root: Optional[str] = None) -> dict[str, Any]:
    data = json.loads(read_text(path, root))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("reports"), list):
        raise ValueError(f"{path}: not a {SCHEMA} snapshot")
    return data


def load_candidates(path: Any, root: Optional[str] = None) -> list[str]:
    names = []
    for line in read_text(path, root).splitlines():
        name = line.split("#", 1)[0].strip()
        if name:
            names.append(name)
    return names


def parse_renames(pairs: Optional[list[str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in pairs or []:
        old, sep, new = pair.partition("=")
        if not sep or not old.strip() or not new.strip():
            raise ValueError(f"--rename expects OLD=NEW, got {pair!r}")
        out[old.strip().lower()] = new.strip()
    return out


def index_reports(snapshot: dict[str, Any], renames: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Reports keyed by lower-cased current repository name (without the owner)."""
    out = {}
    for r in snapshot["reports"]:
        name = r["repository"].rpartition("/")[2]
        out[renames.get(name.lower(), name).lower()] = r
    return out


def counts(report: dict[str, Any]) -> dict[str, int]:
    c = dict.fromkeys(OUTCOMES, 0)
    for p in report.get("probes", []):
        c[p["outcome"]] += 1
    return c


def top_hotspot(report: dict[str, Any]) -> str:
    for p in report.get("probes", []):
        if p["id"] == "structure.hotspots":
            if p["outcome"] == "unreadable":
                return "unreadable"
            top = (p.get("attributes") or {}).get("top") or next(iter(p.get("evidence", [])), None)
            return f"`{top}`" if top else "none found"
    return "unreadable"


def find_report_file(report: dict[str, Any], dirs: list[Path]) -> Optional[Path]:
    """The rendered report for this repository, under the name it had when rendered."""
    stem = report["repository"].replace("/", "_").lower()
    for d in dirs:
        for f in sorted(Path(d).glob("*.md")):
            if f.stem.lower() == stem:
                return f
    return None


def where_to_start(report: dict[str, Any], dirs: list[Path]) -> tuple[str, str]:
    """(primary suggestion, first follow-up) from the rendered report, or ('-', '-')."""
    f = find_report_file(report, dirs)
    if f is None:
        return "-", "-"
    text = f.read_text(encoding="utf-8")
    if NOTHING in text:
        return "Nothing needs action", "-"
    lead, then = LEAD_RE.search(text), THEN_RE.search(text)
    cap = lambda s: s[:1].upper() + s[1:]  # noqa: E731
    return (cap(lead.group(1)) if lead else "-", then.group(1).rstrip(".") if then else "-")


def build_rows(
    candidates: list[str],
    base: dict[str, Any],
    fill: Optional[dict[str, Any]],
    renames: dict[str, str],
    report_dirs: list[Path],
) -> list[dict[str, Any]]:
    base_idx = index_reports(base, renames)
    fill_idx = index_reports(fill, renames) if fill else {}
    rows = []
    for name in candidates:
        report, source = base_idx.get(name.lower()), base
        if report is None and name.lower() in fill_idx:
            report, source = fill_idx[name.lower()], fill
        if report is None:
            rows.append({"name": name, "missing": True})
            continue
        lead, then = where_to_start(report, report_dirs)
        rows.append(
            {
                "name": name,
                "missing": False,
                "filled": source is not base,
                "collected": (report.get("collected_at") or source.get("collected_at") or "")[:10],
                "findings": len(report.get("probes", [])),
                "counts": counts(report),
                "hotspot": top_hotspot(report),
                "start": lead,
                "then": then,
            }
        )
    return rows


def render_table(rows: list[dict[str, Any]]) -> str:
    out = [
        "| Repository | Enforced | Present | Absent | Unreadable | Findings | Top hotspot file | Where to start | Next action |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        if r["missing"]:
            out.append(f"| `{r['name']}` | - | - | - | - | - | not in snapshot | - | - |")
            continue
        c = r["counts"]
        mark = f" ({r['collected']})" if r["filled"] else ""
        out.append(
            f"| `{r['name']}`{mark} | {c['enforced']} | {c['present']} | {c['absent']} | {c['unreadable']} "
            f"| {r['findings']} | {r['hotspot']} | {r['start']} | {r['then']} |"
        )
    return "\n".join(out) + "\n"


def main(argv: Optional[list[str]] = None, root: Optional[str] = None) -> int:
    ap = argparse.ArgumentParser(description="Per-repository practice table from a Code Futures snapshot.")
    ap.add_argument("snapshot", type=Path)
    ap.add_argument("--fill", type=Path, help="snapshot used only for candidates missing from SNAPSHOT")
    ap.add_argument("--candidates", type=Path, default=DEFAULT_CANDIDATES)
    ap.add_argument("--rename", action="append", metavar="OLD=NEW")
    ap.add_argument("--reports", action="append", type=Path, default=[], metavar="DIR")
    ap.add_argument("-o", "--output", type=Path)
    args = ap.parse_args(argv)
    try:
        rows = build_rows(
            load_candidates(args.candidates, root),
            load_snapshot(args.snapshot, root),
            load_snapshot(args.fill, root) if args.fill else None,
            parse_renames(args.rename),
            args.reports,
        )
        table = render_table(rows)
        if args.output:
            write_text(args.output, table, root)
        else:
            sys.stdout.write(table)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
