"""Unit tests for scripts/diff-code-futures.py (oss-slu/oss_cybersecurity#69).

Run with:  python3 -m unittest discover -s tests -v
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cfdiff", ROOT / "scripts" / "diff-code-futures.py")
cfdiff = importlib.util.module_from_spec(spec)
sys.modules["cfdiff"] = cfdiff
spec.loader.exec_module(cfdiff)


def probe(pid, outcome, language=None, evidence=None, attributes=None):
    p = {"id": pid, "outcome": outcome}
    if language:
        p["language"] = language
    if evidence:
        p["evidence"] = evidence
    if attributes:
        p["attributes"] = attributes
    return p


def snapshot(when, **repos):
    return {
        "schema": "code-futures/v1",
        "collected_at": when,
        "reports": [
            {"schema": "code-futures/v1", "repository": f"oss-slu/{name}", "collected_at": when, "probes": probes}
            for name, probes in repos.items()
        ],
        "failures": {},
    }


class ClassifyTests(unittest.TestCase):
    def test_normal_ladder(self):
        self.assertEqual(cfdiff.classify("test.unit", "absent", "present"), "improved")
        self.assertEqual(cfdiff.classify("test.unit", "present", "enforced"), "improved")
        self.assertEqual(cfdiff.classify("test.unit", "absent", "enforced"), "improved")
        self.assertEqual(cfdiff.classify("test.unit", "enforced", "present"), "regressed")
        self.assertEqual(cfdiff.classify("test.unit", "present", "absent"), "regressed")
        self.assertEqual(cfdiff.classify("test.unit", "present", "present"), "unchanged")

    def test_structure_probes_are_inverted(self):
        self.assertEqual(cfdiff.classify("structure.hotspots", "present", "absent"), "improved")
        self.assertEqual(cfdiff.classify("structure.hotspots", "absent", "present"), "regressed")

    def test_known_vulnerabilities_is_inverted(self):
        self.assertEqual(cfdiff.classify("deps.known_vulnerabilities", "present", "absent"), "improved")
        self.assertEqual(cfdiff.classify("deps.known_vulnerabilities", "absent", "present"), "regressed")

    def test_unreadable_is_never_improvement_or_regression(self):
        for other in ("enforced", "present", "absent"):
            self.assertEqual(cfdiff.classify("security.sast", other, "unreadable"), "became_unreadable")
            self.assertEqual(cfdiff.classify("security.sast", "unreadable", other), "became_readable")

    def test_added_and_removed(self):
        self.assertEqual(cfdiff.classify("lint", None, "present"), "added")
        self.assertEqual(cfdiff.classify("lint", "present", None), "removed")


class DiffTests(unittest.TestCase):
    def setUp(self):
        self.old = snapshot(
            "2026-11-02 14:00 UTC",
            alpha=[
                probe("test.unit", "present"),
                probe("lint", "enforced", "Python"),
                probe("lint", "absent", "JavaScript"),
                probe("security.sast", "enforced"),
                probe("structure.hotspots", "present", evidence=["a.py", "b.py"], attributes={"top": "a.py"}),
            ],
            gone=[probe("test.unit", "absent")],
        )
        self.new = snapshot(
            "2026-12-01 14:00 UTC",
            Alpha=[  # same repository, different letter case
                probe("test.unit", "enforced"),
                probe("lint", "present", "Python"),
                probe("lint", "absent", "JavaScript"),
                probe("security.sast", "unreadable"),
                probe("structure.hotspots", "present", evidence=["c.py", "a.py"], attributes={"top": "c.py"}),
            ],
            fresh=[probe("test.unit", "absent")],
        )
        self.drift = cfdiff.diff_snapshots(self.old, self.new)

    def test_improved_and_regressed(self):
        self.assertEqual([(c["probe"], c["language"]) for c in self.drift["improved"]], [("test.unit", None)])
        self.assertEqual([(c["probe"], c["language"]) for c in self.drift["regressed"]], [("lint", "Python")])

    def test_per_language_findings_are_separate(self):
        changed = [c for k in ("improved", "regressed") for c in self.drift[k] if c["probe"] == "lint"]
        self.assertEqual([c["language"] for c in changed], ["Python"])

    def test_unreadable_not_counted_as_regression(self):
        self.assertEqual([c["probe"] for c in self.drift["became_unreadable"]], ["security.sast"])
        self.assertNotIn("security.sast", [c["probe"] for c in self.drift["regressed"]])

    def test_repository_match_ignores_case(self):
        self.assertEqual(self.drift["repositories_compared"], 1)
        self.assertEqual(self.drift["only_in_old"], ["oss-slu/gone"])
        self.assertEqual(self.drift["only_in_new"], ["oss-slu/fresh"])

    def test_rename_pairs_old_name_with_new(self):
        old = snapshot("t1", **{"enroll-dash": [probe("test.unit", "absent")]})
        new = snapshot("t2", **{"geo-enricher": [probe("test.unit", "enforced")]})
        plain = cfdiff.diff_snapshots(old, new)
        self.assertEqual((plain["only_in_old"], plain["only_in_new"]), (["oss-slu/enroll-dash"], ["oss-slu/geo-enricher"]))
        d = cfdiff.diff_snapshots(old, new, cfdiff.parse_renames(["Enroll-Dash=geo-enricher"]))
        self.assertEqual(d["repositories_compared"], 1)
        self.assertEqual([c["repository"] for c in d["improved"]], ["oss-slu/geo-enricher"])
        with self.assertRaises(cfdiff.SnapshotError):
            cfdiff.parse_renames(["no-equals-sign"])

    def test_hotspot_migration(self):
        (h,) = self.drift["hotspot_migrations"]
        self.assertEqual(h["entered"], ["c.py"])
        self.assertEqual(h["left"], ["b.py"])
        self.assertEqual((h["old_top"], h["new_top"]), ("a.py", "c.py"))

    def test_identical_snapshots_have_no_drift(self):
        d = cfdiff.diff_snapshots(self.old, self.old)
        for key in ("improved", "regressed", "became_readable", "became_unreadable", "hotspot_migrations"):
            self.assertEqual(d[key], [], key)

    def test_markdown_lists_each_section(self):
        md = cfdiff.render_markdown(self.drift)
        self.assertIn("## Practices that regressed", md)
        self.assertIn("| `Alpha` | `lint` (Python) | enforced | present |", md)
        self.assertIn("- New hotspot: `c.py`", md)
        self.assertIn("Top hotspot moved from `a.py` to `c.py`", md)


class CliTests(unittest.TestCase):
    def run_cli(self, old, new, *extra):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "old.json", Path(tmp) / "new.json"
            a.write_text(json.dumps(old) if isinstance(old, dict) else old)
            b.write_text(json.dumps(new))
            out = Path(tmp) / "drift.md"
            code = cfdiff.main([str(a), str(b), "-o", str(out), *extra], root=tmp)
            return code, (out.read_text() if out.exists() else "")

    def test_exit_codes(self):
        old = snapshot("t1", r=[probe("test.unit", "enforced")])
        new = snapshot("t2", r=[probe("test.unit", "absent")])
        self.assertEqual(self.run_cli(old, new)[0], 0)
        self.assertEqual(self.run_cli(old, new, "--fail-on-regression")[0], 3)
        self.assertEqual(self.run_cli(old, old, "--fail-on-regression")[0], 0)

    def test_refuses_paths_outside_the_root(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as elsewhere:
            good = Path(tmp) / "s.json"
            good.write_text(json.dumps(snapshot("t1", r=[])))
            outside = Path(elsewhere) / "s.json"
            outside.write_text(good.read_text())
            self.assertEqual(cfdiff.main([str(good), str(good), "-o", str(Path(tmp) / "d.md")], root=tmp), 0)
            self.assertEqual(cfdiff.main([str(outside), str(good)], root=tmp), 1)
            self.assertEqual(cfdiff.main([str(good), str(good), "-o", str(Path(elsewhere) / "d.md")], root=tmp), 1)
            self.assertEqual(cfdiff.main([str(good), str(good), "-o", "../escape.md"], root=tmp), 1)
            self.assertFalse((Path(elsewhere) / "d.md").exists())
            with self.assertRaises(cfdiff.SnapshotError):
                cfdiff.safe_path("../../etc/passwd", tmp)
            self.assertEqual(cfdiff.safe_path("sub/x.json", tmp), str(Path(tmp).resolve() / "sub" / "x.json"))

    def test_rejects_wrong_schema_and_bad_json(self):
        good = snapshot("t1", r=[])
        self.assertEqual(self.run_cli({"schema": "other/v9", "reports": []}, good)[0], 1)
        self.assertEqual(self.run_cli("{not json", good)[0], 1)


if __name__ == "__main__":
    unittest.main()
