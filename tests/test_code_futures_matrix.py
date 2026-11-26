"""Unit tests for scripts/code-futures-matrix.py (oss-slu/oss_cybersecurity#69).

Run with:  python3 -m unittest discover -s tests -v
"""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cfmatrix", ROOT / "scripts" / "code-futures-matrix.py")
cfmatrix = importlib.util.module_from_spec(spec)
sys.modules["cfmatrix"] = cfmatrix
spec.loader.exec_module(cfmatrix)


def report(name, when, *probes):
    return {"repository": f"oss-slu/{name}", "collected_at": when, "probes": list(probes)}


def snap(when, *reports):
    return {"schema": "code-futures/v1", "collected_at": when, "reports": list(reports), "failures": {}}


HOT = {"id": "structure.hotspots", "outcome": "present", "evidence": ["b.py"], "attributes": {"top": "a.py"}}
BASE = snap(
    "2026-11-02 21:33 UTC",
    report("enroll-dash", "2026-11-02 21:33 UTC", HOT, {"id": "lint", "outcome": "enforced", "language": "Python"},
           {"id": "lint", "outcome": "absent", "language": "JavaScript"}, {"id": "security.sast", "outcome": "unreadable"}),
)
FILL = snap("2026-11-23 17:20 UTC", report("civickit", "2026-11-23 17:20 UTC", {"id": "structure.hotspots", "outcome": "absent"}))


class MatrixTests(unittest.TestCase):
    def rows(self, dirs=()):
        return cfmatrix.build_rows(
            ["geo-enricher", "civickit", "nowhere"], BASE, FILL, cfmatrix.parse_renames(["enroll-dash=geo-enricher"]), list(dirs)
        )

    def test_counts_rename_and_hotspot(self):
        r = self.rows()[0]
        self.assertEqual(r["counts"], {"enforced": 1, "present": 1, "absent": 1, "unreadable": 1})
        self.assertEqual((r["findings"], r["hotspot"], r["filled"]), (4, "`a.py`", False))

    def test_fill_and_missing(self):
        _, filled, missing = self.rows()
        self.assertTrue(filled["filled"])
        self.assertEqual((filled["collected"], filled["hotspot"]), ("2026-11-23", "none found"))
        self.assertTrue(missing["missing"])
        table = cfmatrix.render_table(self.rows())
        self.assertIn("| `civickit` (2026-11-23) | 0 | 0 | 1 | 0 | 1 | none found | - | - |", table)
        self.assertIn("| `nowhere` | - | - | - | - | - | not in snapshot | - | - |", table)

    def test_where_to_start_reads_report_under_old_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "oss-slu_enroll-dash.md").write_text(
                "Our suggestion here is **the licence**:\n\nThen, in order:\n\n1. **Write a README.** More text.\n2. **Other.**\n"
            )
            r = self.rows([Path(tmp)])[0]
        self.assertEqual((r["start"], r["then"]), ("The licence", "Write a README"))

    def test_candidates_file_ignores_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp, "c.txt")
            f.write_text("# header\n\ncivickit\ncore_desk   # listed as CoreDesk\n")
            self.assertEqual(cfmatrix.load_candidates(f, tmp), ["civickit", "core_desk"])

    def test_refuses_paths_outside_the_root(self):
        import json

        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as elsewhere:
            Path(tmp, "c.txt").write_text("geo-enricher\n")
            Path(tmp, "s.json").write_text(json.dumps(BASE))
            Path(elsewhere, "s.json").write_text(json.dumps(BASE))
            ok = ["s.json", "--candidates", "c.txt", "--rename", "enroll-dash=geo-enricher"]
            self.assertEqual(cfmatrix.main(ok + ["-o", "t.md"], root=tmp), 0)
            self.assertIn("| `geo-enricher` | 1 | 1 | 1 | 1 | 4 |", Path(tmp, "t.md").read_text())
            self.assertEqual(cfmatrix.main([str(Path(elsewhere, "s.json")), "--candidates", "c.txt"], root=tmp), 1)
            self.assertEqual(cfmatrix.main(ok + ["-o", str(Path(elsewhere, "t.md"))], root=tmp), 1)
            self.assertFalse(Path(elsewhere, "t.md").exists())
            with self.assertRaises(ValueError):
                cfmatrix.safe_path("../x", tmp)


if __name__ == "__main__":
    unittest.main()
