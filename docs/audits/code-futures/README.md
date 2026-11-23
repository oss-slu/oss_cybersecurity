# Code Futures Snapshots

Dated snapshots from [oss-slu/code-futures](https://github.com/oss-slu/code-futures) (schema `code-futures/v1`), kept so engineering practice can be compared from one sweep to the next. Governing issue: [oss-slu/oss_cybersecurity#69](https://github.com/oss-slu/oss_cybersecurity/issues/69).

## Snapshots

| File | Collected | Covers |
|---|---|---|
| `2026-11-02-snapshot.json` | 2026-11-02 | Organization-wide sweep, 29 repositories |
| `2026-11-23-snapshot.json` | 2026-11-23 | 22 candidate repositories, collected without organization credentials |

Files are named `YYYY-MM-DD-snapshot.json` by collection date.

## End-of-sprint procedure

Run from the root of this repository.

1. Run the sweep. `code-futures doctor` must pass first.

   ```bash
   code-futures doctor
   code-futures sweep
   ```

2. Copy the result into this folder under its collection date.

   ```bash
   cp evidence/fall-2026/code-futures.json docs/audits/code-futures/YYYY-MM-DD-snapshot.json
   ```

3. Compare it with the previous snapshot.

   ```bash
   python3 scripts/diff-code-futures.py \
       docs/audits/code-futures/PREVIOUS-snapshot.json \
       docs/audits/code-futures/YYYY-MM-DD-snapshot.json \
       --rename enroll-dash=geo-enricher
   ```

   Add `--fail-on-regression` to exit with code 3 when any practice regressed.

4. Rebuild the matrix table for the practice matrix document.

   ```bash
   python3 scripts/code-futures-matrix.py docs/audits/code-futures/YYYY-MM-DD-snapshot.json \
       --rename enroll-dash=geo-enricher --reports PATH_TO_RENDERED_REPORTS
   ```

## Reading a drift summary

- A move to or from `unreadable` is a change in what the tool could see, not a change in the repository. The diff script lists these separately.
- For Structure probes and `deps.known_vulnerabilities`, `absent` is the good outcome, so `present` to `absent` is reported as an improvement.
- Rendered Code Futures reports are internal to the program and are not stored here.
