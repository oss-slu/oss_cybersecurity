# SALTIFY (SpeechTranscription) — Software Bill of Materials

This directory contains a Software Bill of Materials (SBOM) for the SALTIFY
(SpeechTranscription) project, generated with [Syft](https://github.com/anchore/syft)
in SPDX JSON format.

- `saltify-sbom.spdx.json` — the generated SBOM (SPDX 2.3, JSON).

## What was scanned

SALTIFY is a Python desktop GUI application (Tkinter/CustomTkinter) that is
packaged into a Windows/macOS executable with PyInstaller, entirely inside
GitHub Actions (`.github/workflows/windows-build.yml`,
`.github/workflows/macos-build.yml`). There is:

- **No Dockerfile / container image** in the repository, so there is no
  built container artifact to scan.
- **No pre-built packaged executable** available outside of CI (building the
  `.exe`/`.app` requires a Windows or macOS runner and the full PyInstaller
  toolchain, which isn't practical to reproduce as part of this task).

Given that, this SBOM follows the fallback option described in the SBOM
issue: **it represents the project's resolved Python dependency set, not the
final packaged artifact.**

Specifically:

1. The project's `requirements.txt` mostly lists dependencies **without
   pinned versions** (e.g. `pyaudio`, `nltk`, `pydub`). Syft cannot report a
   version for a package that has no version information available, so
   scanning `requirements.txt` directly produced an almost-empty SBOM (only
   files with resolvable versions, like GitHub Actions steps and bundled
   `ffmpeg` binaries, showed up).
2. To get a meaningful, realistic SBOM, pip's dependency resolver was used to
   determine the exact versions that `pip install -r requirements.txt` would
   actually install today (including transitive dependencies), **without**
   performing a full disk install. That resolved, pinned dependency list was
   written to `requirements-resolved.txt`.
3. Syft was then run against that resolved requirements file.

This means the SBOM reflects **what would currently be installed into
SALTIFY's Python environment**, which is the closest practical stand-in for
a "resolved build environment" available without a Windows/macOS build
runner.

One dependency, [`pattern`](https://github.com/clips/pattern) (installed
from git per `requirements.txt`), was **excluded from resolution** — see
"Known limitations" below.

## Exact commands used

All commands were run from the root of a clean clone of the repository.

**1. Install Syft:**

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
syft version   # confirm install (used: syft 1.51.1)
```

**2. Resolve the real dependency versions (without installing them):**

```bash
# Exclude the one line that cannot be resolved in a stock environment
# (git+https://github.com/clips/pattern.git — see Known limitations)
grep -v "clips/pattern" requirements.txt > requirements-trimmed.txt

pip install --dry-run --ignore-installed \
  --report pip-report.json \
  -r requirements-trimmed.txt
```

**3. Convert the resolver's report into a pinned requirements file:**

```bash
python3 -c "
import json
with open('pip-report.json') as f:
    report = json.load(f)
lines = sorted(
    f\"{item['metadata']['name']}=={item['metadata']['version']}\"
    for item in report['install']
)
with open('requirements-resolved.txt', 'w') as f:
    f.write('\n'.join(lines) + '\n')
"
```

**4. Generate the SBOM with Syft:**

mkdir /tmp/sbom-scan && mv requirements-resolved.txt /tmp/sbom-scan/
syft dir:/tmp/sbom-scan -o spdx-json=docs/sbom/saltify-sbom.spdx.json

## How Syft was installed/run

- Installed via Anchore's official install script, which downloads a
  release binary from the [Syft GitHub releases](https://github.com/anchore/syft/releases)
  page — no Docker or package manager required.
- Version used: **Syft v1.51.1** (Linux/amd64).
- Run entirely locally/offline against a directory of files — Syft does not
  need network access to the target being scanned (it does try to check
  GitHub for its own newer release on startup; that check failing is
  harmless and doesn't affect the scan).

## What kinds of dependencies appear in the SBOM

The SBOM contains **174 components**, primarily:

- **Core application dependencies** declared in `requirements.txt`:
  `customtkinter`, `pyaudio`, `pydub`, `python-docx`, `pillow`,
  `python-dotenv`, `sv_ttk`, `nltk`, `language_tool_python`, `matplotlib`,
  `openai-whisper`, `pyannote-audio`, `simple-diarizer`, `spectralcluster`,
  `Resemblyzer`, `lightning-fabric`, `pytest`.
- **Machine-learning / audio-processing stack** pulled in transitively by
  `pyannote.audio` and `openai-whisper`: `torch`, `torchaudio`, `torchcodec`,
  `numpy`, `scipy`, `scikit-learn`, `numba`, `librosa`, `soundfile`,
  `speechbrain`, `pytorch-lightning`, `sentencepiece`, `tiktoken`.
- **NVIDIA/CUDA runtime packages** (`nvidia-cublas`, `nvidia-cudnn-cu13`,
  `nvidia-cufft`, etc.) that `torch` depends on, even though SALTIFY itself
  does not require a GPU.
- **General-purpose supporting libraries**: `requests`, `httpx`, `rich`,
  `PyYAML`, `packaging`, `click`, `Jinja2`, `SQLAlchemy` (an `optuna`
  transitive dependency), and similar common Python ecosystem packages.

No operating-system-level packages appear (this is a pure Python dependency
scan, not an OS/container scan), and no proprietary SALTIFY source files are
listed as components — the SBOM only reflects third-party packages.

## Known limitations

- **Not the final packaged artifact.** This SBOM does not represent the
  actual Windows/macOS executable produced by PyInstaller in CI. It does not
  include bundled runtime files that PyInstaller adds at packaging time,
  such as the `ffmpeg.exe`/`ffplay.exe`/`ffprobe.exe` binaries and the
  `en-model.slp` pattern data file shipped in `build_assets/`.
- **`pattern` (from git) was excluded from resolution.** `requirements.txt`
  installs `pattern` directly from
  `git+https://github.com/clips/pattern.git`, which in turn depends on
  `mysqlclient`. Building `mysqlclient` requires MySQL/MariaDB client
  development headers that are not present in a stock environment, so pip's
  resolver could not complete dependency resolution with that package
  included. As a result, **`pattern` and its dependencies are not present
  in this SBOM.**
- **Version drift over time.** The resolved versions reflect what PyPI
  currently serves as the latest compatible releases at the time this SBOM
  was generated (since most of `requirements.txt` has no version pins).
  Re-running the same commands on a different date can produce a different
  set of resolved versions and therefore a different SBOM. For a fully
  reproducible SBOM, the project's `requirements.txt` would need to pin
  exact versions.
- **No OS-level or native-library inventory.** Because this SBOM is based on
  a Python dependency resolution rather than a built container image or
  installed system, it does not capture OS packages, system libraries
  (e.g. `pkg-config`, PortAudio, MySQL client libraries) that some of these
  Python packages depend on at build or runtime.
- **License/security metadata is best-effort.** Fields such as
  `licenseConcluded` are marked `NOASSERTION` for most packages, since Syft
  did not have access to installed package metadata/license files (only the
  resolved name/version pairs).

## Verification performed

After generation, I installed Syft locally, re-ran the generation steps,
 and checked the output myself to confirm it captured the project's real,
  expected dependencies (rather than being empty or malformed), including: 
`torch`, `numpy`, `openai-whisper`,`pyannote-audio`, `customtkinter`, `pillow`,
`matplotlib`, `nltk`,`python-docx`, `pydub`, `PyAudio`, `pytest`, `Resemblyzer`,
`spectralcluster`, `python-dotenv`, and `lightning-fabric` — all were
present with concrete resolved versions and SPDX package entries
(including CPE references) in the generated file.
