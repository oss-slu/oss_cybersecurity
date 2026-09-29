# Hunter Cataldo - 9/28/26
# DigitalBoneBox SBOM Documentation

This document describes the Software Bill of Materials (SBOM) generated for **DigitalBoneBox**, including what was scanned, the exact command to reproduce it, what dependencies appeared, and known limitations.

---

## 1. What Was Scanned

- **Target:** DigitalBoneBox repository filesystem (`..\DigitalBoneBox`)
- **Commit:** `1d6bcf9cb4b85f61a6eb5dc3a12ba2b3298a53ba` (clean working tree, no uncommitted changes)
- **Format:** SPDX 2.3 JSON (`SPDX-2.3`)
- **Output File:** `docs/sbom/DigitalBoneBox-sbom.spdx.json`
- **Tool:** Syft 1.52.0

> **Note:** A repository-level fallback scan was performed. No container image was built, so this SBOM covers the dependencies declared in the repository's lockfiles, not a final packaged artifact.

---

## 2. Reproduction Steps

### Step 1: Install Syft
Downloaded `syft_1.52.0_windows_amd64.zip` from https://github.com/anchore/syft/releases/tag/v1.52.0 and unzipped it to `C:\tools\syft`. (Any install method works, for example `brew install syft` on macOS.)

### Step 2: Clone both repositories side by side
`oss_cybersecurity` and `DigitalBoneBox` should sit in the same parent folder. Check out commit `1d6bcf9cb4b85f61a6eb5dc3a12ba2b3298a53ba` in DigitalBoneBox to get an identical result.

### Step 3: Create the destination directory
From the root of `oss_cybersecurity`:

```powershell
mkdir -Force docs/sbom
```

### Step 4: Run Syft
```powershell
C:\tools\syft\syft.exe dir:..\DigitalBoneBox -o spdx-json=docs/sbom/DigitalBoneBox-sbom.spdx.json
```

If Syft is on your PATH: `syft dir:..\DigitalBoneBox -o spdx-json=docs/sbom/DigitalBoneBox-sbom.spdx.json`

---

## 3. What Appeared in the SBOM

Syft reported **192 packages**.

- **npm packages** from `package-lock.json` (root) and `boneset-api/package-lock.json`. Most packages appear twice, once per lockfile.
- **Direct dependencies** include express, axios, cors, dotenv, @upstash/redis, express-rate-limit, simple-git and body-parser, plus their sub-dependencies.
- **GitHub Actions** from `.github/workflows/lint.yml`: `actions/checkout` and `actions/setup-node`.

---

## 4. Verification

Compared the SBOM against `package.json` and `boneset-api/package.json` at commit `1d6bcf9`. Confirmed these declared dependencies appear in the SBOM at the expected versions:
- **express** 4.22.3, **axios** 1.18.0 and **@upstash/redis** 1.39.0 (both lockfiles)
- **express-rate-limit** 8.7.0 (root) and 8.5.1 (boneset-api), matching each `package.json`
- **simple-git** 3.36.0 (root only) and **dotenv** 16.4.7 (boneset-api only)

Development dependencies (jest, eslint, babel, nodemon, supertest, etc.) do not appear in the SBOM.

---

## 5. Known Limitations

- Repository scan only, not a built image or packaged app. OS-level packages and build-time additions are not included.
- Package data comes from lockfiles. Nothing was installed, so versions in a real deployment could differ.
- Many packages show `NOASSERTION` for license, because lockfiles often lack license data.
- Libraries added by hand or loaded from a CDN (not in a lockfile) would not appear.
- The scanned folder is named by its relative path (`..\DigitalBoneBox`) because Syft was given no name for it.
- Snapshot of one commit. Re-run the command to refresh it.