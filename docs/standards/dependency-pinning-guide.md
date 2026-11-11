# Dependency Pinning and Deterministic Lockfile Guide

**Status:** Organizational Standard  
**Governing Issue:** [oss-slu/oss_cybersecurity#70](https://github.com/oss-slu/oss_cybersecurity/issues/70)  
**Related Policies:** [oss-slu/oss_infra_ops#167](https://github.com/oss-slu/oss_infra_ops/issues/167) (SLSA L3 Cluster Policy), [oss-slu/oss_cicd_automation#154](https://github.com/oss-slu/oss_cicd_automation/issues/154) (SLSA L3 Reusable Workflow)  

---

## 1. Executive Summary & Purpose

Software supply chain attacks frequently exploit dynamic, unpinned dependency resolution. When projects rely on loose package ranges (e.g. `requests>=2.25.0` or `express: "^4.18.0"`), every new build or deployment risks pulling unvetted, potentially compromised upstream releases without developer awareness.

Furthermore, **SLSA (Supply-chain Levels for Software Artifacts) Build Level 3** requires reproducible, hermetic build pipelines where every input artifact is deterministically tracked.

This standard establishes mandatory dependency pinning and lockfile conventions across all programming language ecosystems supported within Open Source with SLU (OSS-SLU).

---

## 2. Supply Chain Threat Model

Adhering to strict dependency pinning mitigates critical attack vectors:

| Threat Vector | Description | Mitigation |
|---|---|---|
| **Compromised Transitive Dependencies** | An attacker takes over a deeply nested dependency and pushes a malicious patch release. | Deterministic lockfiles freeze exact versions until deliberately audited and updated. |
| **Dependency Confusion / Typosquatting** | Public package registries are seeded with malicious packages mirroring internal or mistyped package names. | Hash-pinned lockfiles and explicit index registries verify source authenticity. |
| **Build Nondeterminism** | Builds pass in CI on Monday but fail unexpectedly on Friday due to an unannounced breaking change in an upstream package. | Frozen lockfiles guarantee identical byte-for-byte dependencies across local, CI, and production environments. |

---

## 3. Language Ecosystem Standards

### 3.1 Python Ecosystem

#### Mandate
- **Raw, unpinned `requirements.txt` is strictly prohibited** for container builds and production deployments.
- All Python projects must commit a deterministic lockfile containing resolved versions and SHA256 integrity hashes.

#### Recommended Tooling
1. **`uv` (Recommended Standard for OSS-SLU):**
   ```bash
   # Generate / update lockfile
   uv lock

   # In CI / Dockerfile, install strictly from lockfile
   uv sync --frozen --no-dev
   ```
2. **`poetry`:**
   ```bash
   # Maintain poetry.lock
   poetry lock --no-update

   # In CI / Dockerfile
   poetry install --no-root --sync --only main
   ```
3. **`pip-tools` (`pip-compile`):**
   ```bash
   # Generate requirements.lock.txt with SHA256 hashes
   pip-compile --generate-hashes --output-file=requirements.lock.txt requirements.in

   # In CI / Dockerfile
   pip install --no-deps --require-hashes -r requirements.lock.txt
   ```

---

### 3.2 JavaScript / TypeScript (Node.js) Ecosystem

#### Mandate
- The project lockfile **must be committed** to the Git repository.
- CI and Dockerfiles must **never use `npm install`**, which modifies or ignores lockfiles.

#### Recommended Tooling
1. **`npm`:**
   - Commit `package-lock.json`.
   - CI / Docker command:
     ```bash
     npm ci --ignore-scripts # or npm ci
     ```
2. **`pnpm`:**
   - Commit `pnpm-lock.yaml`.
   - CI / Docker command:
     ```bash
     pnpm install --frozen-lockfile
     ```
3. **`yarn` (v2+ / Berry):**
   - Commit `yarn.lock`.
   - CI / Docker command:
     ```bash
     yarn install --immutable
     ```

---

### 3.3 Rust Ecosystem

#### Mandate
- All binary crates, services, and web applications must commit `Cargo.lock`.
- CI builds must enforce the `--locked` flag to guarantee that `Cargo` aborts if the lockfile requires updates.

```bash
# In CI / Dockerfile
cargo build --release --locked
```

---

### 3.4 Go Ecosystem

#### Mandate
- Both `go.mod` and `go.sum` must be committed to version control.
- CI builds must enforce `-mod=readonly` so that missing dependencies cause build failures rather than silent downloads.

```bash
# In CI / Dockerfile
go build -mod=readonly -v ./...
```

---

## 4. CI/CD Validation & Pre-Commit Linting

To ensure that maintainers and contributors do not accidentally commit manifests out-of-sync with their lockfiles, projects should include the following check in their PR workflow (`.github/workflows/ci.yml`):

### GitHub Actions Workflow Snippet

```yaml
name: Verify Dependency Lockfiles

on:
  pull_request:
    branches: [main]

jobs:
  verify-lockfile:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      # Python projects (uv)
      - name: Check uv lockfile currency
        if: hashFiles('pyproject.toml') != ''
        run: |
          curl -LsSf https://astral.sh/uv/install.sh | sh
          uv lock --check

      # Node.js projects (npm)
      - name: Check package-lock.json currency
        if: hashFiles('package.json') != ''
        run: |
          npm ci --dry-run
```

---

## 5. Automated Dependency Maintenance (Dependabot)

Lockfiles must not become stale. To maintain currency and receive timely security patches, all repositories must maintain a `.github/dependabot.yml` configuration:

```yaml
version: 2
updates:
  - package-ecosystem: "npm" # or "pip", "cargo", "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    groups:
      minor-and-patch:
        patterns:
          - "*"
        update-types:
          - "minor"
          - "patch"
```

---

## 6. Ecosystem Readiness Scorecard

Preliminary audit of active Open Source with SLU projects and their dependency pinning posture:

| Repository | Primary Ecosystem | Current Lockfile Status | Readiness Tier | Next Action |
|---|---|---|---|---|
| **`oss_dev_analytics`** | Python / FastStream | `requirements.txt` (loose) | **High Priority (Pilot)** | Migrate to `uv.lock` as part of SLSA L3 Pilot (#168). |
| **`mithridatium`** | Python | `poetry.lock` (committed) | **Ready** | Enforce `--frozen` in CI Docker build. |
| **`oss_portfolio`** | Node.js / React | `package-lock.json` (committed) | **Ready** | Verify `npm ci` is used exclusively in Dockerfile. |
| **`in-reach`** | Node.js / TypeScript | `package-lock.json` (committed) | **Ready** | Enforce frozen lockfile check in PR workflow. |
| **`shelter_volunteers`** | Python / Django | `requirements.txt` (unpinned) | **Needs Migration** | Generate `uv.lock` or hash-pinned `pip-compile` lockfile. |
| **`GradEval360`** | Python / Django | `requirements.txt` (partial pins) | **Needs Migration** | Standardize on `uv.lock`. |

---

## 7. Migration Runbook for Maintainers

If your project currently relies on unpinned dependencies:

1. **Step 1: Pick the Standard Tool:**
   - For Python: Install `uv` (`curl -LsSf https://astral.sh/uv/install.sh | sh` or `pip install uv`).
   - For Node: Ensure `npm` (v7+) or `pnpm` is installed.
2. **Step 2: Generate the Lockfile:**
   - In your project root, run `uv lock` (or `npm install`).
3. **Step 3: Update the Dockerfile:**
   - Replace `pip install -r requirements.txt` with `uv sync --frozen --no-dev`.
   - Replace `npm install` with `npm ci`.
4. **Step 4: Commit and Open PR:**
   - Commit the generated lockfile (`git add uv.lock Dockerfile`).
   - Reference [oss-slu/oss_cybersecurity#70](https://github.com/oss-slu/oss_cybersecurity/issues/70) in your pull request.
