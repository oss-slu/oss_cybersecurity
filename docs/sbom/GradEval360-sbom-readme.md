# Mike Budzynski - 9/21/26
# GradEval360 SBOM Documentation

This document describes the Software Bill of Materials (SBOM) generated for **GradEval360**, detailing the scanned target, exact reproduction commands, dependency coverage, and known scan limitations.

---

## 1. What Was Scanned

- **Target:** GradEval360 repository filesystem (`..\GradEval360`)
- **Format:** SPDX 2.3 JSON (`SPDX-2.3`)
- **Output File:** `docs/sbom/GradEval360-sbom.spdx.json`

> **Note:** A repository level fallback scan was performed rather than scanning a packaged runtime container image, capturing declared dependencies from repository manifests and lockfiles. Only contains the dir for GradEval360 

# This was done using 
- syft dir:..\GradEval360 -o spdx-json=docs/sbom/GradEval360-sbom.spdx.json

# There is no docker image so scanning the directory as it currently is rather than a docker image

---

## 2. Reproduction Steps

### Step 1: Create Destination Directory
From the root of `oss_cybersecurity`, create the output directory:

```powershell
mkdir -p docs/sbom