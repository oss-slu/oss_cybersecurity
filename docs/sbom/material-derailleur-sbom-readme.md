# Material Derailleur SBOM

A baseline Software Bill of Materials (SBOM) for [Material Derailleur](https://github.com/oss-slu/material-derailleur), generated with [Syft](https://github.com/anchore/syft).

| | |
|---|---|
| SBOM file | `material-derailleur-sbom.spdx.json` |
| Format | SPDX 2.3, JSON |
| Generated with | Syft 1.52.0 |
| Generated on | 2026-09-25 |
| Source commit | [`5f89612`](https://github.com/oss-slu/material-derailleur/commit/5f89612adf9947917b849cca9d256c8e2fbb0ba5) on `main` (2026-09-14) |
| Contents | 3,480 package entries (2,393 unique name/version pairs) |

## What was scanned

Material Derailleur runs as three Docker images, defined in `docker-compose.yml`:

| Image | Base | What the Dockerfile adds | In this SBOM |
|---|---|---|---|
| Server (`server/Dockerfile`) | `node:20` | `npm install`, then `npx prisma generate` | Yes |
| Client (`client-app/Dockerfile`) | `node:18` | `npm install --legacy-peer-deps`, then `npm install ajv@8 --legacy-peer-deps` | Yes |
| Database (`docker-files/database/Dockerfile`) | `postgres:16.2` | SQL init scripts only | No (no application dependencies) |

The issue prefers scanning the built container image, but that wasn't practical:

- CI (`.github/workflows/build-and-push.yml`) pushes the server and client images to `ghcr.io/oss-slu/material-derailleur/{server,client}`, but they can't be pulled publicly. An anonymous pull returns `authentication required`.
- Docker wasn't available on the machine used, so the images couldn't be built locally.

This SBOM therefore uses the issue's second option: the **resolved build environment**. The `/app` directory of the server and client images was recreated outside Docker:

1. The `server/` and `client-app/` build contexts were exported from the commit above with `git archive`, which includes tracked files only.
2. Each directory ran the same `npm install` commands as its Dockerfile. These install from the committed `package-lock.json` files.
3. Syft scanned both directories together using the cataloger set it uses for container images (`--override-default-catalogers image`). With this set, Syft reads the `package.json` of every package actually installed under `node_modules/`, which is also what it reads inside a real image. A default directory scan reads only `package-lock.json` files and also picks up CI workflow files inside third-party packages.

Each package's path in the SBOM starts with `/server/` or `/client-app/`, so you can tell which image it belongs to.

## How Syft was installed and run

Recommended — reproducible, pinned Syft installer (works on macOS and Linux):

```bash
# Use Anchore's installer and pin the Syft version used to generate the SBOM:
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin v1.52.0
~/.local/bin/syft version   # should print v1.52.0
```

Optional Homebrew note:

```bash
# Homebrew installs whatever version is currently available in the formula and is not
# guaranteed to match the SBOM's pinned version. Use the installation above for exact reproducibility.
brew install syft
syft version
```

Syft scans files on the local disk and uploads nothing. Its only network call is a check for a newer Syft release.

The dependency install step also needs Node.js and npm. This SBOM was generated with Node 24.6.0 and npm 11.5.1.

## Reproducing the SBOM

Requires git, Node.js/npm, and Syft.

```bash
# 1. Get the exact source that was scanned
git clone https://github.com/oss-slu/material-derailleur.git
cd material-derailleur
git checkout 5f89612adf9947917b849cca9d256c8e2fbb0ba5

# 2. Recreate the server and client build contexts in a temporary directory.
#    `pwd -P` resolves symlinks (on macOS, /var is a link to /private/var).
#    Without it, Syft records absolute paths and scans outside the directory.
STAGE="$(cd "$(mktemp -d)" && pwd -P)"
git archive HEAD server client-app | tar -x -C "$STAGE"

# 3. Install dependencies the same way each Dockerfile does.
#    --ignore-scripts skips install scripts (native builds, binary downloads);
#    it doesn't change which packages are installed.
(cd "$STAGE/server" && npm install --ignore-scripts)
(cd "$STAGE/client-app" && npm install --legacy-peer-deps --ignore-scripts \
  && npm install ajv@8.20.0 --legacy-peer-deps --ignore-scripts)

# 4. Generate the SBOM. Run it from inside $STAGE so paths start at /server and /client-app.
cd "$STAGE"
syft scan dir:. \
  --override-default-catalogers image \
  --source-name material-derailleur \
  --source-version 5f89612 \
  -o spdx-json=material-derailleur-sbom.spdx.json
```

Copy `$STAGE/material-derailleur-sbom.spdx.json` into `docs/sbom/` in this repository.

Syft prints `WARN adding 'file' tag to the default cataloger selection`. This is expected. It's also why the SBOM has a `files` section with a checksum for each installed `package.json`.

A rerun of these steps from a fresh clone produced exactly the same 3,480 packages (same names, versions and paths). Only the document timestamp and namespace ID change between runs.

## What's in the SBOM

3,475 of the 3,480 entries are npm packages.

- **Server (800 entries).** The Express 5 web stack (`express`, `cors`, `morgan`, `cookie-parser`, `multer`, `express-validator`), Prisma 7 with PostgreSQL (`@prisma/client`, `@prisma/adapter-pg`, `prisma`, `pg`), authentication (`jsonwebtoken`, `bcrypt`, `bcryptjs`), Azure Blob Storage (`@azure/storage-blob`, `smcloudstore`), Google Gemini (`@google/genai`), email (`nodemailer`) and templating (`pug`). About half the tree (391 of 803 lockfile entries) is dev-only tooling: TypeScript, Jest, ts-node, nodemon and `@types/*`.
- **Client (2,679 entries).** React 19 and MUI 9 (`react`, `react-dom`, `@mui/material`, `@emotion/*`, `react-router-dom`, `axios`), plus a large Create React App / CRACO toolchain (`react-scripts`, webpack, Babel, ESLint, PostCSS, Tailwind, Workbox, Jest). Build and test tooling makes up most of this tree.
- **The project's own packages.** `server@1.0.0` and `my-app@0.1.0` (the name in the client's `package.json`).
- **Four Windows executables** that ship inside npm packages (`windows-kill.exe` from `nodemon`, and `term-size.exe` from `npx`'s bundled dependencies). They don't run on the Linux images.

97% of entries declare a license, mostly MIT, then ISC, BSD-3-Clause, Apache-2.0 and BSD-2-Clause. The other 106 are `NOASSERTION`.

### Worth a follow-up

These came up while checking the SBOM. They aren't vulnerabilities, but each one adds attack surface, so they're worth raising with the Material Derailleur team:

- Both Dockerfiles run `npm install` without `--omit=dev`, so test frameworks, TypeScript and nodemon ship in the images. Both containers also start development servers (`nodemon`, `craco start`) rather than production builds.
- The client declares server-side packages as runtime dependencies (`mongoose`, `express`, `nodemailer`, `jsonwebtoken`, `bcryptjs`, `create-react-app`), but nothing in `client-app/src` imports them.
- The client depends on the deprecated `npx@10.2.2` package. It bundles its own copy of `npm@5.1.0` (from 2017), which adds 501 old packages to the client image.

## Verification

- **Valid SPDX.** The SPDX project's own validator (`pyspdxtools` from spdx-tools 0.8.5) reports no errors.
- **Direct dependencies are all present.** Every direct dependency in `server/package.json` (44 of 45) and `client-app/package.json` (63 of 63) is in the SBOM at the version installed from the lockfile. That includes `ajv@8.20.0` from the client Dockerfile's extra install step. The one server entry not listed is `"server": "file:"`, a link from the package to itself, which Syft correctly doesn't follow. The server package itself is listed as `server@1.0.0`.
- **Spot checks.** Server: `express@5.2.1`, `@prisma/client@7.7.0`, `pg@8.20.0`, `jsonwebtoken@9.0.3`, `@azure/storage-blob@12.31.0`. Client: `react@19.2.5`, `@mui/material@9.0.0`, `axios@1.18.0`, `react-router-dom@7.18.2`, `react-scripts@5.0.1`.
- **Reproducible.** Rerunning the commands above from a fresh clone gave the same package set.

## Known limitations

- **Not the built images.** The SBOM doesn't include anything from the base images (`node:20`, `node:18`, `postgres:16.2`): no Debian packages, no Node.js binary, and no npm or Yarn installed there. Scanning the published GHCR images, which issue #36 covers, would include these.
- **Database image not covered.** It's the stock `postgres:16.2` image plus SQL scripts, with no application dependencies.
- **Root `package.json` not covered.** The repository root has its own `package.json` and lockfile (`bwip-js`, `cors`, `express`, `concurrently`, `prettier`, `serve`) for local development scripts, not the application containers.
- **Different Node and npm versions.** Packages were installed with Node 24.6.0 and npm 11.5.1. The images use Node 20 and Node 18 with their bundled npm. The server tree matched its lockfile exactly, and the client tree matched with the pinned `ajv@8.20.0` override.
- **Install scripts skipped.** Because of `--ignore-scripts`, and because `npx prisma generate` wasn't run, some build outputs aren't on disk, such as the compiled `bcrypt` addon and the downloaded Prisma engine.
- **A snapshot of one commit.** The SBOM describes commit `5f89612`. Dependabot updates Material Derailleur's `main` often, so the SBOM will go out of date. Issue #36 tracks generating SBOMs automatically.
- **Repeated package names are expected.** npm installs different versions of a package in different places, for example `react@19.2.5` in the client and `react@18.3.1` nested under `my-tailwind-*` or other tooling.
- **License data wasn't reviewed.** License fields come straight from each package's own `package.json`.

---

Disclosure: This document was partially drafted with AI assistance and manually reviewed before pushing

Last updated 9/25/26 by Kysen Krishnaswamy
