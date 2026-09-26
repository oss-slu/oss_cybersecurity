Title: Fix SBOM README: pin Syft install and fix reproduction script

This PR fixes reproducibility and scripting issues in the Material Derailleur SBOM README:

- Use Anchore's installer and pin Syft to v1.52.0 so macOS and Linux reproductions use the same Syft version that produced the SBOM.
- Add a Homebrew note that explains Homebrew may not provide the same version and recommends the pinned installer for exact reproductions.
- Close the unclosed subshell in the reproduction script so the client `npm install` command completes and Syft runs.
- Ensure Ajv is installed at `ajv@8.20.0` (already present in the doc) to freeze the client dependency graph.

Closes: none

Signed-off-by: Copilot <copilot@github.com>
