# CoreDesk SBOM

## What Was Scanned

The CoreDesk repository was scanned using Syft. The repository directory was used as the scan target rather than a built container image because Docker was not available in the local environment.

The resulting SBOM is stored at:

`docs/sbom/core_desk-sbom.spdx.json`

## Syft Command

The SBOM was generated using the following command from the root of the CoreDesk repository:

```bash
syft scan dir:. -o spdx-json=docs/sbom/core_desk-sbom.spdx.json
```

## Syft Installation and Execution

Syft version 1.52.0 was installed and run locally on macOS.

The generated SBOM was written in SPDX JSON format. The JSON output was also validated using:

```bash
python3 -m json.tool docs/sbom/core_desk-sbom.spdx.json
```

## Dependencies Identified

The scan identified dependencies associated with the CoreDesk repository, including JavaScript and Node.js packages used throughout the application, API, and testing components.

The SBOM records package information such as package names, versions, and other metadata detected by Syft.

## Known Limitations

Because the repository directory was scanned instead of a built container image or packaged application, the SBOM represents dependencies detectable from the source repository rather than the exact contents of a production deployment.

The scan may include development or testing dependencies that would not be included in production. It may also omit dependencies that are introduced only during the build or deployment process.
