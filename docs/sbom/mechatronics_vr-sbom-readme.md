# MechatronicsVR SBOM

This folder holds a baseline Software Bill of Materials (SBOM) for [MechatronicsVR](https://github.com/oss-slu/mechatronics-vr), generated with [Syft](https://github.com/anchore/syft) 1.51.1 on 2026-09-28. The file is `mechatronics_vr.spdx.json` (SPDX 2.3, JSON). It describes commit [`3235f0c`](https://github.com/oss-slu/mechatronics-vr/commit/3235f0cee047bef52f8aac14299c1210e947d062) on `main`.

## What was scanned

The MechatronicsVR repository checkout, not a packaged build. This is the issue's fallback target, and it was the only practical one:

- MechatronicsVR is an Unreal Engine 5.7 project. Shipping builds are packaged from the Unreal Editor on a developer workstation, and there is no packaged build in the repository or on a GitHub Release to scan.
- Unreal has no package manager or lockfile, so there is no "resolved build environment" to recreate. The project's dependencies are the engine and its bundled plugins, which are installed on each machine through the Epic Games Launcher and are not in the repository.

So the SBOM covers what is committed to the repository: the C++ source, configuration, two in-repo plugins (`Plugins/MetaXR`, `Plugins/MCPUnreal`), and the third-party binaries inside them.

## Syft installation

Installed on macOS with Homebrew:

```bash
brew install syft
syft version   # 1.51.1
```

Syft reads local files only and uploads nothing. Its one network call is a check for a newer release.

## Command used

Run from the root of a MechatronicsVR clone checked out at `3235f0c`:

```bash
git clone https://github.com/oss-slu/mechatronics-vr.git
cd mechatronics-vr
git checkout 3235f0cee047bef52f8aac14299c1210e947d062

syft scan dir:. \
  --source-name mechatronics-vr \
  --source-version 3235f0c \
  -o spdx-json=mechatronics_vr.spdx.json
```

`--source-name` and `--source-version` set the name and version of the SBOM's root package so the document says what it describes. Copy the output into `docs/sbom/` in this repository. The scan finishes in seconds because Syft ignores Unreal content assets (`.uasset`, `.umap`); it only opens files that match one of its catalogers.

## What the SBOM contains

Five components plus the repository itself as the root package:

| Component | Version | Found in |
|---|---|---|
| OVRPlugin | 1.205.0 | `Plugins/MetaXR/Source/Thirdparty/OVRPlugin/…/OVRPlugin.dll` and `libOVRPlugin.so` |
| EngineTelemetry | unknown | `Plugins/MetaXR/Source/Thirdparty/EngineTelemetry/…` |
| mrutilitykitshared | unknown | `Plugins/MetaXR/Source/Thirdparty/MRUtilityKitShared/…` |
| Node.js | 16.13.2 | `Content/Oculus/Tools/ovr-platform-util.exe` |
| actions/checkout | v4 | `.github/workflows/cpp-format.yml` |

The first three are the native libraries that ship inside the Meta XR plugin (version 1.205.0), each present as a Windows `.dll` and an Android `.so`. `ovr-platform-util.exe` is Meta's command-line tool for uploading builds to the Quest store; it is packaged as a standalone Node.js executable, which is why Syft reports a Node.js runtime. It is a developer tool, not part of the game. `actions/checkout` is the one dependency of the repository's clang-format workflow.

## Verification

- `python3 -m json.tool docs/sbom/mechatronics_vr.spdx.json` parses the file without error.
- The `OVRPlugin` version in the SBOM (1.205.0) matches `"VersionName": "1.205.0"` in `Plugins/MetaXR/OculusXR.uplugin`, so the version Syft read out of the binary is the version the plugin declares.
- The repository contains eight compiled binaries (`git ls-files | grep -E '\.(dll|so|exe|lib)$'`). The seven loadable ones are listed in the SBOM's `files` section; the eighth, `OVRPlugin.lib`, is a link-time import stub with no runtime code.

## Known limitations

- **This is not the shipping build.** The engine runtime, the engine-bundled plugins enabled in `MechatronicsVR.uproject` (OpenXR, MetaHuman, LiveLinkControlRig, and others), and the engine modules linked in `Source/MechatronicsVR/MechatronicsVR.Build.cs` are all absent, because none of them are in the repository. The in-repo plugins are also not listed as plugins, only their binaries are, since Syft has no cataloger for `.uplugin` or `.Build.cs` files. A full inventory requires scanning the packaged Windows output, which is the subject of issue #41.
- **Two components have no version.** `EngineTelemetry` and `mrutilitykitshared` carry no version string Syft recognizes. Both ship with Meta XR 1.205.0.
- **No license data.** Every license field is `NOASSERTION`; the binaries embed nothing Syft can read.
- **One commit only.** The SBOM describes `3235f0c` and goes stale as `main` moves. Issue #41 automates regeneration in CI.
- **Node.js 16 is end-of-life** (since September 2023). It is inside a developer tool rather than game code, but the MechatronicsVR team may want to update or remove `ovr-platform-util.exe`.

---

Disclosure: This document was partially drafted with AI assistance and manually reviewed before pushing.
