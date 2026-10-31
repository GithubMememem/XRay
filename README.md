# XRay

XRay is a browser-first binary inspection workspace. The GitHub Pages version does not require a terminal, Python server, local engine, or file upload to a remote service.

## Open XRay

https://githubmememem.github.io/XRay/

Choose a file or drop it into the workspace. Analysis runs in the browser tab, and the progress display reports the current parsing stage.

## Browser-supported workflows

| File | Browser workflow | What it provides |
|---|---|---|
| WASM | WABT in a Web Worker | Module validation, section/import/export report, SHA-256 and WAT conversion |
| APK | ZIP + DEX inspection | Package file listing, manifest presence, DEX string identifiers, type identifiers and class descriptors |
| EXE / DLL | PE parser | Architecture, entry point, image base, sections, imported DLL names and readable ASCII strings |
| C/C++, JS, Java, ASM, WAT, text | Source cleanup | Conservative cleanup of common decompiler names, selected masks and explicitly requested pointer-offset rewrites |

APK and PE inspection is static metadata/structure analysis. It does **not** reconstruct full Java, C or C++ source code. Android binary XML manifests are detected but not fully decoded. EXE analysis currently targets Windows PE files; ELF, SO, DYLIB, O and A are not browser-supported in this Pages build.

## Privacy and performance

- Files are read locally by the browser and are not sent to an XRay server.
- No uploaded binary is executed.
- APK files are limited to 48 MiB; PE files are limited to 96 MiB; WASM files are limited to 8 MiB.
- APK archives are unpacked in browser memory, so very large or unusually compressed packages may exceed device memory.
- WASM conversion loads WABT from esm.sh the first time, so an internet connection is needed for that dependency.
- The fflate package is loaded from esm.sh when an APK is opened.

## Accuracy

This version provides inspection data, not full reverse-engineering decompilation for APK/EXE. A real source-level decompiler such as JADX or Ghidra requires a compute environment that can run those tools; a static GitHub Pages site cannot run them by itself. XRay avoids presenting metadata or extracted strings as recovered source code.

## Development

Run the optional Python analysis utilities/tests from a development environment:

```bash
python -m unittest discover -s tests -v
```

The legacy local analysis API and specialist-tool integrations remain in the repository for development, but the published browser UI does not depend on them. See [binary tool notes](docs/BINARY_TOOLS.md).
