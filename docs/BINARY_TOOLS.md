# Binary analysis tools

XRay uses specialist local programs for real APK and native-binary decompilation. The GitHub Pages frontend is static; it cannot run Ghidra or JADX by itself.

## Supported inputs

| Input | Tool | Output |
|---|---|---|
| APK | JADX (`jadx`) | Java-like decompiled sources and resources |
| EXE, DLL, SO, ELF, DYLIB, O, A | Ghidra (`analyzeHeadless`) | Per-function C-like pseudocode |
| WASM | WABT | Validation report, section inventory, manifest and WAT |

## Install tools

- **JADX:** https://github.com/skylot/jadx/releases. Install Java, unpack JADX and put its `bin` directory on PATH.
- **Ghidra:** https://github.com/NationalSecurityAgency/ghidra/releases. Unpack it and put the Ghidra `support` directory on PATH so `analyzeHeadless` is available.
- **WABT:** https://github.com/WebAssembly/wabt. Install `wasm-validate`, `wasm-objdump`, and `wasm2wat`.

Check PATH:

```bash
jadx --version
analyzeHeadless
wasm-validate --version
wasm-objdump --version
wasm2wat --version
```

## Start the upload engine

From the XRay repository root:

```bash
python engine/server.py
```

The API listens at `http://127.0.0.1:8765`. Keep it running while using the hosted website. In XRay, use that address in **Local engine address** and press **Check connection**. Then upload an APK or supported native binary. XRay displays the server job stage and downloads a ZIP of the output when analysis finishes.

The service binds only to loopback. It allows the official XRay GitHub Pages origin and local UI origins. It accepts uploads up to 128 MiB, stores each input in a temporary directory, and deletes that temporary workspace when analysis ends. Do not change the bind address to expose it to a public network.

## CLI alternative

```bash
python engine/xray.py app.apk -o output/
python engine/xray.py program.exe -o output/
python engine/xray.py module.wasm -o output/
```

## Important

These tools perform extraction, disassembly and decompilation—not restoration of exact original source. Decompiled output is approximate. XRay never executes a supplied target binary; it only passes it to the selected analysis tool. Treat output as untrusted.
