# Binary analysis tools

XRay can launch specialist local tools for common binary formats. Install the relevant tool and ensure its executable is on PATH.

| Input | Tool | Output |
|---|---|---|
| APK | JADX (jadx) | Java-like decompiled sources and resources |
| EXE, DLL, SO, ELF, object files | Ghidra (analyzeHeadless) | Per-function C-like pseudocode |
| WASM | WABT (wasm-decompile or wasm2wat) | C-like pseudocode or WebAssembly text |

## Install in Codespaces

- **JADX:** download a release from https://github.com/skylot/jadx/releases, unpack it, add its bin directory to PATH, and ensure Java is installed.
- **Ghidra:** download from https://github.com/NationalSecurityAgency/ghidra/releases, unpack it, and add Ghidra's support directory to PATH.
- **WABT:** use your distribution package manager where available, or download from https://github.com/WebAssembly/wabt.

Check installation with jadx --version, analyzeHeadless, or wasm-decompile --help.

## Run

    python engine/xray.py app.apk -o output/
    python engine/xray.py program.exe -o output/
    python engine/xray.py module.wasm -o output/

For native binaries, XRay uses ghidra/ExportDecompiled.java to export decompiler output for discovered functions.

## Important

These tools perform extraction, disassembly, and decompilation—not restoration of exact original source. Compilers remove comments, formatting, many variable names, and sometimes type/control-flow information. Decompiled output is approximate and may need manual repair. XRay never executes the target binary; it only passes it to the selected analysis tool. Analyze only files you own or are authorized to inspect, and treat output as untrusted.
