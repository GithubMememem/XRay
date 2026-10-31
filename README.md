# XRay

XRay is a local-first binary inspection and source reconstruction workspace. The browser UI combines a launcher-style file discovery flow with a code workspace.

## Browser app

Open [index.html](index.html), or enable GitHub Pages (Settings → Pages → Deploy from a branch → main → /root).

- **WebAssembly:** open a `.wasm` file and XRay parses the module header, section boundaries, imports, exports, function/type counts and SHA-256 locally. It then asks WABT to validate the module and convert it to readable `.wat`. The file is not uploaded. The inspection flow is inspired by REA's evidence-first WASM workflow; see `web/wasm-inspector.js` and `THIRD_PARTY_NOTICES.md`.
- **Source and decompiler output:** paste or open C/C++, JavaScript, Java, ASM, WAT and text, then run the conservative cleanup pass locally.
- **Export:** save the generated WAT or reconstructed text from the workspace.

The WABT JavaScript module is loaded from esm.sh on first WASM use, so an internet connection is needed for that first library load. After it loads, parsing, validation and conversion run locally in the browser. Browser inspection is capped at 8 MiB to bound memory use. WebGPU is not required: WebGPU accelerates certain GPU workloads but is not a general-purpose decompiler.

## Python engine

Python 3.10+; no third-party Python packages required for source cleanup.

```bash
python engine/xray.py input.c -o recovered.c
python engine/xray.py project.zip -o recovered-project/
python engine/xray.py module.wasm -o output/
python engine/xray.py app.apk -o output/
python engine/xray.py program.exe -o output/
```

Optional binary tools:
- WASM: WABT (`wasm-validate`, `wasm-objdump`, and `wasm2wat` recommended; `wasm-decompile` is a fallback)
- APK: JADX
- Native EXE/DLL/ELF/SO/object files: Ghidra headless

See [Binary tool setup](docs/BINARY_TOOLS.md) for installation details. These tools produce WAT, extracted resources, disassembly or approximate pseudocode—not exact original source. XRay never executes a supplied target binary.

## What the cleanup pass does

- Renames common decompiler-generated local names consistently.
- Simplifies selected 32-bit masks.
- Optionally rewrites byte offsets as array indexes when an element size is explicitly selected.
- Uses clang-format when installed and requested by the Python CLI.

All transformations are heuristic and may change program meaning. Keep the original file and review, compile and test reconstructed output before relying on it.
