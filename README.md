# XRay

XRay is a local-first binary inspection and source reconstruction workspace. The browser UI combines a launcher-style file discovery flow with a code workspace.

## Browser app

**Live site:** https://githubmememem.github.io/XRay/ (after the first Pages deployment completes).\n\nGitHub Pages is configured with `.github/workflows/pages.yml`. In the repository, open **Settings → Pages** and set **Build and deployment → Source → GitHub Actions** if it is not already selected. Every push to `main` then deploys the static browser app automatically. The workflow publishes only `index.html` and `web/`; the optional Python engine is not hosted on Pages. You can also open [index.html](index.html) locally.

- **WebAssembly:** open a `.wasm` file and XRay parses the module header, section boundaries, imports, exports, function/type counts and SHA-256 locally. It then asks WABT to validate the module and convert it to readable `.wat`. The file is not uploaded. The inspection flow is inspired by REA's evidence-first WASM workflow; see `web/wasm-inspector.js` and `THIRD_PARTY_NOTICES.md`.
- **Source and decompiler output:** paste or open C/C++, JavaScript, Java, ASM, WAT and text, then run the conservative cleanup pass locally.
- **Export:** save the generated WAT or reconstructed text from the workspace.

The WABT JavaScript module is loaded from esm.sh on first WASM use, so an internet connection is needed for that first library load. After it loads, parsing, validation and conversion run locally in the browser. Browser inspection is capped at 8 MiB to bound memory use. The UI uses a static starfield (no continuous animation), caps canvas pixel density, and shows staged analysis progress to reduce unnecessary device load. WebGPU is not required: WebGPU accelerates certain GPU workloads but is not a general-purpose decompiler.

## AI-assisted reverse-engineering handoff\n\nUse the **Copy AI handoff prompt** button in the site, paste it into Claude or another coding assistant, and attach the target file separately. The prompt points the assistant to this repository and asks it to inspect the project and analyze the uploaded target without executing it. GitHub Pages hosts the XRay web UI; it does not automatically upload a target file to Claude or run the Python engine.\n\n## Python engine

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
