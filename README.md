# XRay

XRay is an offline-first, deterministic source-reconstruction and code-cleanup toolkit. It provides a browser interface and a Python command-line engine.

## Run in the browser
Open [index.html](index.html) in a browser, or enable GitHub Pages for this repository (Settings → Pages → Deploy from a branch → main → /root).

The browser tool processes text-based source locally. Files are not uploaded anywhere.

## Run the Python engine
Python 3.10+; no third-party packages required.

```bash
python engine/xray.py input.c -o recovered.c
python engine/xray.py project.zip -o recovered-project/
python engine/xray.py --help
```

The ZIP mode safely extracts supported source/text files and reconstructs them into the output folder. It rejects path traversal entries and skips oversized files.

## What it does
- Removes selected low-risk disassembly/compiler noise (opt-in patterns only).
- Renames common decompiler-generated local names consistently.
- Simplifies selected 32-bit masks.
- Optionally rewrites byte offsets as array indexes when you explicitly choose a 4-byte element size.
- Uses clang-format when installed and requested.

## Important limits
XRay now has optional local binary-analysis adapters. APK files can be decompiled with JADX, native EXE/DLL/SO/ELF files with Ghidra headless, and WASM files with WABT. Install the relevant tool and follow [Binary tool setup](docs/BINARY_TOOLS.md), then run the same CLI command with the binary as input. These tools produce extracted resources, disassembly, or approximate pseudocode—not the exact original source. XRay never executes the target binary.

All transformations are heuristic and may change program meaning. Keep the original file, inspect the diff, and compile/test reconstructed code before relying on it.
