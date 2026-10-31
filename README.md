# XRay

XRay is a local-first reverse-engineering workspace. It separates lightweight browser inspection from real binary decompilation performed by local specialist tools.

## Browser interface

Live UI: https://githubmememem.github.io/XRay/

The GitHub Pages site can inspect WASM in the browser and clean existing source/decompiler output. It also accepts APK and native binary files, but those formats require the local XRay engine described below. GitHub Pages itself cannot run JADX or Ghidra.

## APK and EXE decompilation

1. Install Python 3.10+.
2. Install JADX for APK files and Ghidra for EXE/DLL/ELF/SO files. Ensure `jadx` or `analyzeHeadless` is on PATH.
3. From the repository root, start the local API:

   ```bash
   python engine/server.py
   ```

4. Leave the server running. In the XRay website, keep the engine address set to `http://127.0.0.1:8765` and click **Check connection**.
5. Choose an APK, EXE, DLL, ELF, SO, or other supported binary. XRay submits it to your own local engine, displays job progress, and downloads a ZIP containing decompiler output and an analysis report.

The local API binds only to loopback and accepts requests from the official GitHub Pages origin or the local UI. It does not expose a public upload server. The local engine has a 128 MiB upload limit to reduce memory pressure. Files are analyzed as data; XRay never executes the supplied target.

### Supported formats

| File | Engine | Output |
|---|---|---|
| APK | JADX | Java-like source and extracted resources |
| EXE, DLL, ELF, SO, DYLIB, O, A | Ghidra headless | Per-function C-like pseudocode |
| WASM | WABT | Validation, section report, and WAT |
| C/C++, JS, Java, ASM, WAT, text | Browser | Conservative source cleanup |

## WebAssembly

Open a `.wasm` file in the browser. XRay parses module sections, imports, exports, function/type counts and SHA-256, then validates and converts it with WABT in a background Web Worker. The browser flow is capped at 8 MiB. The WABT JavaScript module is fetched from esm.sh on first use, so that first conversion needs internet access.

## Source cleanup

The cleanup pass can rename common decompiler-generated local names, simplify selected 32-bit masks, and optionally rewrite byte offsets as array indexes when an element size is explicitly selected. These are heuristics, not a compiler or a true decompiler.

## Limits and accuracy

Decompiler output is an approximation. Compilers discard comments, formatting, many original names, and sometimes type/control-flow information. APK output is Java-like reconstruction; native output is pseudocode; WASM output is WAT. Keep the original binary and review the output. Analyze only files you own or are authorized to inspect.

## Development

Run the Python test suite with:

```bash
python -m unittest discover -s tests -v
```

See [binary tool setup](docs/BINARY_TOOLS.md) for installation details.
