#!/usr/bin/env python3
"""Best-effort binary adapters. Never executes input binaries."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

NATIVE_SUFFIXES = {".exe", ".dll", ".so", ".elf", ".o", ".a", ".dylib"}
APK_SUFFIXES = {".apk"}
WASM_SUFFIXES = {".wasm"}
WASM_MAX_BYTES = 8 * 1024 * 1024


def _run(command: list[str], timeout: int = 900) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"analysis timed out after {timeout} seconds") from exc
    except OSError as exc:
        raise RuntimeError(f"could not start analysis tool: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout or "tool returned a non-zero exit code")[-4000:]
        raise RuntimeError(detail)
    return result


def _inspect_wasm(source: Path, output: Path) -> str:
    size = source.stat().st_size
    if size > WASM_MAX_BYTES:
        raise RuntimeError(f"WASM input exceeds XRay's {WASM_MAX_BYTES}-byte safety limit.")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    def assert_unchanged() -> None:
        current = hashlib.sha256(source.read_bytes()).hexdigest()
        if current != digest:
            raise RuntimeError("WASM input changed during analysis; refusing to mix evidence from different file contents.")
    validate = shutil.which("wasm-validate")
    objdump = shutil.which("wasm-objdump")
    wasm2wat = shutil.which("wasm2wat")
    decompile = shutil.which("wasm-decompile")

    if validate and objdump and wasm2wat:
        assert_unchanged()
        validation = _run([validate, "--enable-all", "--ignore-custom-section-errors", str(source)], timeout=30)
        assert_unchanged()
        sections = _run([objdump, "-h", "-x", str(source)], timeout=30)
        assert_unchanged()
        wat = _run([wasm2wat, "--enable-all", "--ignore-custom-section-errors", str(source)], timeout=30)
        assert_unchanged()
        (output / (source.stem + ".validation.txt")).write_text(
            "WABT validation passed.\n" + (validation.stdout or validation.stderr), encoding="utf-8"
        )
        (output / (source.stem + ".sections.txt")).write_text(sections.stdout, encoding="utf-8")
        (output / (source.stem + ".wat")).write_text(wat.stdout, encoding="utf-8")
        report = {
            "format": "WebAssembly",
            "input": source.name,
            "size_bytes": size,
            "sha256": digest,
            "validation": "passed",
            "tools": {
                "wasm-validate": validate,
                "wasm-objdump": objdump,
                "wasm2wat": wasm2wat,
            },
            "artifacts": {
                "validation": source.stem + ".validation.txt",
                "sections": source.stem + ".sections.txt",
                "wat": source.stem + ".wat",
            },
        }
        (output / (source.stem + ".analysis.json")).write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        return (
            f"WASM validated and inspected with WABT. WAT: {output / (source.stem + '.wat')}; "
            f"sections: {output / (source.stem + '.sections.txt')}; SHA-256: {digest}"
        )

    if decompile:
        target = output / (source.stem + ".decompiled.c")
        assert_unchanged()
        _run([decompile, str(source), "-o", str(target)], timeout=30)
        assert_unchanged()
        return f"WASM translated to C-like pseudocode: {target}. Install wasm-validate, wasm-objdump and wasm2wat for full artifact inspection."
    if wasm2wat:
        target = output / (source.stem + ".wat")
        assert_unchanged()
        _run([wasm2wat, str(source), "-o", str(target)], timeout=30)
        assert_unchanged()
        return f"WASM converted to WAT text: {target}. Install wasm-validate and wasm-objdump for validation and section evidence."
    raise RuntimeError(
        "WASM support requires WABT. Install wasm-validate, wasm-objdump and wasm2wat "
        "(recommended), or wasm-decompile. See docs/BINARY_TOOLS.md."
    )


def decompile_binary(source: Path, output: Path) -> str:
    suffix = source.suffix.lower()
    output.mkdir(parents=True, exist_ok=True)
    if suffix in APK_SUFFIXES:
        tool = shutil.which("jadx")
        if not tool:
            raise RuntimeError("APK support requires JADX (jadx) on PATH. See docs/BINARY_TOOLS.md.")
        target = output / "jadx"
        _run([tool, "-d", str(target), str(source)])
        return f"APK decoded with JADX into {target}; output is Java-like, not original source."
    if suffix in WASM_SUFFIXES:
        return _inspect_wasm(source, output)
    if suffix in NATIVE_SUFFIXES:
        tool = shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat")
        if not tool:
            raise RuntimeError("Native binary decompilation requires Ghidra analyzeHeadless on PATH. See docs/BINARY_TOOLS.md.")
        project = output / ".ghidra-project"
        target = output / "decompiled"
        target.mkdir(parents=True, exist_ok=True)
        scripts = Path(__file__).resolve().parents[1] / "ghidra"
        _run([tool, str(project), "xray_analysis", "-import", str(source.resolve()),
              "-scriptPath", str(scripts), "-postScript", "ExportDecompiled.java", str(target),
              "-deleteProject"], timeout=1800)
        return f"Native binary analyzed with Ghidra; pseudocode exported to {target}"
    raise RuntimeError(f"unsupported binary extension: {suffix or '(none)'}")


def is_supported_binary(path: Path) -> bool:
    return path.suffix.lower() in APK_SUFFIXES | WASM_SUFFIXES | NATIVE_SUFFIXES
