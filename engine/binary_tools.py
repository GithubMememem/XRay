#!/usr/bin/env python3
"""Best-effort binary adapters. Never executes input binaries."""
from __future__ import annotations
import shutil
import subprocess
from pathlib import Path

NATIVE_SUFFIXES = {".exe", ".dll", ".so", ".elf", ".o", ".a", ".dylib"}
APK_SUFFIXES = {".apk"}
WASM_SUFFIXES = {".wasm"}

def _run(command: list[str], timeout: int = 900) -> None:
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"analysis timed out after {timeout} seconds") from exc
    except OSError as exc:
        raise RuntimeError(f"could not start analysis tool: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout or "tool returned a non-zero exit code")[-4000:]
        raise RuntimeError(detail)

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
        tool = shutil.which("wasm-decompile")
        if tool:
            target = output / (source.stem + ".decompiled.c")
            _run([tool, str(source), "-o", str(target)])
            return f"WASM translated to C-like pseudocode: {target}"
        tool = shutil.which("wasm2wat")
        if tool:
            target = output / (source.stem + ".wat")
            _run([tool, str(source), "-o", str(target)])
            return f"WASM converted to WAT text: {target}"
        raise RuntimeError("WASM support requires WABT (wasm-decompile or wasm2wat) on PATH. See docs/BINARY_TOOLS.md.")
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
