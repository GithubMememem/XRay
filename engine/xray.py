#!/usr/bin/env python3
"""XRay: deterministic, conservative source cleanup and reconstruction helpers."""
from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath

TEXT_EXTENSIONS = {
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".hxx", ".txt",
    ".asm", ".s", ".json", ".xml", ".log", ".js", ".ts", ".java",
    ".kt", ".py", ".rs", ".go", ".wasm.txt", ".wat"
}
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024

# Keep keywords and common type names intact when renaming decompiler locals.
KEEP = set("""
auto break case char const continue default do double else enum extern float for
goto if inline int long register restrict return short signed sizeof static struct
switch typedef union unsigned void volatile while _Bool _Complex _Imaginary
bool true false nullptr class public private protected virtual template typename
namespace using new delete this throw try catch constexpr static_cast reinterpret_cast
uint8_t uint16_t uint32_t uint64_t int8_t int16_t int32_t int64_t size_t
""".split())


def _mask_comments_and_strings(source: str) -> str:
    """Return same-length text with comments/string contents replaced by spaces."""
    out = list(source)
    i, n = 0, len(source)
    state = "code"
    quote = ""
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "line"
                continue
            if ch == "/" and nxt == "*":
                out[i] = out[i + 1] = " "
                i += 2
                state = "block"
                continue
            if ch in ("'", '"'):
                quote = ch
                out[i] = " "
                state = "string"
        elif state == "line":
            if ch == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block":
            if ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "code"
                continue
            if ch != "\n":
                out[i] = " "
        elif state == "string":
            if ch == "\\":
                out[i] = " "
                if i + 1 < n:
                    if source[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
            elif ch == quote:
                out[i] = " "
                state = "code"
            elif ch != "\n":
                out[i] = " "
        i += 1
    return "".join(out)


def rename_decompiler_locals(source: str) -> str:
    """Rename common decompiler local names in code, never inside comments/strings."""
    masked = _mask_comments_and_strings(source)
    pattern = re.compile(r"\b(?:local_[0-9a-fA-F]+h?|var_[0-9a-fA-F]+h?|param_[0-9]+)\b")
    mapping: dict[str, str] = {}
    for match in pattern.finditer(masked):
        name = match.group(0)
        if name not in mapping:
            mapping[name] = f"recovered_var_{len(mapping) + 1}"
    if not mapping:
        return source
    # Replace only spans identified in the masked code.
    pieces, last = [], 0
    for match in pattern.finditer(masked):
        pieces.append(source[last:match.start()])
        pieces.append(mapping[match.group(0)])
        last = match.end()
    pieces.append(source[last:])
    return "".join(pieces)


def simplify_32bit_masks(source: str) -> str:
    """Replace common unsigned 32-bit all-ones masks with an explicit cast."""
    source = re.sub(r"\(([^()\n]+)\s*&\s*0x[Ff]{8}\)", r"(uint32_t)(\1)", source)
    source = re.sub(r"\b([A-Za-z_]\w*)\s*&\s*0x[Ff]{8}\b", r"(uint32_t)(\1)", source)
    return source


def rewrite_pointer_offsets(source: str, element_size: int | None = None) -> str:
    """Convert ptr + byte_offset to ptr[index] only with an explicit element size."""
    if not element_size:
        return source
    if element_size < 1:
        raise ValueError("element size must be a positive integer")
    pattern = re.compile(r"\b([A-Za-z_]\w*)\s*\+\s*(\d+)\b")
    def replace(match: re.Match[str]) -> str:
        offset = int(match.group(2))
        if offset == 0 or offset % element_size:
            return match.group(0)
        return f"{match.group(1)}[{offset // element_size}]"
    return pattern.sub(replace, source)


def clean_source(source: str, element_size: int | None = None) -> str:
    source = rename_decompiler_locals(source)
    source = simplify_32bit_masks(source)
    source = rewrite_pointer_offsets(source, element_size)
    return source


def format_with_clang(source: str) -> tuple[str, bool]:
    """Format C/C++ if clang-format is installed; otherwise return unchanged."""
    import shutil
    import subprocess
    executable = shutil.which("clang-format")
    if not executable:
        return source, False
    try:
        result = subprocess.run(
            [executable], input=source, text=True, capture_output=True,
            timeout=20, check=True
        )
        return result.stdout, True
    except (subprocess.SubprocessError, OSError):
        return source, False


def process_text(path: Path, output: Path, element_size: int | None, use_formatter: bool) -> str:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds {MAX_FILE_BYTES} byte limit")
    raw = path.read_text(encoding="utf-8", errors="replace")
    result = clean_source(raw, element_size)
    formatted = False
    if use_formatter and path.suffix.lower() in {".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".hxx"}:
        result, formatted = format_with_clang(result)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result, encoding="utf-8")
    return "formatted with clang-format" if formatted else "processed"


def safe_extract_zip(archive: Path, output_dir: Path, element_size: int | None, use_formatter: bool) -> int:
    total = 0
    count = 0
    root = output_dir.resolve()
    with zipfile.ZipFile(archive) as zf:
        for item in zf.infolist():
            if item.is_dir():
                continue
            relative = PurePosixPath(item.filename)
            if relative.is_absolute() or ".." in relative.parts:
                print(f"SKIP unsafe path: {item.filename}", file=sys.stderr)
                continue
            if Path(item.filename).suffix.lower() not in TEXT_EXTENSIONS:
                continue
            if item.file_size > MAX_FILE_BYTES or total + item.file_size > MAX_TOTAL_BYTES:
                print(f"SKIP size limit: {item.filename}", file=sys.stderr)
                continue
            target = (root / Path(*relative.parts)).resolve()
            if root not in target.parents and target != root:
                print(f"SKIP unsafe path: {item.filename}", file=sys.stderr)
                continue
            data = zf.read(item)
            total += len(data)
            text = clean_source(data.decode("utf-8", errors="replace"), element_size)
            if use_formatter and target.suffix.lower() in {".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".hxx"}:
                text, _ = format_with_clang(text)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="XRay deterministic source reconstruction toolkit")
    parser.add_argument("input", type=Path, help="source/text file or ZIP archive")
    parser.add_argument("-o", "--output", type=Path, required=True, help="output file or directory")
    parser.add_argument("--element-size", type=int, default=None,
                        help="explicit pointer element size in bytes (e.g. 4); enables offset-to-index rewrite")
    parser.add_argument("--clang-format", action="store_true", help="format C/C++ when clang-format is installed")
    args = parser.parse_args()
    try:
        if not args.input.exists():
            raise FileNotFoundError(args.input)
        if zipfile.is_zipfile(args.input):
            count = safe_extract_zip(args.input, args.output, args.element_size, args.clang_format)
            print(f"XRay processed {count} supported file(s) into {args.output}")
        elif args.input.suffix.lower() in TEXT_EXTENSIONS:
            status = process_text(args.input, args.output, args.element_size, args.clang_format)
            print(f"XRay: {status} → {args.output}")
        else:
            raise ValueError("unsupported input. For EXE/DLL/APK/SO/WASM binaries, extract or disassemble first; XRay does not execute binaries or recover original source directly.")
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"XRay error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
