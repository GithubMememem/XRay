#!/usr/bin/env python3
"""Local XRay analysis API. Binds to loopback and never executes target files."""
from __future__ import annotations

import io
import json
import hmac
import os
import tempfile
import threading
import uuid
import zipfile
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from binary_tools import decompile_binary, is_supported_binary

ROOT = Path(__file__).resolve().parents[1]
MAX_UPLOAD = 128 * 1024 * 1024
BIND_HOST = os.environ.get("XRAY_HOST", "127.0.0.1")
ENGINE_TOKEN = os.environ.get("XRAY_TOKEN", "")
ALLOWED_ORIGINS = {
    "https://githubmememem.github.io",
    "http://127.0.0.1:8765",
    "http://localhost:8765",
}
JOBS: dict[str, dict] = {}
LOCK = threading.Lock()


def make_bundle(source_name: str, payload: bytes, progress=None) -> tuple[bytes, str]:
    suffix = Path(source_name).suffix.lower()
    if suffix not in {".apk", ".exe", ".dll", ".elf", ".so", ".dylib", ".o", ".a", ".wasm"}:
        raise ValueError("Supported binaries: APK, EXE, DLL, ELF, SO, DYLIB, O, A and WASM.")
    if len(payload) > MAX_UPLOAD:
        raise ValueError("Upload exceeds the 128 MiB local-engine limit.")
    with tempfile.TemporaryDirectory(prefix="xray-") as temporary:
        root = Path(temporary)
        source = root / ("input" + suffix)
        output = root / "output"
        source.write_bytes(payload)
        if not is_supported_binary(source):
            raise ValueError("Unsupported binary type.")
        summary = decompile_binary(source, output, progress)
        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
            for item in output.rglob("*"):
                if item.is_file() and ".ghidra-project" not in item.parts:
                    archive.write(item, item.relative_to(output).as_posix())
            archive.writestr("XRAY-REPORT.txt", summary + "\n\nInput: " + source_name +
                             "\nTarget binaries are analyzed as data and are never executed.\n")
        return bundle.getvalue(), summary


class Handler(BaseHTTPRequestHandler):
    server_version = "XRayLocalEngine/1.0"

    def authorized(self) -> bool:
        if not ENGINE_TOKEN:
            return True
        supplied = self.headers.get("Authorization", "")
        return hmac.compare_digest(supplied, "Bearer " + ENGINE_TOKEN)

    @property
    def headers_in_origin(self) -> str:
        return self.headers.get("Origin", "")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        origin = self.headers_in_origin
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()

    def json_response(self, status: int, value: dict) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        origin = self.headers_in_origin
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if not self.authorized():
            self.json_response(401, {"error": "Invalid or missing XRay engine token."})
            return
        if self.path == "/api/health":
            self.json_response(200, {"ok": True, "engine": "XRay local", "formats": ["apk", "exe", "dll", "elf", "so", "dylib", "o", "a", "wasm"]})
            return
        self.json_response(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if not self.authorized():
            self.json_response(401, {"error": "Invalid or missing XRay engine token."})
            return
        if self.path != "/api/analyze":
            self.json_response(404, {"error": "Not found"})
            return
        origin = self.headers_in_origin
        if origin and origin not in ALLOWED_ORIGINS:
            self.json_response(403, {"error": "Origin not allowed"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_UPLOAD + 1024 * 1024:
            self.json_response(413, {"error": "Missing file or upload exceeds 128 MiB."})
            return
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self.json_response(400, {"error": "Expected multipart/form-data upload."})
            return
        raw = self.rfile.read(length)
        message = BytesParser(policy=default).parsebytes(
            b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + raw
        )
        uploaded = None
        for part in message.iter_parts():
            if part.get_param("name", header="content-disposition") == "file":
                uploaded = (part.get_filename() or "upload.bin", part.get_payload(decode=True) or b"")
                break
        if not uploaded:
            self.json_response(400, {"error": "No file field found."})
            return
        name, data = uploaded
        job_id = uuid.uuid4().hex
        with LOCK:
            JOBS[job_id] = {"status": "running", "progress": 18, "stage": "File received; preparing analysis", "result": None, "error": None}

        def run() -> None:
            def update_progress(value: int, stage: str) -> None:
                with LOCK:
                    JOBS[job_id].update(progress=value, stage=stage)
            update_progress(25, "Preparing isolated analysis workspace")
            try:
                bundle, summary = make_bundle(Path(name).name, data, update_progress)
                update_progress(97, "Packaging analysis artifacts")
                with LOCK:
                    JOBS[job_id].update(status="complete", progress=100, stage="Analysis complete", result=bundle, summary=summary)
            except Exception as error:
                with LOCK:
                    JOBS[job_id].update(status="error", progress=100, stage="Analysis failed", error=str(error))

        threading.Thread(target=run, daemon=True).start()
        self.json_response(202, {"job_id": job_id, "stage": "Analysis queued"})

    def log_message(self, fmt: str, *args) -> None:
        print("[xray-api] " + fmt % args)


class JobHandler(Handler):
    def do_GET(self) -> None:
        if not self.authorized():
            self.json_response(401, {"error": "Invalid or missing XRay engine token."})
            return
        if self.path.startswith("/api/jobs/"):
            job_id = self.path.rsplit("/", 1)[-1]
            with LOCK:
                job = JOBS.get(job_id)
                if not job:
                    self.json_response(404, {"error": "Job not found"})
                    return
                self.json_response(200, {key: job.get(key) for key in ("status", "progress", "stage", "error", "summary")})
            return
        if self.path.startswith("/api/results/"):
            job_id = self.path.rsplit("/", 1)[-1]
            with LOCK:
                job = JOBS.get(job_id)
                if not job or job.get("status") != "complete":
                    self.json_response(404, {"error": "Result not ready"})
                    return
                data = job["result"]
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="xray-analysis.zip"')
            self.send_header("Content-Length", str(len(data)))
            origin = self.headers_in_origin
            if origin in ALLOWED_ORIGINS:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.end_headers()
            self.wfile.write(data)
            return
        super().do_GET()


if __name__ == "__main__":
    address = BIND_HOST
    port = int(os.environ.get("XRAY_PORT", "8765"))
    if address not in {"127.0.0.1", "localhost", "0.0.0.0"}:
        raise SystemExit("XRAY_HOST must be 127.0.0.1, localhost, or 0.0.0.0.")
    if address == "0.0.0.0" and len(ENGINE_TOKEN) < 24:
        raise SystemExit("Binding for Chromebook port forwarding requires XRAY_TOKEN with at least 24 characters.")
    print(f"XRay local engine listening at http://{address}:{port}")
    if address == "0.0.0.0":
        print("Token authentication is enabled. Enter the same XRAY_TOKEN in the XRay website.")
    ThreadingHTTPServer((address, port), JobHandler).serve_forever()
