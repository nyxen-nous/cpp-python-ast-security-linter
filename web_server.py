#!/usr/bin/env python3
"""SentinelLint local dashboard.

Starts a local-only browser UI over the existing analyzer. No network calls,
no third-party packages, and uploaded source is stored only in a temporary
workspace for the lifetime of the process.
"""
import html
import json
import os
import shutil
import tempfile
import zipfile
import threading
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, unquote

HERE = Path(__file__).resolve().parent
import sys
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import analyzer.cpp  # noqa: F401
import analyzer.python  # noqa: F401
from analyzer.core.engine import scan
from analyzer.core.rule import all_rules
from analyzer.fixes.autofix import apply_fixes

HOST = "127.0.0.1"
PORT = int(os.environ.get("SENTINELLINT_PORT", "8000"))
MAX_UPLOAD = 20 * 1024 * 1024
ALLOWED_EXT = {".py", ".pyw", ".pyi", ".cpp", ".cc", ".cxx", ".c++", ".c", ".h", ".hpp", ".hh", ".hxx"}

SESSIONS = {}
SESSIONS_LOCK = threading.Lock()


def safe_rel(name: str) -> str:
    name = name.replace("\\", "/")
    while name.startswith("/"):
        name = name[1:]
    parts = []
    for p in name.split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            continue
        parts.append(p)
    return "/".join(parts) or "untitled.txt"


def json_bytes(obj):
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def result_payload(scan_id, result, workspace):
    data = result.to_dict()
    data["scan_id"] = scan_id
    data["workspace"] = workspace
    data["rules"] = [
        {"id": r.id, "language": r.language, "category": r.category,
         "severity": r.severity, "message": r.message, "cwe": r.cwe,
         "fixable": bool(r.fixable)}
        for r in sorted(all_rules(), key=lambda x: x.id)
    ]
    # Keep absolute workspace paths private to the frontend.
    for finding in data["findings"]:
        fpath = Path(finding["file"])
        try:
            finding["file"] = fpath.relative_to(Path(workspace)).as_posix()
        except ValueError:
            finding["file"] = fpath.name
    return data


def stored_result(scan_id):
    with SESSIONS_LOCK:
        return SESSIONS.get(scan_id)


def create_workspace():
    return tempfile.mkdtemp(prefix="sentinellint-")


def parse_multipart(handler):
    ctype = handler.headers.get("Content-Type", "")
    clen = int(handler.headers.get("Content-Length", "0"))
    if clen > MAX_UPLOAD:
        raise ValueError("upload exceeds 20 MB limit")
    body = handler.rfile.read(clen)
    if len(body) != clen:
        raise ValueError("incomplete upload")
    headers = f"Content-Type: {ctype}\r\nMIME-Version: 1.0\r\n\r\n".encode()
    # cgi.FieldStorage is unavailable in some Python 3.13 builds, so parse
    # multipart using the stdlib email parser through a tiny local helper.
    from email.parser import BytesParser
    from email.policy import default
    parsed = BytesParser(policy=default).parsebytes(headers + body)
    fields = {}
    if not parsed.is_multipart():
        raise ValueError("expected multipart/form-data")
    for part in parsed.iter_parts():
        name = part.get_param("name", header="Content-Disposition")
        filename = part.get_filename()
        if not name:
            continue
        payload = part.get_payload(decode=True) or b""
        fields.setdefault(name, []).append((filename, payload, part.get_content_type()))
    return fields


def _extract_zip(payload, workspace):
    """Extract only supported source files, safely, into the local workspace."""
    if len(payload) > MAX_UPLOAD:
        raise ValueError("ZIP exceeds the 20 MB request limit")
    written = []
    total_uncompressed = 0
    with zipfile.ZipFile(__import__("io").BytesIO(payload)) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > 5000:
            raise ValueError("ZIP contains too many files (limit: 5000)")
        for info in infos:
            rel = safe_rel(info.filename)
            ext = Path(rel).suffix.lower()
            # Preserve the project ignore file when present. All other
            # unsupported files are intentionally ignored by the scanner.
            allowed = ext in ALLOWED_EXT or Path(rel).name == ".sentinellintignore"
            if not allowed:
                continue
            # Protect against ZIP bombs and unreasonable extraction size.
            total_uncompressed += int(info.file_size)
            if total_uncompressed > 200 * 1024 * 1024:
                raise ValueError("ZIP expands beyond the 200 MB extraction limit")
            dest = Path(workspace, rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(dest, "wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            if ext in ALLOWED_EXT:
                written.append(rel)
    return written


def write_uploaded_files(fields, workspace):
    entries = fields.get("files", [])
    written = []
    for filename, payload, _ctype in entries:
        if not filename:
            continue
        if len(payload) > MAX_UPLOAD:
            raise ValueError("a file exceeds the 20 MB request limit")
        ext = Path(filename).suffix.lower()
        if ext == ".zip":
            written.extend(_extract_zip(payload, workspace))
            continue
        rel = safe_rel(filename)
        if Path(rel).suffix.lower() not in ALLOWED_EXT:
            continue
        dest = Path(workspace, rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)
        written.append(rel)
    return written


def write_paste(fields, workspace):
    items = fields.get("code", [])
    if not items:
        return None
    code = items[0][1].decode("utf-8", errors="replace")
    lang = (fields.get("language", [(None, b"python", "text/plain")])[0][1]
            .decode("utf-8", errors="replace").strip().lower())
    filename = (fields.get("filename", [(None, b"snippet.py", "text/plain")])[0][1]
                .decode("utf-8", errors="replace").strip()) or "snippet.py"
    if lang in {"cpp", "c++", "c"}:
        if not Path(filename).suffix:
            filename += ".cpp"
    else:
        if not Path(filename).suffix:
            filename += ".py"
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        raise ValueError("unsupported snippet extension")
    dest = Path(workspace, safe_rel(filename))
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(code, encoding="utf-8")
    return safe_rel(filename)


class Handler(BaseHTTPRequestHandler):
    server_version = "SentinelLintLocal/1.0"

    def _send(self, status, body, content_type="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, json_bytes(obj), "application/json; charset=utf-8")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            return self._serve_static("index.html")
        if path.startswith("/static/"):
            return self._serve_static(path[len("/static/"):])
        if path == "/api/health":
            return self._json(200, {"ok": True, "offline": True, "rules": len(all_rules())})
        if path == "/api/scan":
            scan_id = parsed.query
            stored = stored_result(scan_id) if scan_id else None
            if not stored:
                return self._json(404, {"error": "scan not found"})
            return self._json(200, result_payload(scan_id, stored["result"], stored["workspace"]))
        if path.startswith("/api/source/"):
            bits = path.split("/", 4)
            if len(bits) < 5:
                return self._json(400, {"error": "bad source request"})
            scan_id, rel = bits[3], unquote(bits[4])
            stored = stored_result(scan_id)
            if not stored:
                return self._json(404, {"error": "scan not found"})
            target = Path(stored["workspace"], safe_rel(rel))
            root = Path(stored["workspace"]).resolve()
            try:
                target.resolve().relative_to(root)
            except ValueError:
                return self._json(400, {"error": "invalid path"})
            if not target.is_file() or target.stat().st_size > MAX_UPLOAD:
                return self._json(404, {"error": "source file not found"})
            try:
                return self._json(200, {"path": rel, "content": target.read_text(encoding="utf-8", errors="replace")})
            except OSError as exc:
                return self._json(500, {"error": str(exc)})
        return self._send(404, "Not found", "text/plain; charset=utf-8")

    def _serve_static(self, rel):
        rel = safe_rel(rel)
        target = (HERE / "web" / rel).resolve()
        root = (HERE / "web").resolve()
        try:
            target.relative_to(root)
        except ValueError:
            return self._send(403, "Forbidden", "text/plain; charset=utf-8")
        if not target.is_file():
            return self._send(404, "Not found", "text/plain; charset=utf-8")
        types = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8"}
        return self._send(200, target.read_bytes(), types.get(target.suffix.lower(), "application/octet-stream"))

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            return self._scan()
        if parsed.path == "/api/fix":
            return self._fix()
        return self._json(404, {"error": "endpoint not found"})

    def _scan(self):
        try:
            fields = parse_multipart(self)
            workspace = create_workspace()
            written = write_uploaded_files(fields, workspace)
            snippet = write_paste(fields, workspace)
            if snippet:
                written.append(snippet)
            if not written:
                shutil.rmtree(workspace, ignore_errors=True)
                return self._json(400, {"error": "no supported source files were provided"})
            top_levels = {Path(p).parts[0] for p in written if Path(p).parts}
            scan_target = workspace
            if len(top_levels) == 1:
                candidate = Path(workspace, next(iter(top_levels)))
                if candidate.is_dir():
                    scan_target = str(candidate)

            result = scan(scan_target)
            scan_id = uuid.uuid4().hex[:12]
            with SESSIONS_LOCK:
                SESSIONS[scan_id] = {"workspace": workspace, "scan_target": scan_target, "result": result}
            payload = result_payload(scan_id, result, workspace)
            payload["inputs"] = written
            return self._json(200, payload)
        except Exception as exc:
            return self._json(400, {"error": str(exc)})

    def _fix(self):
        try:
            clen = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(clen)
            req = json.loads(body.decode("utf-8"))
            scan_id = req.get("scan_id")
            rule_id = req.get("rule_id")
            rel_file = safe_rel(req.get("file", ""))
            line = int(req.get("line", 0))
            stored = stored_result(scan_id)
            if not stored:
                return self._json(404, {"error": "scan not found"})
            result = stored["result"]
            candidates = []
            root = Path(stored["workspace"]).resolve()
            for finding in result.findings:
                if finding.rule_id != rule_id or finding.line != line:
                    continue
                try:
                    rel = Path(finding.file).resolve().relative_to(root).as_posix()
                except ValueError:
                    rel = Path(finding.file).name
                if rel == rel_file and finding.fix:
                    candidates.append(finding)
            if not candidates:
                return self._json(404, {"error": "fixable finding not found"})
            results = apply_fixes(candidates, write=True)
            if not results or not results[0].changed:
                return self._json(400, {"error": "fix was rejected during validation"})
            fresh = scan(stored["scan_target"])
            stored["result"] = fresh
            return self._json(200, result_payload(scan_id, fresh, stored["workspace"]))
        except Exception as exc:
            return self._json(400, {"error": str(exc)})

    def log_message(self, fmt, *args):
        print(f"[SentinelLint] {self.address_string()} - {fmt % args}")


def main():
    print("\nSentinelLint Local Dashboard")
    print(f"Local-only server: http://{HOST}:{PORT}")
    print("No external network access is required. Press Ctrl+C to stop.\n")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        server.server_close()
        with SESSIONS_LOCK:
            workspaces = [v["workspace"] for v in SESSIONS.values()]
            SESSIONS.clear()
        for w in workspaces:
            shutil.rmtree(w, ignore_errors=True)


if __name__ == "__main__":
    main()
