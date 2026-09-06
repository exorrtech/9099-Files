#!/usr/bin/env python3
"""
test_harness.py: real verification for all 19 chapter scripts
9099 Files: MCP Exploitation Playbook

Starts the mock MCP server (plus its vulnerable dev-tool twin), runs
every chapter script N times, and reports the honest numbers. The
landing page only quotes what this harness actually prints.
"""
import subprocess
import sys
import threading
import time
import socket
import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import mock_mcp_server as mock

RUNS = int(sys.argv[1]) if len(sys.argv) > 1 else 30
BASE = "http://127.0.0.1:8080"

import os as _os
SCRIPTS = [entry for entry in [
    ("chapter_01.py", [BASE]),
    ("chapter_02.py", [BASE]),
    ("chapter_03.py", [BASE]),
    ("chapter_04.py", [BASE]),
    ("chapter_05.py", [BASE]),
    ("chapter_06.py", [BASE]),
    ("chapter_07.py", [BASE]),
    ("chapter_08.py", [BASE]),
    ("chapter_09.py", [BASE]),
    ("chapter_10.py", [BASE, "0.3", "2"]),
    ("chapter_11.py", [BASE]),
    ("chapter_12.py", [BASE]),
    ("chapter_13.py", ["http://127.0.0.1"]),
    ("chapter_14.py", ["https://registry.npmjs.org", "postmark-mcp"]),
    ("chapter_15.py", [BASE]),
    ("chapter_16.py", [BASE]),
    ("chapter_17.py", [BASE]),
    ("chapter_18.py", [BASE]),
    ("chapter_19.py", [BASE]),
] if _os.path.exists(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), entry[0]))]


class DevToolHandler(BaseHTTPRequestHandler):
    """stand-in for a vulnerable MCP dev/inspector tool on :6277"""
    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/health", "/debug/vars", "/debug/eval"):
            self._send(200, json.dumps({"service": "mock-devtool", "debug": True}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode() if n else ""
        if "eval" in self.path or "code" in self.path:
            # vulnerable dev tool: evaluates the canary, echoes result
            self._send(200, json.dumps({"result": "2", "evaluated": body[:40]}))
        else:
            self._send(200, json.dumps({"ok": True}))


def main():
    global mock
    mock.POISON_MUTATE = True

    mcp_srv = ThreadingHTTPServer(("127.0.0.1", 8080), mock.MockMCP)
    dev_srv = ThreadingHTTPServer(("127.0.0.1", 6277), DevToolHandler)
    for s in (mcp_srv, dev_srv):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    def wait_for_port(port, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    if not wait_for_port(8080) or not wait_for_port(6277):
        print("[!] lab servers not ready, aborting", flush=True)
        return 1
    print(f"[*] harness: mock MCP on :8080 (POISON_MUTATE=1), dev tool on :6277", flush=True)
    print(f"[*] running {len(SCRIPTS)} scripts x {RUNS} runs\n", flush=True)

    results = {}
    t0 = time.time()
    for script, args in SCRIPTS:
        passed, failed = 0, 0
        errs = []
        for i in range(RUNS):
            try:
                r = subprocess.run(
                    [sys.executable, f"scripts/{script}"] + args,
                    capture_output=True, text=True, timeout=90)
                out = r.stdout + r.stderr
                ok = (r.returncode == 0
                      and "Traceback" not in out
                      and len(r.stdout.strip()) > 20
                      and ("[+]" in r.stdout or "[!]" in r.stdout or "[~]" in r.stdout))
            except subprocess.TimeoutExpired:
                ok = False
                r = None
                out = "TIMEOUT after 90s"
            if ok:
                passed += 1
            else:
                failed += 1
                if len(errs) < 2:
                    errs = [f"rc={getattr(r, 'returncode', 'timeout')}", str(out)[-300:]]
        results[script] = (passed, failed, errs)
        mark = "PASS" if failed == 0 else "FAIL"
        print("", end="", flush=True)
        print(f"  [{mark}] {script:<18} {passed}/{RUNS}"
              + (f"   first failure: {errs[0]} | {errs[1][:120]}" if failed else ""))

    total_p = sum(p for p, f, _ in results.values())
    total_f = sum(f for p, f, _ in results.values())
    dt = time.time() - t0
    print(f"\n=== RESULTS: {total_p}/{total_p + total_f} runs passed, "
          f"{total_f} failed, {dt:.1f}s total ===")
    with open("harness_results.json", "w") as fh:
        json.dump({"runs_per_script": RUNS, "total_passed": total_p,
                   "total_failed": total_f, "detail":
                   {k: {"passed": p, "failed": f} for k, (p, f, _) in results.items()}}, fh, indent=1)
    return 0 if total_f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
