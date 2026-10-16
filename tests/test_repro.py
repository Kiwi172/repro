"""Tests for repro. Run with: python3 -m pytest tests/ (or python3 tests/test_repro.py)

All replay tests run against a local stdlib HTTP server whose behaviour the
test controls -- no internet needed, fully deterministic.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

TOOL = str(Path(__file__).resolve().parent.parent / "repro.py")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import repro as rp  # noqa: E402

# ---------------------------------------------------------------------------
# local server with switchable behaviour
# ---------------------------------------------------------------------------

STATE = {"status": 500, "body": b"internal error", "extra_hdr": {}}


class H(BaseHTTPRequestHandler):
    def _handle(self):
        STATE["hits"] = STATE.get("hits", 0) + 1
        self.send_response(STATE["status"])
        self.send_header("content-type", "text/plain")
        self.send_header("x-request-id", f"random-{STATE['hits']}")  # noise
        self.send_header("date", "now")                              # noise
        for k, v in STATE["extra_hdr"].items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(STATE["body"])

    do_GET = do_POST = do_HEAD = _handle

    def log_message(self, *a):
        pass


def serve():
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


try:  # reset the fake server's behaviour between tests under pytest;
    import pytest              # the standalone runner resets it itself
    @pytest.fixture(autouse=True)
    def _reset_state():
        STATE.update(status=500, body=b"internal error", extra_hdr={},
                     hits=0)
except ImportError:
    pass


def run(*argv):
    return subprocess.run([sys.executable, TOOL, *argv],
                          capture_output=True, text=True)


POC_TMPL = """# CBX-004 — admin 500 on malformed login

```bash
curl -s "http://{host}/api/login/" \\
  -A "CS_YWH/BB" -H "Content-Type: application/json" \\
  -X POST -d '{{"email":"","password":"x"}}'
```
"""


def write_poc(tmp: Path, host: str) -> Path:
    p = tmp / "CBX-004.md"
    p.write_text(POC_TMPL.format(host=host))
    return p


# ---------------------------------------------------------------------------
# extraction / parsing (pure)
# ---------------------------------------------------------------------------

def test_extract_curl_from_markdown():
    md = ("text\n```bash\ncurl -s https://a.example/x \\\n  -H 'X: 1'\n"
          "```\nnot code: curl https://ignored\n```python\nprint(1)\n```\n")
    cmds = list(rp.extract_curl(md))
    assert len(cmds) == 1 and cmds[0].endswith("-H 'X: 1'")


def test_parse_curl_flags():
    r = rp.parse_curl("curl -s 'https://e.x/p?q=1' -X PUT -H 'A: b' "
                     "-u 'user:pw' -d 'body'")
    assert r["method"] == "PUT" and r["url"] == "https://e.x/p?q=1"
    assert r["headers"]["a"] == "b"
    assert r["headers"]["authorization"].startswith("Basic ")
    assert r["body"] == b"body"
    # method inference
    assert rp.parse_curl("curl https://e.x/")["method"] == "GET"
    assert rp.parse_curl("curl -I https://e.x/")["method"] == "HEAD"
    assert rp.parse_curl("curl -d x https://e.x/")["method"] == "POST"
    assert rp.parse_curl("curl -s ftp://nope/") is None
    # combined short flags and attached values (found in real PoC files)
    assert rp.parse_curl("curl -sI https://e.x/")["method"] == "HEAD"
    assert rp.parse_curl("curl -sSL https://e.x/")["method"] == "GET"
    r2 = rp.parse_curl("curl -s -HOrigin:https://evil.com https://e.x/")
    assert r2["headers"]["origin"] == "https://evil.com"


def test_parse_http_file():
    raw = ("POST /api/login HTTP/1.1\nHost: e.example\n"
           "Content-Type: application/json\n\n{\"a\":1}\n")
    reqs = list(rp.parse_http_file(raw))
    assert len(reqs) == 1
    r = reqs[0]
    assert r["method"] == "POST" and r["url"] == "https://e.example/api/login"
    assert r["body"].startswith(b'{"a":1}')  # trailing newline normalized


def test_evidence_block_body_stops_at_response_marker():
    block = ("POST /api/login HTTP/1.1\nHost: e.example\n\n{\"a\":1}\n"
             "--- response ---\nHTTP/1.1 500 Internal Server Error\n"
             "content-type: application/json\n\n{\"error\":500}\n")
    reqs = list(rp.parse_http_file(block))
    assert len(reqs) == 1
    assert reqs[0]["body"] == b'{"a":1}'      # response not in the body


def test_extract_reads_fenced_http_blocks(tmp_path):
    md = tmp_path / "finding.md"
    md.write_text(
        "# F — finding\n\n```http\nGET /api/x HTTP/1.1\nHost: e.example\n\n"
        "--- response ---\nHTTP/1.1 200 OK\n\nok\n```\n")
    reqs = rp.extract_requests(md)
    assert len(reqs) == 1
    assert reqs[0]["method"] == "GET"
    assert reqs[0]["url"] == "https://e.example/api/x"


# ---------------------------------------------------------------------------
# replay + verdicts (local server)
# ---------------------------------------------------------------------------

def test_baseline_then_same_then_changed(tmp_path):
    srv = serve()
    host = f"127.0.0.1:{srv.server_address[1]}"
    poc = write_poc(tmp_path, host)
    common = ["--allow-write", "--delay", "0", str(poc)]

    r1 = run(*common)
    assert "BASELINE" in r1.stdout and "1 baseline" in r1.stdout

    r2 = run(*common)
    # noise headers (x-request-id, date) differ but verdict stays SAME
    assert "STILL REPRODUCES" in r2.stdout and "1 still-reproduces" in r2.stdout

    STATE["status"] = 400
    STATE["body"] = b"validation failed"
    r3 = run(*common)
    assert "CHANGED" in r3.stdout
    assert "status: 500 -> 400" in r3.stdout
    assert "validation failed" in r3.stdout          # body diff shown
    srv.shutdown()


def test_network_error_is_inconclusive_not_fixed(tmp_path):
    srv = serve()
    port = srv.server_address[1]
    poc = write_poc(tmp_path, f"127.0.0.1:{port}")
    assert "BASELINE" in run("--allow-write", "--delay", "0", str(poc)).stdout
    srv.shutdown()
    r = run("--allow-write", "--delay", "0", "--retries", "0", str(poc))
    assert "INCONCLUSIVE" in r.stdout
    assert "STILL REPRODUCES" not in r.stdout


def test_write_methods_gated(tmp_path):
    srv = serve()
    host = f"127.0.0.1:{srv.server_address[1]}"
    poc = write_poc(tmp_path, host)
    r = run("--delay", "0", str(poc))       # no --allow-write
    assert "SKIPPED" in r.stdout and "1 skipped" in r.stdout
    assert "BASELINE" not in r.stdout
    srv.shutdown()


def test_header_change_detected(tmp_path):
    srv = serve()
    host = f"127.0.0.1:{srv.server_address[1]}"
    poc = write_poc(tmp_path, host)
    common = ["--allow-write", "--delay", "0", str(poc)]
    run(*common)
    STATE["extra_hdr"]["access-control-allow-origin"] = "*"
    r = run(*common)
    assert "CHANGED" in r.stdout
    assert "access-control-allow-origin" in r.stdout
    srv.shutdown()


def test_list_mode_sends_nothing(tmp_path):
    srv = serve()
    host = f"127.0.0.1:{srv.server_address[1]}"
    poc = write_poc(tmp_path, host)
    before = STATE.get("hits", 0)
    r = run("--list", str(poc))
    assert "POST" in r.stdout and host in r.stdout
    assert STATE.get("hits", 0) == before
    srv.shutdown()


def test_json_output(tmp_path):
    srv = serve()
    host = f"127.0.0.1:{srv.server_address[1]}"
    poc = write_poc(tmp_path, host)
    r = run("--allow-write", "--delay", "0", "--json", str(poc))
    d = json.loads(r.stdout)
    assert d["tool"] == "repro"
    assert d["results"][0]["status"] == 500
    assert d["results"][0]["verdict"] == "baseline"
    srv.shutdown()


if __name__ == "__main__":
    import tempfile
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            import inspect
            if inspect.signature(fn).parameters:
                with tempfile.TemporaryDirectory() as d:
                    STATE.update(status=500, body=b"internal error",
                                 extra_hdr={}, hits=0)
                    try:
                        fn(Path(d))
                        print(f"  ok  {name}")
                    except Exception as e:
                        failed += 1
                        print(f"FAIL  {name}: {type(e).__name__}: {e}")
            else:
                try:
                    fn()
                    print(f"  ok  {name}")
                except Exception as e:
                    failed += 1
                    print(f"FAIL  {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
