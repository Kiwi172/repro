#!/usr/bin/env python3
"""repro -- does the finding still reproduce?

You filed a bug with a curl PoC. Three weeks later triage says "cannot
reproduce" -- or you want to check before commenting. repro extracts the
curl requests from your PoC markdown (or .http files), replays them
exactly, and diffs the responses against the snapshot you saved when you
found it: status, headers (noise stripped), body. Verdict per request:
still-reproduces / changed / inconclusive. A network error is never
reported as "fixed".
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import shlex
import ssl
import sys
import time
from http.client import HTTPSConnection, HTTPConnection
from pathlib import Path

VERSION = "0.1.0"

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# headers that differ between identical responses and prove nothing
NOISE_HEADERS = {
    "date", "set-cookie", "x-request-id", "x-amz-cf-id", "x-amz-cf-pop",
    "x-trace-id", "x-trace", "traceparent", "cf-ray", "cf-cache-status",
    "x-nf-request-id", "x-cf-requestid", "x-cache", "x-cache-hits",
    "age", "server-timing", "x-served-by", "x-timer", "via",
    "x-envoy-upstream-service-time", "x-amz-cognito-request-id",
    "x-amzn-requestid", "x-amzn-trace-id",
    "report-to", "nel", "alt-svc", "content-length", "vary", "expires",
}

CURL_BLOCK = re.compile(
    r"```(?:bash|sh|shell|console|text)?\s*\n(.*?)```", re.S)
CURL_CMD = re.compile(r"(?:^|\n)\s*(?:sudo\s+)?curl\b")


# ---------------------------------------------------------------------------
# extraction: curl commands from md/sh, raw requests from .http
# ---------------------------------------------------------------------------

def extract_curl(text: str):
    """Yield curl command strings from fenced blocks and bare lines."""
    chunks = [m.group(1) for m in CURL_BLOCK.finditer(text)] or [text]
    for chunk in chunks:
        # join backslash continuations
        joined = re.sub(r"\\\s*\n\s*", " ", chunk)
        for line in joined.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if CURL_CMD.search(line):
                yield line


def parse_curl(cmd: str):
    """curl command -> {method, url, headers, body} or None."""
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return None
    argv = argv[argv.index("curl") + 1:] if "curl" in argv else argv
    method, url, headers, body = None, None, {}, None
    i = 0
    val_flags = {"-H": "header", "--header": "header",
                 "-X": "method", "--request": "method",
                 "-d": "data", "--data": "data", "--data-raw": "data",
                 "--data-binary": "data",
                 "-A": "ua", "--user-agent": "ua",
                 "-b": "cookie", "--cookie": "cookie",
                 "-u": "user", "--user": "user",
                 "-o": "ignore", "--output": "ignore",
                 "-w": "ignore", "--write-out": "ignore",
                 "-m": "ignore", "--max-time": "ignore",
                 "--connect-timeout": "ignore", "--url": "url"}
    bool_flags = {"-s", "-S", "-v", "-i", "-k", "-L", "-I", "--silent",
                  "--show-error", "--verbose", "--head", "--insecure",
                  "--location", "-f", "--fail"}
    head = False
    while i < len(argv):
        a = argv[i]
        if a in val_flags:
            if i + 1 >= len(argv):
                return None
            v = argv[i + 1]
            kind = val_flags[a]
            if kind == "header":
                k, _, hv = v.partition(":")
                headers[k.strip().lower()] = hv.strip()
            elif kind == "method":
                method = v.upper()
            elif kind == "data":
                body = v if body is None else body + "&" + v
            elif kind == "ua":
                headers["user-agent"] = v
            elif kind == "cookie":
                headers["cookie"] = v
            elif kind == "user":
                import base64
                headers["authorization"] = "Basic " + \
                    base64.b64encode(v.encode()).decode()
            elif kind == "url":
                url = v
            i += 2
        elif a in bool_flags:
            head = head or a in ("-I", "--head")
            i += 1
        elif a.startswith("--"):
            i += 1                       # unknown long flag: skip
        elif re.match(r"^-[A-Za-z]{2,}$", a):
            chars = a[1:]
            if all(ch in "sSvikLfI" for ch in chars):
                head = head or "I" in chars      # combined: -sI, -sSL
            i += 1
        elif re.match(r"^-[A-Za-z].+$", a):
            argv[i:i + 1] = [a[:2], a[2:]]       # attached value: -Hfoo, -XPUT
        elif a.startswith("-"):
            i += 1                       # unknown flag: skip
        else:
            if url is None:
                url = a
            i += 1
    if not url or not re.match(r"https?://", url):
        return None
    if method is None:
        method = "HEAD" if head else ("POST" if body is not None else "GET")
    headers.setdefault("user-agent", "repro/" + VERSION)
    headers.setdefault("accept", "*/*")
    return {"method": method, "url": url, "headers": headers,
            "body": body.encode() if body is not None else None,
            "command": cmd}


def parse_http_file(text: str):
    """Raw .http files: METHOD /path HTTP/1.1, headers, blank, body."""
    for block in re.split(r"\n\s*#{3,}.*|\n\s*={3,}.*", text):
        block = block.strip()
        if not block:
            continue
        head, _, rest = block.partition("\n\n")
        lines = head.splitlines()
        first = lines[0].strip()
        m = re.match(r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)"
                     r"(?:\s+HTTP/[\d.]+)?$", first, re.I)
        if not m:
            continue
        method, target = m.group(1).upper(), m.group(2)
        headers = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            if v:
                headers[k.strip().lower()] = v.strip()
        host = headers.pop("host", None)
        if target.startswith("http"):
            url = target
        elif host:
            scheme = headers.pop("x-scheme", "https")
            url = f"{scheme}://{host}{target}"
        else:
            continue
        body = rest.encode() if rest.strip() else None
        if method == "UNKNOWN":
            method = "POST" if body else "GET"
        yield {"method": method, "url": url, "headers": headers,
              "body": body, "command": first}


def extract_requests(path: Path):
    text = path.read_text(errors="replace")
    if path.suffix.lower() in (".http", ".rest"):
        return list(parse_http_file(text))
    reqs = []
    for cmd in extract_curl(text):
        r = parse_curl(cmd)
        if r:
            reqs.append(r)
    return reqs


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------

def send(req, timeout, insecure):
    from urllib.parse import urlsplit
    u = urlsplit(req["url"])
    tls = u.scheme == "https"
    host = u.hostname
    port = u.port or (443 if tls else 80)
    ctx = ssl._create_unverified_context() if insecure else \
        ssl.create_default_context()
    conn = (HTTPSConnection(host, port, timeout=timeout, context=ctx)
            if tls else HTTPConnection(host, port, timeout=timeout))
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    headers = dict(req["headers"])
    if req["body"] is not None:
        headers.setdefault("content-length", str(len(req["body"])))
    conn.request(req["method"], path, body=req["body"], headers=headers)
    resp = conn.getresponse()
    raw = resp.read(512 * 1024)
    conn.close()
    return resp, raw


def snapshot(resp, raw):
    hdrs = {}
    for k, v in resp.getheaders():
        k = k.lower()
        if k in NOISE_HEADERS:
            continue
        hdrs.setdefault(k, []).append(v)
    return {
        "proto": resp.version,
        "status": resp.status,
        "reason": resp.reason,
        "headers": hdrs,
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "body_len": len(raw),
        "body_text": (raw.decode("utf-8", "replace")
                      if len(raw) <= 64 * 1024 else None),
    }


def diff_snapshots(old, new):
    """Human-readable list of differences; empty means identical."""
    out = []
    if old["status"] != new["status"]:
        out.append(f"status: {old['status']} -> {new['status']}")
    keys = sorted(set(old["headers"]) | set(new["headers"]))
    for k in keys:
        ov, nv = old["headers"].get(k), new["headers"].get(k)
        if ov != nv:
            out.append(f"header {k}: {ov!r} -> {nv!r}")
    if old["body_sha256"] != new["body_sha256"]:
        ot, nt = old.get("body_text"), new.get("body_text")
        if ot is not None and nt is not None:
            d = list(difflib.unified_diff(
                ot.splitlines(), nt.splitlines(),
                "found", "now", lineterm="", n=1))
            shown = d[:40]
            out.append("body differs ({} diff lines):".format(len(d)))
            out.extend("  " + l for l in shown)
            if len(d) > len(shown):
                out.append(f"  … {len(d) - len(shown)} more diff lines")
        else:
            out.append(f"body differs: {old['body_len']} -> "
                       f"{new['body_len']} bytes")
    return out


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------

def req_id(req):
    return hashlib.sha256(
        f"{req['method']} {req['url']} {sorted(req['headers'])}".encode()
    ).hexdigest()[:16]


def load_state(path: Path):
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"tool": "repro", "version": VERSION, "requests": {}}


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(
        prog="repro",
        description="Replay the curl PoCs in your finding files and diff "
                    "the responses against the snapshot from when you "
                    "found them. Stdlib-only.")
    ap.add_argument("paths", nargs="+", metavar="POC",
                    help="markdown/sh files with curl blocks, or .http files")
    ap.add_argument("--state", metavar="PATH",
                    help="snapshot file (default: <poc>.repro.json)")
    ap.add_argument("--allow-write", action="store_true",
                    help="also replay POST/PUT/PATCH/DELETE (off by default)")
    ap.add_argument("--delay", type=float, default=1.0,
                    help="seconds between requests (default: 1.0)")
    ap.add_argument("--retries", type=int, default=2,
                    help="retries on connection errors (default: 2)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification")
    ap.add_argument("--header", action="append", default=[], metavar="N:V",
                    help="add/override a header on every request")
    ap.add_argument("--list", action="store_true",
                    help="show extracted requests without sending anything")
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--version", action="version", version=f"repro {VERSION}")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    results = {"same": 0, "changed": 0, "new": 0, "error": 0, "skipped": 0}
    json_out = []

    def emit(*a):
        if not args.as_json:
            print(*a)

    for p in map(Path, args.paths):
        if not p.is_file():
            print(f"repro: no such file: {p}", file=sys.stderr)
            return 2
        reqs = extract_requests(p)
        state_path = Path(args.state) if args.state and len(args.paths) == 1 \
            else Path(str(p) + ".repro.json")
        state = load_state(state_path)

        emit(f"{p}  ·  {len(reqs)} request(s) extracted")
        extra = {}
        for h in args.header:
            k, _, v = h.partition(":")
            extra[k.strip().lower()] = v.strip()

        for req in reqs:
            req["headers"].update(extra)
            rid = req_id(req)
            line = f"  {req['method']:<6} {req['url']}"

            if args.list:
                emit(line)
                continue
            if req["method"] in WRITE_METHODS and not args.allow_write:
                emit(line + "  " + c("33", "SKIPPED") +
                     " (write method; --allow-write to replay)")
                results["skipped"] += 1
                continue

            resp_snap = None
            err = None
            for attempt in range(args.retries + 1):
                try:
                    resp, raw = send(req, args.timeout, args.insecure)
                    resp_snap = snapshot(resp, raw)
                    break
                except Exception as e:
                    err = e
                    if attempt < args.retries:
                        time.sleep(2 * (attempt + 1))

            if resp_snap is None:
                emit(line + "  " + c("33", "INCONCLUSIVE") +
                     f" (network error: {err})")
                results["error"] += 1
                json_out.append({"file": str(p), "request": line.strip(),
                                 "verdict": "inconclusive", "error": str(err)})
                continue

            prev = state["requests"].get(rid)
            if prev is None:
                state["requests"][rid] = {
                    "method": req["method"], "url": req["url"],
                    "command": req["command"], "snapshot": resp_snap,
                    "first_seen": time.strftime("%Y-%m-%dT%H:%M:%S"),
                }
                emit(line + "  " + c("36", "BASELINE") +
                     f"  {resp_snap['status']} · saved for next time")
                results["new"] += 1
                verdict, diffs = "baseline", []
            else:
                diffs = diff_snapshots(prev["snapshot"], resp_snap)
                if not diffs:
                    emit(line + "  " + c("32", "STILL REPRODUCES") +
                         f"  {resp_snap['status']} · identical response")
                    results["same"] += 1
                    verdict = "same"
                else:
                    emit(line + "  " + c("31", "CHANGED"))
                    for d in diffs:
                        emit(c("90", f"      {d}"))
                    results["changed"] += 1
                    verdict = "changed"
            json_out.append({"file": str(p), "request": line.strip(),
                             "status": resp_snap["status"],
                             "verdict": verdict, "diff": diffs})
            time.sleep(args.delay)

        if not args.list:
            state_path.write_text(json.dumps(state, indent=1))

    if args.list:
        return 0
    if args.as_json:
        print(json.dumps({"tool": "repro", "version": VERSION,
                          "summary": results, "results": json_out}, indent=2))
    else:
        print()
        print(f"{results['same']} still-reproduces · {results['changed']} "
              f"changed · {results['new']} baseline · {results['error']} "
              f"inconclusive · {results['skipped']} skipped")
        print("authorized testing only: repro replays exactly what your PoC "
              "file contains, nothing else.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
