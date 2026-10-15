# repro

[![tests](https://github.com/Kiwi172/repro/actions/workflows/ci.yml/badge.svg)](https://github.com/Kiwi172/repro/actions/workflows/ci.yml)

**Does the finding still reproduce? Run it against your PoC file.**

You filed a bug with a curl snippet in the markdown. Weeks later triage
says "cannot reproduce", or you want to check before commenting "still
open, verified 2026-10-15". Right now that means opening the PoC, finding
the curl block, fixing the quoting, eyeballing whether the response still
has the bad status/header/body. `repro` reads the PoC file itself: it
extracts every `curl` request from your fenced code blocks (or raw
`.http` files), replays them exactly as written, and diffs the responses
against the snapshot you saved when you found the bug.

```
   your PoC file                          the live target
   ┌────────────────────────┐            ┌──────────────┐
   │ # CBX-004 — admin 500  │            │              │
   │ ```bash                │  replay    │   POST       │
   │ curl -s ".../login/" \ │ ─────────▶ │   /api/login │
   │   -X POST -d '...'     │  exactly   │              │
   │ ```                    │  as found  └──────┬───────┘
   └────────────────────────┘                   │
                  │                            ▼
                  ▼                snapshot diff, noise stripped
          STILL REPRODUCES  500 · identical response
          CHANGED  status: 500 -> 400        ← vendor fixed it
          INCONCLUSIVE (network error)       ← never claims "fixed"
```

The diff ignores the headers that prove nothing — `Date`, `Set-Cookie`,
`X-Request-Id`, `CF-RAY`, cache `Expires` — and reports everything else:
status changes, header changes (a CORS header appearing/disappearing is
the whole finding for many bugs), and a unified diff of the body.

---

## Install

Any machine with Python 3.9 or newer. One file, nothing to build:

```bash
curl -sO https://raw.githubusercontent.com/Kiwi172/repro/main/repro.py
chmod +x repro.py
```

Or:

```bash
pipx install git+https://github.com/Kiwi172/repro
```

## Use

First run saves a baseline; every later run answers the question:

```
$ repro poc/CBX-004-admin-login-500.md --allow-write
poc/CBX-004-admin-login-500.md  ·  2 request(s) extracted
  POST  https://admin.bounty.cryptobox.com/api/v1/login/  BASELINE  500 · saved for next time
  POST  https://admin.bounty.cryptobox.com/api/v1/login/  BASELINE  500 · saved for next time

$ repro poc/CBX-004-admin-login-500.md --allow-write     # three weeks later
  POST  https://admin.bounty.cryptobox.com/api/v1/login/  STILL REPRODUCES  500 · identical response
  POST  https://admin.bounty.cryptobox.com/api/v1/login/  CHANGED
      status: 500 -> 400
      body differs (6 diff lines):
      - {"error": {"code": 500, "message": "Erreur interne du serveur"}}
      + {"error": {"code": 400, "message": "email manquant"}}
```

That second block is what a "fixed" reply looks like. The snapshots live
in `<poc>.repro.json` next to your file — plain JSON, diffable, yours.

See what would be sent before sending it:

```bash
repro --list poc/*.md
```

Add auth without editing the PoC (`--header` applies to every request):

```bash
repro finding.md --header "Authorization: Bearer <token>"
```

## Safety: authorized testing only

- `repro` replays **exactly** the requests in your file — no crawling, no
  fuzzing, no extra paths.
- Write methods (`POST/PUT/PATCH/DELETE`) are **skipped unless you pass
  `--allow-write`**, because a PoC that wrote data may write it again.
- One request per second by default (`--delay`), retries with backoff.
- A network error is reported as `INCONCLUSIVE`, never as "fixed". A
  timeout is not evidence.

## What it understands

| input | how |
|---|---|
| `*.md`, `*.sh` | `curl` commands inside fenced code blocks (or bare lines), including backslash continuations, combined short flags (`-sI`), attached values (`-HName:v`), `-X/-d/-I` method inference, `-u`, `-b`, `-A`, `-H` |
| `*.http`, `*.rest` | raw requests: `METHOD /path HTTP/1.1`, headers, blank line, body |

Responses are compared on: status line, all headers except a fixed noise
list, and the body (SHA-256 for equality, unified diff for text bodies up
to 64 kB).

## Flags

| flag | meaning |
|---|---|
| `--list` | show extracted requests, send nothing |
| `--allow-write` | replay POST/PUT/PATCH/DELETE too |
| `--state PATH` | snapshot file location (default `<poc>.repro.json`) |
| `--header N:V` | add/override a header on every request |
| `--delay / --retries / --timeout / --insecure` | politeness and TLS |
| `--json` | machine-readable verdicts |

## Non-goals

- **Not a proxy or a capture tool.** It replays requests you already
  wrote down. For capturing new ones, use your usual client.
- **HTTP/1.1.** It speaks HTTP/1.1 (`http.client`); servers behave the
  same for the findings this targets, but the wire protocol differs from
  a browser's HTTP/2.
- **Not a scanner.** One replay per request in your file. Authorized,
  deliberate, auditable.

## Tests

```bash
python3 -m pytest tests/      # or: python3 tests/test_repro.py
```

The replay tests run against a local stdlib HTTP server whose behaviour
the test controls — baseline, identical-rerun, status change, header
change, network failure — so the verdict logic is proven without touching
the internet.

## License

MIT
