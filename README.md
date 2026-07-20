<h1 align="center">🔥 SSRF-Scanner 🔥</h1>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

<p align="center">
  <b>Find Server-Side Request Forgery before someone else does.</b><br>
  A fast, async SSRF scanner that hammers a target through 14 attack phases and
  <i>confirms</i> blind SSRF out-of-band instead of guessing.
</p>

---

## Why this one?

- ⚡ **Async & fast** — up to 200 concurrent requests, adaptive rate limiting.
- 🎯 **14 attack phases** — from local-IP tricks to Next.js CVEs.
- 📡 **Real confirmation** — a self-hosted callback listener proves blind SSRF with unique per-payload tokens (no more "maybe").
- 🧠 **Low noise** — smart baselining + anchored signatures kill the usual false positives.
- 🧩 **452 flat payloads + 420 templated CVE probes**, all editable text/JSON.
- 📊 **Reports everywhere** — JSON, CSV, HTML, TXT.

## Install

```bash
git clone https://github.com/Dancas93/SSRF-Scanner.git
cd SSRF-Scanner
python3 -m venv venv && source venv/bin/activate   # Windows: .\venv\Scripts\activate
pip3 install -r requirements.txt
```

## Quick start

```bash
# Single URL
python3 ssrf_scanner.py -u https://example.com

# A list of URLs
python3 ssrf_scanner.py -f urls.txt

# Only show hits, run hot
python3 ssrf_scanner.py -u https://example.com -q --concurrency 300 --rate-limit 150

# Confirm blind SSRF out-of-band (see "Out-of-band" below)
python3 ssrf_scanner.py -u https://example.com \
    --oob-mode selfhosted --oob-listen 0.0.0.0:8000 --oob-domain oob.example.com
```

## Options

```
-u, --url URL           Single URL to scan
-f, --file FILE         File of URLs (one per line)
-b, --backurl HOST      Callback host for manual/Burp Collaborator detection
-c, --cookie STR        Cookies ('name1=value1; name2=value2')
-H, --header 'K: V'     Add a header to every request (repeatable)
-q, --quiet             Only show vulnerabilities
-d, --debug             Verbose debug output
--concurrency N         Concurrent requests (default: 200)
--rate-limit N          Max requests/sec (default: 100)
--limit-per-host N      Max connections per host (0 = auto, matches concurrency)
--url-concurrency N     How many URLs from -f to scan at once (default: 5)
--proxy URL             Proxy (e.g. http://127.0.0.1:8080)
--proxy-auth U:P        Proxy credentials
--output-format FMT     json | csv | html | txt | all (default: csv)

Out-of-band confirmation:
--oob-mode MODE         off | selfhosted (default: off)
--oob-listen H:P        Listener bind address (default: 0.0.0.0:8000)
--oob-domain DOMAIN     Public authority with wildcard DNS -> listener
--oob-wait N            Seconds to wait for late callbacks (default: 8)
```

## Attack phases

| # | Phase | What it does |
|---|-------|--------------|
| 1 | **Local IP** | Internal IPs in every format: decimal, hex, octal, IPv6, shorthand, unicode-dot, encoded |
| 2 | **Cloud Metadata** | AWS / GCP / Azure / DigitalOcean / Alibaba metadata endpoints (IMDSv1 & v2) |
| 3 | **Protocol** | `gopher://`, `dict://`, `file://`, `ftp://`, `ldap://` and friends |
| 4 | **Encoded** | Single/double URL, base64, hex and unicode encodings |
| 5 | **Parameter** | SSRF via `url=`, `redirect=`, `webhook=`, … and existing query params |
| 6 | **Port Scan** | Internal service discovery across common ports |
| 7 | **DNS Rebinding** | `nip.io`, `localtest.me`, custom callback domains |
| 8 | **CRLF Injection** | Header injection, request smuggling, response splitting |
| 9 | **Scheme Confusion** | Parser-confusion bypasses (`+&@`, `#@`, `\@`) + rare schemes |
| 10 | **WAF Bypass** | Filter-evasion primitives (encoding, case, null bytes, traversal) |
| 11 | **Blind SSRF / CVE** | 420 templated probes (Weblogic, Solr, Confluence, Jenkins, Redis gopher…) |
| 12 | **Next.js** 🆕 | Framework-specific SSRF — see below |
| 13 | **Redirect** | 30x-to-internal bypass of first-URL-only filters *(OOB only)* |
| 14 | **Remote** | External callback validation, one unique token per header |

Payloads live in `payloads/` as plain text/JSON — edit or extend any of them.

### Next.js phase 🆕

Modern Next.js apps have their own SSRF sinks that the generic phases can't reach, so they get a dedicated phase:

- **CVE-2026-44578 — WebSocket-upgrade SSRF** *(CVSS 8.6, self-hosted `next` ≥13.4.13)*. A malformed absolute-form upgrade request (`GET http:///path` + `Upgrade: websocket`) makes the server proxy to `localhost`/arbitrary hosts. This needs raw request-line control, so it's sent over a raw socket and paired with an origin-form **control probe** to stay false-positive-safe. With OOB on, a variant points the authority at your canary for a clean confirmation.
- **`next/image` blind SSRF** — `/_next/image?url=<internal>` fetches attacker-supplied URLs server-side. Confirmed by a content signature in-band or an OOB callback.
- **CVE-2024-34351 — Server Actions Host-header SSRF** — a `Next-Action` POST with the `Host` set to your canary makes a vulnerable action call back to you (blind; needs `-b`/OOB).

## Out-of-band confirmation 📡

Blind SSRF can't be proven from the HTTP response — the only real signal is the target calling *you*. Point wildcard DNS (`*.oob.example.com`) at a host the target can reach, then:

```bash
python3 ssrf_scanner.py -u https://target.example \
    --oob-mode selfhosted --oob-listen 0.0.0.0:8000 --oob-domain oob.example.com --oob-wait 10
```

Every callback-style payload gets a unique token `‹token›.oob.example.com`. An inbound hit = **confirmed SSRF**, attributed to the exact payload/header/parameter that carried it (attack type `OOB:…`, method `OOB Interaction`).

> ⚠️ `--oob-mode selfhosted` opens an **unauthenticated** inbound HTTP listener so the target can reach it. It only logs requests and always returns a benign response, but bind it deliberately and expose it only for the scan. Without OOB, use `-b` with a Burp Collaborator host and watch Collaborator yourself.

## How detection works

The scanner combines several signals and leans conservative to avoid false positives:

1. **Content signatures** (highest in-band confidence) — anchored markers like `root:x:0:0:`, `"AccessKeyId"`, `security-credentials`, `computeMetadata`, private keys. Generic words (`secret`, `token`) are deliberately *not* used.
2. **Baseline comparison** — 3 warm-up requests fingerprint status/size/stability; only meaningful deviations are flagged.
3. **Status analysis** — 4xx (incl. 429) is never a finding on its own; a signature is required.
4. **Suspicious headers** — `x-internal`, `x-backend-server`, `x-upstream`, …
5. **Out-of-band interaction** — a recorded callback confirms SSRF outright.

## Output

Reports land in `output/<timestamp>/` as `report.json`, `report.csv`, `report.html` (escaped), and `report.txt`, plus a `summary.txt`. Each finding records the URL, attack type, exact payload, response code/size, verification method, timestamp, and baseline diff.

## Contributing

PRs welcome — new payloads, better detection, performance, docs.

## License

MIT — see [LICENSE](LICENSE).

## ⚠️ Disclaimer

For **authorized** security testing and education only. You are responsible for having permission to test any target. The authors assume no liability for misuse or damage.
