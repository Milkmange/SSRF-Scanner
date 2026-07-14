# 🔥 SSRF-Scanner 🔥
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# SSRF-Scanner

A comprehensive, high-performance SSRF (Server-Side Request Forgery) vulnerability scanner that tests web applications for potential SSRF issues through multiple attack vectors.

## 🎯 Features

- **12 Attack Phases** - Comprehensive testing methodology
- **Tens of thousands of requests** - Extensive payload coverage per target
- **432 flat payloads + 420 templated blind/CVE probes** - Across 11 payload files plus a bundled blind-SSRF template library
- **Out-of-band (OOB) confirmation** - Self-hosted callback listener that *confirms* blind SSRF via unique per-payload tokens
- **Smart Baseline Detection** - Reduces false positives with anchored, high-signal indicators
- **Payload deduplication** - Removes redundant encoded variants before sending
- **Concurrent Scanning** - Up to 200 concurrent requests
- **Rate Limiting** - Configurable requests per second (enforced + adaptive backoff)
- **Multiple Output Formats** - JSON, CSV, HTML (escaped output), TXT
- **Real-time Progress** - Live request statistics and success rates
- **Async/Await** - High-performance asynchronous implementation
- **Modular package** - Organized under the `ssrfscanner/` package; `ssrf_scanner.py` is a thin CLI entrypoint

## Installation

### Clone the repository

```
git clone https://github.com/Dancas93/SSRF-Scanner.git
cd SSRF-Scanner
```

### Create virtual environment

```
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
.\venv\Scripts\activate

# Install requirements
pip3 install -r requirements.txt
```

## 🚀 Quick Start

### Basic Usage

```bash
# Scan a single URL
python3 ssrf_scanner.py -u https://example.com

# Scan multiple URLs from file
python3 ssrf_scanner.py -f urls.txt

# Scan with callback URL for remote SSRF detection
python3 ssrf_scanner.py -u https://example.com -b your-callback.burpcollaborator.net

# High-speed scan with custom settings
python3 ssrf_scanner.py -u https://example.com --concurrency 300 --rate-limit 150

# Quiet mode (only show vulnerabilities)
python3 ssrf_scanner.py -u https://example.com -q

# Multiple output formats
python3 ssrf_scanner.py -u https://example.com --output-format html,json,csv

# Confirm blind SSRF out-of-band with a self-hosted listener
python3 ssrf_scanner.py -u https://example.com \
    --oob-mode selfhosted --oob-listen 0.0.0.0:8000 --oob-domain oob.example.com
```

### Command Line Options

```
-h, --help              Show help message
-u, --url              Single URL to scan
-f, --file             File containing URLs to scan
-b, --backurl          Callback host for remote SSRF detection (manual/Burp Collaborator)
-d, --debug            Enable debug mode
-c, --cookie           Set cookies (format: 'name1=value1; name2=value2')
-H, --header           Custom header to add to every request (format: 'Name: value')
--concurrency N        Number of concurrent requests (default: 200)
--rate-limit N         Max requests per second (default: 100)
--limit-per-host N     Max simultaneous connections per host (default: 0 = auto,
                       aligned with --concurrency; set lower to be gentle on one target)
-q, --quiet            Only show vulnerabilities (no progress)
--proxy URL            Proxy URL (e.g., http://127.0.0.1:8080)
--proxy-auth U:P       Proxy authentication (username:password)
--output-format FMT    Output format: json, csv, html, txt, all (default: csv)

Out-of-band (OOB) confirmation of blind SSRF:
--oob-mode MODE        off | selfhosted (default: off)
--oob-listen H:P       Interface:port to bind the listener (default: 0.0.0.0:8000)
--oob-domain DOMAIN    Public authority with wildcard DNS pointing at the listener
                       (e.g. oob.example.com; *.oob.example.com -> your IP)
--oob-wait N           Seconds to wait for late callbacks after the scan (default: 8)
```

## 🎯 Attack Phases

The scanner performs **12 comprehensive attack phases** (tens of thousands of requests per target; more when `--backurl`/OOB is enabled):

### 1. Local IP Attack (20% - ~5,600 requests)
Tests for internal network access using various IP formats:
- **35 base payloads** × 27 headers × variations
- Standard localhost (`127.0.0.1`, `localhost`, `::1`)
- IP encoding (decimal: `2130706433`, hex: `0x7f000001`, octal: `0177.0.0.1`)
- IPv6 variations (`[::1]`, `[0:0:0:0:0:ffff:127.0.0.1]`)
- Unicode variations (`127。0。0。1`)
- URL encoded formats

### 2. Cloud Metadata Attack (12% - ~3,400 requests)
Attempts to access cloud service metadata endpoints:
- **39 payloads** targeting AWS, GCP, Azure, DigitalOcean, Alibaba Cloud
- AWS: `169.254.169.254/latest/meta-data/`
- GCP: `metadata.google.internal/computeMetadata/v1/`
- Azure: `169.254.169.254/metadata/instance`
- IMDSv1 and IMDSv2 variations
- Encoded and obfuscated endpoints

### 3. Protocol Attack (12% - ~3,400 requests)
Tests various protocol handlers:
- **21 protocols** from `protocols.txt`
- Standard: `http://`, `https://`, `ftp://`, `file://`
- Advanced: `gopher://`, `dict://`, `ldap://`, `jar://`
- Database: `mysql://`, `mongodb://`, `postgres://`, `redis://`
- Network: `ws://`, `wss://`, `smtp://`
- Protocol-specific handlers (Gopher commands, Dict queries, File paths)

### 4. Encoded Payload Attack (8% - ~2,300 requests)
Uses encoding techniques to bypass filters:
- **10 base payloads** with multiple encoding variations
- Single/double URL encoding
- Base64 encoding
- Unicode encoding (`。`, `／`)
- Mixed encoding combinations
- Hex encoding

### 5. Parameter Attack (8% - ~2,300 requests)
Tests SSRF through URL parameters:
- **66 parameter payloads**
- Common: `url=`, `path=`, `redirect=`, `uri=`, `file=`
- File inclusion: `document=`, `page=`, `load=`
- API: `callback=`, `webhook=`, `api_url=`
- Redirect: `redirect_to=`, `return_url=`, `next=`

### 6. Port Scan Attack (8% - ~2,300 requests)
Detects internal services via port scanning:
- **33 port payloads**
- Web: `:80`, `:443`, `:8080`, `:8443`
- Database: `:3306`, `:5432`, `:6379`, `:27017`
- Admin: `:8000`, `:8008`, `:9000`
- Services: `:22`, `:21`, `:25`, `:9200`

### 7. DNS Rebinding Attack (8% - ~2,300 requests)
Tests DNS rebinding vulnerabilities:
- **13 payloads** including Burp Collaborator integration
- `127.0.0.1.nip.io`, `127.0.0.1.xip.io`
- `localhost.localtest.me`
- Custom callback domains (with `-b` flag)
- Time-based DNS variations

### 8. CRLF Injection Attack (10% - ~2,800 requests) 🆕
Manipulates HTTP requests via newline injection:
- **43 CRLF payloads**
- Header injection: `%0d%0aHost:%20evil.com`
- Request smuggling: `%0d%0aTransfer-Encoding:%20chunked`
- Response splitting: `%0d%0aHTTP/1.1%20200%20OK`
- Cache poisoning: `%0d%0aX-Forwarded-Scheme:%20http`
- Session fixation: `%0d%0aSet-Cookie:%20admin=true`
- CORS bypass: `%0d%0aAccess-Control-Allow-Origin:%20*`

### 9. Scheme Confusion Attack (10% - ~2,800 requests) 🆕
Tests alternative/rare protocols to bypass filters:
- **90+ scheme payloads**
- Java-specific: `jar:`, `netdoc:`
- PHP wrappers: `php://filter`, `expect://`, `phar://`
- Data URIs: `data://text/plain;base64,`
- File transfer: `tftp://`, `nfs://`, `rsync://`, `smb://`
- Directory: `ldap://`, `ldapi://`
- Version control: `git://`, `svn://`
- Streaming: `rtsp://`, `rtmp://`
- Remote access: `ssh://`, `telnet://`, `rdp://`, `vnc://`
- Compression: `compress.zlib://`, `compress.bzip2://`

### 10. WAF Bypass Attack 🆕
Filter/WAF evasion primitives from `waf_bypass.txt` (now loaded and active):
- Encoded schemes, case variation, protocol confusion, null bytes, traversal
- Prefix-style entries (e.g. `http://`, `http:\\`) are combined with local IPs
- Injected as header values

### 11. Blind SSRF / CVE Probe Attack 🆕
Uses the bundled `blind-ssrf-payloads.json` template library (420 templated
payloads, sourced from the MIT-licensed
[errorfiathck/ssrf-exploit](https://github.com/errorfiathck/ssrf-exploit)):
- **Direct CVE probes** (Weblogic, Apache Solr, Confluence, Jenkins, OpenTSDB, Docker…) requested straight at the target
- **`gopher://` exploitation** strings (Redis, Memcache)
- **HTTP request-smuggling templates** (shellshock, Consul, PeopleSoft) injected via a `url=` parameter
- Canary-dependent payloads are gated on a configured callback (`--backurl` or OOB); without one, only the ~16 self-contained probes run
- Best confirmed with OOB (see below)

### 12. Remote Attack
External callback validation (runs when `-b`/`--backurl` **or** OOB is configured):
- **10 callback URL variations** (plain, HTTP/HTTPS, with paths/ports, URL-encoded)
- With OOB enabled, each header gets a **unique callback token** so a hit pinpoints the vulnerable header
- Tests external communication and DNS resolution


## 📡 Out-of-Band (OOB) Confirmation

Blind SSRF cannot be confirmed from the HTTP response alone - the only reliable
signal is the target server actually calling back to infrastructure you control.
The scanner can run a **self-hosted callback listener** to provide that signal.

### How it works
1. For each callback-style payload the scanner mints a **unique correlation
   token** and builds a callback authority `‹token›.‹oob-domain›`.
2. That authority is embedded in the callback/blind payloads.
3. The built-in HTTP listener records every inbound hit (token, source IP, time).
4. After the scan, hits are matched to the tokens that were sent. **A hit =
   confirmed SSRF**, attributed to the exact payload/header/parameter that
   carried the token. Confirmed findings appear with attack type `OOB:…` and
   verification method `OOB Interaction`.

### Requirements
- The **target must be able to reach your listener.** Use a public host or a
  tunnel (ngrok/cloudflared).
- Correlation uses the leftmost DNS label (subdomain), so point **wildcard DNS**
  `*.oob-domain` at the listener's IP (this is how Burp Collaborator / interactsh
  work). Path-based hits (`/‹token›`) are also correlated as a fallback.
- Only HTTP callbacks are captured. DNS-only exfiltration is not (that needs an
  authoritative DNS listener / interactsh).

### Example
```bash
# On a host reachable from the target, with *.oob.example.com -> this host:
python3 ssrf_scanner.py -u https://target.example \
    --oob-mode selfhosted \
    --oob-listen 0.0.0.0:8000 \
    --oob-domain oob.example.com \
    --oob-wait 10
```

> ⚠️ **Security note:** `--oob-mode selfhosted` opens an **unauthenticated**
> inbound HTTP listener so a remote target can reach it. It only *logs* requests
> and always returns a benign response - it never executes anything - but you
> should bind it deliberately and expose it only for the duration of a scan.

Without `--oob-mode`, the existing manual workflow is unchanged: pass a Burp
Collaborator host with `-b` and watch Collaborator yourself.

## 🔍 Verification Methods

The scanner uses **smart baseline comparison** to reduce false positives:

### 1. Response Code Analysis
- Compares against baseline status codes
- Only flags if status code **differs** from baseline
- Excludes rate limiting (429) from vulnerabilities
- Detects unexpected status changes

### 2. Response Content Analysis
- Searches for **anchored, high-signal** SSRF indicators (chosen to avoid the
  false positives caused by generic words like `token`/`secret`/`key`):
  - `root:x:0:0:` / `root:*:0:0:` (`/etc/passwd`)
  - `security-credentials`, `"AccessKeyId"`, `"SecretAccessKey"`, `ami-id`, `instance-identity` (AWS metadata)
  - `computeMetadata`, `Metadata-Flavor` (GCP metadata)
  - `-----BEGIN … PRIVATE KEY-----`, `ssh-rsa ` (keys)
- Excludes rate limiting responses

### 3. Response Headers Analysis
- Detects suspicious headers:
  - `x-internal`, `server-internal`
  - `x-backend-server`, `x-upstream`
  - `x-forwarded-server`
- Internal service indicators

### 4. Timing Analysis
- Per-request response time is measured and available to detection
- Flags responses slower than a threshold (useful for blind/port probing)

### 5. Out-of-Band Interaction (highest confidence)
- When OOB is enabled, a recorded callback confirms the SSRF outright,
  independent of the response (see the OOB section above)

### Smart Baseline Detection
- Creates baseline with 3 initial requests
- Tracks status codes, response sizes, content hashes
- Determines response stability
- Only flags **significant deviations** from baseline
- Prevents false positives when status matches baseline

## 📊 Output and Reporting

### Output Formats
The scanner generates multiple report formats:

1. **JSON Report** (`output/report.json`)
   - Machine-readable format
   - Complete vulnerability details
   - Easy integration with other tools

2. **CSV Report** (`output/report.csv`)
   - Spreadsheet-compatible
   - Sortable and filterable
   - Good for data analysis

3. **HTML Report** (`output/report.html`)
   - Visual, interactive report
   - Statistics and charts
   - Color-coded severity
   - Professional presentation

4. **Text Report** (`output/report.txt`)
   - Human-readable format
   - Quick review
   - Terminal-friendly

### Report Contents
Each vulnerability finding includes:
- **Target URL** - The tested endpoint
- **Attack Type** - Phase that detected the issue (e.g., CRLF_Injection, Scheme_Confusion)
- **Payload** - Exact payload that triggered the vulnerability
- **Response Code** - HTTP status code received
- **Response Size** - Size of the response in bytes
- **Verification Method** - How it was verified (e.g., "Response Content Analysis")
- **Timestamp** - When the vulnerability was detected
- **Notes** - Additional details and differences from baseline

### Summary Statistics
- Total URLs scanned
- Total requests made
- Vulnerabilities found
- Success rate (%)
- Unique attack types
- Breakdown by attack phase
- Scan duration

## 📈 Performance

### Speed & Efficiency
- **Concurrent Requests**: Configurable via `--concurrency` (default: 200)
- **Per-host connections**: The connection pool auto-aligns with `--concurrency`,
  so raising concurrency actually increases throughput against a single target
  (previously capped at 50/host). Use `--limit-per-host` to throttle one target.
- **Rate Limiting**: Configurable (default: 100 req/s), enforced on the request path
- **Adaptive Throttling**: Automatically adjusts based on errors
- **Smart Backoff**: Reduces rate on failures, increases on success
- **Async/Await**: High-performance asynchronous implementation (I/O-bound; threads
  would not help - the event loop already overlaps all the network waits)

> ℹ️ **Why not threads?** The scanner is network-I/O-bound, and Python's GIL means
> threads can't parallelize work here. asyncio already overlaps thousands of
> in-flight requests on one thread. The real throughput levers are `--concurrency`,
> `--limit-per-host`, and `--rate-limit` - not threading.

### Typical Scan Times
- **Single URL**: ~3-5 minutes (28,300 requests at 100 req/s)
- **With high concurrency**: ~2-3 minutes (300 concurrent, 150 req/s)
- **Multiple URLs**: Scales linearly

### Resource Usage
- **Memory**: ~100-200 MB
- **CPU**: Moderate (async I/O bound)
- **Network**: Configurable bandwidth usage

## 🛡️ Security Features

### Smart Detection
- ✅ Baseline comparison to reduce false positives
- ✅ Rate limiting exclusion (429 not flagged as vulnerability)
- ✅ Response pattern analysis
- ✅ Content-based verification
- ✅ Timing-based detection

### Safe Scanning
- ✅ Configurable rate limiting
- ✅ Timeout handling
- ✅ Error recovery
- ✅ Graceful degradation
- ✅ Connection pooling

## 📦 Payload Files

All payloads are stored in the `payloads/` directory:

```
payloads/
├── local_ips.txt              (41 payloads)   - Internal IP variations
├── headers.txt                (27 payloads)   - HTTP headers to test
├── cloud_metadata.txt         (49 payloads)   - Cloud metadata endpoints
├── protocols.txt              (21 payloads)   - Protocol handlers
├── encoded_payloads.txt       (10 payloads)   - Encoding variations
├── parameter_payloads.txt     (78 payloads)   - URL parameters + nested targets
├── port_payloads.txt          (42 payloads)   - Port specifications
├── dns_rebinding.txt          (13 payloads)   - DNS rebinding domains
├── crlf_injection.txt         (42 payloads)   - CRLF injection patterns
├── scheme_confusion.txt       (90 payloads)   - Alternative protocols
├── waf_bypass.txt             (19 payloads)   - WAF/filter bypass primitives (active)
├── blind-ssrf-payloads.json   (420 templates) - Blind-SSRF/CVE probe library
└── THIRD_PARTY_NOTICES.md                     - Attribution for bundled payloads
```

**Total: 432 flat payloads + 420 templated blind/CVE probes**

You can customize any payload file to add your own test cases!

## 🎯 Example Output

```
░██████╗░██████╗██████╗░███████╗
██╔════╝██╔════╝██╔══██╗██╔════╝
╚█████╗░╚█████╗░██████╔╝█████╗░░
░╚═══██╗░╚═══██╗██╔══██╗██╔══╝░░
██████╔╝██████╔╝██║░░██║██║░░░░░
╚═════╝░╚═════╝░╚═╝░░╚═╝╚═╝

[*] Configuration:
    Concurrency: 200
    Rate Limit: 100 req/s
    Timeout: 15s
    Output Format: json

[*] Creating baseline for https://example.com...
[*] Baseline: Status={200}, AvgSize=3125, Stable=Yes
[*] Starting attack phases...

URLs: 1/1 | Requests: 5,234/28,300 (98.5% success, 112.3 req/s) | Phase: Local IP | Progress: 20.0%
URLs: 1/1 | Requests: 18,234/28,300 (99.1% success, 118.4 req/s) | Phase: CRLF Injection | Progress: 64.0%
URLs: 1/1 | Requests: 28,300/28,300 (99.5% success, 121.5 req/s) | Phase: Remote | Progress: 100.0%

⏱️  Total Scan Time: 233.12 seconds

==================================================
SSRF Scan Summary
==================================================
Statistics:
--------------------
Total URLs Scanned: 1
Total Requests: 28,300
Vulnerabilities Found: 3
Success Rate: 99.5%
Unique Attack Types: 2

Vulnerabilities by Attack Type:
------------------------------
CRLF_Injection: 2 found
Scheme_Confusion: 1 found
==================================================
Detailed results saved in:
JSON Report: output/report.json
```

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Add new payload files
- Improve detection methods
- Optimize performance
- Fix bugs
- Enhance documentation

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

### Third-party payloads

`payloads/blind-ssrf-payloads.json` is bundled from
[errorfiathck/ssrf-exploit](https://github.com/errorfiathck/ssrf-exploit)
(MIT License, Copyright (c) 2023 Error). Full notice in
`payloads/THIRD_PARTY_NOTICES.md`.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have permission to test target systems. The developers assume no liability for misuse or damage caused by this tool.
