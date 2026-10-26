# Automated Web Security Scanner (Headers, TLS, Cookies, CORS & Exposed Files)

**IBM SkillsBuild Cyber Security Bootcamp 2026 | BharatCares**
**Author:** Hafsa Fatima  |  **Version:** 2.0

A Python command-line tool that audits a website for common security misconfigurations. It runs nine groups of checks, rates every finding by severity (with a CWE reference and a recommended fix), calculates a security score and grade, and exports results as JSON, CSV or a styled HTML report. It also has a built-in **demo mode** that compares a deliberately vulnerable server against a hardened one, so the project can be tested safely without internet access.

## Project Description

Many successful web attacks (XSS, clickjacking, session theft, cross-origin data theft, credential leaks) are caused by simple configuration mistakes, not complex exploits. This tool automates the checks a security tester would do by hand and explains how to fix each issue.

| # | Check group | What is tested |
|---|-------------|----------------|
| 1 | Transport | Plain HTTP use, missing HTTP to HTTPS redirect |
| 2 | TLS | Certificate validity (self-signed, wrong host, expired, expiring soon), TLS version, issuer |
| 3 | Security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, plus weak values (short HSTS, `unsafe-inline`, wildcard CSP) |
| 4 | Information disclosure | `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, meta generator tag |
| 5 | Cookies | `Secure`, `HttpOnly`, `SameSite`, `SameSite=None` without `Secure` |
| 6 | HTTP methods | Risky methods advertised by `OPTIONS` (TRACE, PUT, DELETE, CONNECT) |
| 7 | CORS | Wildcard, reflected origin, `null` origin, credentials, weak prefix/suffix validation, unsafe preflight responses |
| 8 | Page content | External scripts without Subresource Integrity, mixed content, login forms posting over HTTP |
| 9 | Exposed files | `/.git/HEAD`, `/.env`, `phpinfo.php`, `server-status`, SQL/ZIP backups, `robots.txt` hints, `security.txt` |

**Scoring:** starts at 100; High -20, Medium -10, Low -4, Info 0. Grades: A 90-100, B 75-89, C 60-74, D 40-59, F below 40.

## Features

- 9 check groups with CWE references and fix recommendations
- Safe built-in demo: vulnerable server vs hardened server comparison
- Multi-target scanning from a file, run in parallel threads
- Reports: colour console, JSON, CSV and HTML
- `--min-severity` filter and `--fail-on` exit code for CI/CD security gates
- Low-false-positive file checks (a file counts only if its content matches, e.g. `ref:` in `.git/HEAD`)
- Self-signed or invalid certificates are reported, and the scan still continues
- Read-only: only GET and OPTIONS requests, no exploitation, no fuzzing

## Dataset

**No dataset is used.** The tool analyses live HTTP responses. Targets can be listed in a text file (`targets.txt`, one URL per line, `#` for comments). The `--demo` mode needs no internet.

## Technologies Used

- Python 3.9+
- `requests` (HTTP client; brings `urllib3`)
- `colorama` (coloured terminal output)
- Standard library: `argparse`, `ssl`, `socket`, `html.parser`, `concurrent.futures`, `http.server`, `json`, `csv`

## Setup

```bash
git clone <YOUR-GITHUB-REPO-LINK>
cd <repo-folder>

# optional virtual environment
python -m venv venv
venv\Scripts\activate            # Windows
source venv/bin/activate         # Linux / macOS

pip install -r requirements.txt
```

## How to Run

```bash
# 1. Safe offline demo (vulnerable vs hardened local server)
python HafsaFatima_WebScanner.py --demo

# 2. Scan one site
python HafsaFatima_WebScanner.py https://example.com

# 3. Several sites, in parallel, with all report formats
python HafsaFatima_WebScanner.py --file targets.txt --threads 4 --json report.json --csv report.csv --html report.html

# 4. Show only serious findings
python HafsaFatima_WebScanner.py https://example.com --min-severity medium

# 5. CI/CD gate: exit code 2 if any High finding exists
python HafsaFatima_WebScanner.py https://staging.example.com --fail-on high
```

### Command-line options

| Option | Description |
|--------|-------------|
| `url` | Target URL (scheme optional, defaults to https) |
| `--file FILE` | File with one URL per line |
| `--json / --csv / --html PATH` | Save a report |
| `--timeout N` | Request timeout in seconds (default 10) |
| `--threads N` | Parallel scans for multiple targets (default 3) |
| `--no-paths` | Skip exposed-file probing |
| `--min-severity` | `info`, `low`, `medium` or `high` (console filter) |
| `--fail-on` | `low`, `medium` or `high`; exit code 2 if reached, 3 if a target could not be scanned |
| `--demo` | Scan the built-in vulnerable and hardened servers |

### Sample results (demo mode)

| Target | High | Medium | Low | Score | Grade |
|--------|-----:|-------:|----:|------:|:-----:|
| Vulnerable demo server | 7 | 6 | 10 | 0 | F |
| Hardened demo server | 0 | 0 | 0 | 100 | A |

### Use in GitHub Actions (optional)

```yaml
- name: Web security scan
  run: |
    pip install -r requirements.txt
    python HafsaFatima_WebScanner.py https://staging.example.com --fail-on high --html report.html
```

## Key Information

- **Legal and ethical use:** scan only sites you own or have written permission to test. Safe practice targets: `http://testphp.vulnweb.com` and your own localhost apps.
- The scanner sends ordinary `GET` and `OPTIONS` requests (with a custom `Origin` header for CORS tests). It does not exploit, brute-force or fuzz.
- **Limitations:** checks only the URL given (no crawling), no full cipher-suite analysis, cannot find application bugs such as SQL injection. Behind a corporate or inspection proxy, TLS results describe the proxy's certificate.
- **Future work:** crawling, cipher-suite checks, trend comparison between scans, PDF report.

## Files

| File | Purpose |
|------|---------|
| `HafsaFatima_WebScanner.py` | Main scanner code |
| `requirements.txt` | Python dependencies |
| `HafsaFatima_ProjectReport.docx` | Full project report |
| `README.md` | This file |
