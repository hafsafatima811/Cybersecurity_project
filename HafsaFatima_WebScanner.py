#!/usr/bin/env python3
"""
Automated Web Security Header & CORS Scanner  (v2.0)
====================================================
IBM SkillsBuild Cyber Security Bootcamp 2026 (BharatCares) - Final Project

What it audits
--------------
  1. Transport     : plain HTTP, missing HTTP -> HTTPS redirect
  2. TLS           : certificate validity / expiry, TLS version, issuer
  3. Security headers : HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
                        Referrer-Policy, Permissions-Policy, COOP (+ weak values)
  4. Info disclosure  : Server, X-Powered-By, X-AspNet-Version, X-Generator
  5. Cookies       : Secure, HttpOnly, SameSite (+ SameSite=None without Secure)
  6. HTTP methods  : dangerous methods advertised by OPTIONS (TRACE, PUT, DELETE)
  7. CORS          : wildcard, reflected origin, null origin, weak validation,
                     credentials, unsafe preflight responses
  8. Page content  : external scripts without SRI, mixed content,
                     insecure login forms, generator meta tag
  9. Exposed files : .git, .env, phpinfo, server-status, SQL backups,
                     robots.txt hints, security.txt

Output: coloured console report, security score/grade, JSON / CSV / HTML export.

ETHICS: scan only targets you OWN or have WRITTEN PERMISSION to test.
Safe practice targets: http://testphp.vulnweb.com , http://localhost

Examples
--------
    python HafsaFatima_WebScanner.py --demo
    python HafsaFatima_WebScanner.py https://example.com
    python HafsaFatima_WebScanner.py --file targets.txt --threads 4 --html report.html
    python HafsaFatima_WebScanner.py https://example.com --json r.json --csv r.csv
    python HafsaFatima_WebScanner.py https://example.com --fail-on high   # for CI/CD
"""

import argparse
import csv
import html
import json
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from html.parser import HTMLParser
from http.cookiejar import DefaultCookiePolicy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

VERSION = "2.0"
DEFAULT_TIMEOUT = 10
USER_AGENT = f"EducationalSecurityScanner/{VERSION} (IBM-SkillsBuild-Project)"
EVIL_ORIGIN = "https://evil-attacker.example"

SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_COLOR = {"HIGH": Fore.RED, "MEDIUM": Fore.YELLOW,
                  "LOW": Fore.CYAN, "INFO": Fore.WHITE}
PENALTY = {"HIGH": 20, "MEDIUM": 10, "LOW": 4, "INFO": 0}

# header -> (severity, why it matters, recommended value, CWE)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "HIGH", "Forces browsers to use HTTPS; prevents SSL-stripping attacks.",
        "max-age=31536000; includeSubDomains", "CWE-319"),
    "Content-Security-Policy": (
        "HIGH", "Restricts script sources; main defence against XSS.",
        "default-src 'self'", "CWE-693"),
    "X-Frame-Options": (
        "MEDIUM", "Prevents clickjacking by blocking framing of the page.",
        "DENY", "CWE-1021"),
    "X-Content-Type-Options": (
        "MEDIUM", "Stops MIME-type sniffing.", "nosniff", "CWE-693"),
    "Referrer-Policy": (
        "LOW", "Controls how much URL data leaks to other sites.",
        "strict-origin-when-cross-origin", "CWE-200"),
    "Permissions-Policy": (
        "LOW", "Limits access to camera, microphone, geolocation, etc.",
        "geolocation=(), camera=(), microphone=()", "CWE-693"),
    "Cross-Origin-Opener-Policy": (
        "LOW", "Isolates the browsing context from cross-origin windows.",
        "same-origin", "CWE-693"),
}
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
RISKY_METHODS = {"TRACE": "MEDIUM", "PUT": "LOW", "DELETE": "LOW", "CONNECT": "LOW"}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def normalise_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def is_loopback(host):
    return bool(host) and (host in ("localhost", "::1") or host.startswith("127."))


def make_finding(category, severity, title, detail, fix="", cwe=""):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "recommendation": fix, "cwe": cwe}


class PageParser(HTMLParser):
    """Collects the few HTML facts the scanner needs (scripts, forms, ...)."""

    def __init__(self):
        super().__init__()
        self.scripts, self.styles, self.media, self.forms = [], [], [], []
        self.generator = None
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append(a)
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower() and a.get("href"):
            self.styles.append(a)
        elif tag in ("img", "iframe") and a.get("src"):
            self.media.append(a["src"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "password": False}
            self.forms.append(self._form)
        elif tag == "input" and a.get("type", "").lower() == "password" and self._form is not None:
            self._form["password"] = True
        elif tag == "meta" and a.get("name", "").lower() == "generator":
            self.generator = a.get("content", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def short_error(exc):
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS/SSL error while connecting"
    if isinstance(exc, requests.exceptions.ConnectTimeout) or isinstance(exc, requests.exceptions.ReadTimeout):
        return f"Request timed out"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "Connection failed (host unreachable, refused or DNS error)"
    return str(exc)[:150]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
class WebScanner:
    def __init__(self, url, timeout=DEFAULT_TIMEOUT, check_paths=True):
        self.url = normalise_url(url)
        self.timeout = timeout
        self.check_paths = check_paths
        self.findings = []
        self.tls_info = None
        self.verify = True
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        # never store cookies: keeps every probe independent
        self.session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))

    # -- plumbing ----------------------------------------------------------
    def add(self, *args, **kwargs):
        self.findings.append(make_finding(*args, **kwargs))

    def request(self, method, url, headers=None, allow_redirects=True, stream=False):
        return self.session.request(method, url, headers=headers, timeout=self.timeout,
                                    allow_redirects=allow_redirects, stream=stream,
                                    verify=self.verify)

    # -- main entry --------------------------------------------------------
    def run(self):
        started = time.time()
        result = {"target": self.url, "final_url": None, "status_code": None,
                  "scanned_at": datetime.now().isoformat(timespec="seconds"),
                  "elapsed_seconds": None, "tls": None, "findings": [],
                  "score": None, "grade": None, "error": None}
        parsed = urlparse(self.url)
        if not parsed.hostname:
            result["error"] = "Invalid URL"
            return result
        try:
            if parsed.scheme == "https":
                self.check_tls(parsed)
            resp = self.request("GET", self.url)
        except requests.RequestException as exc:
            result["error"] = short_error(exc)
            return result

        result["status_code"] = resp.status_code
        result["final_url"] = resp.url
        final = urlparse(resp.url)

        self.check_transport(final)
        self.check_security_headers(resp)
        self.check_info_leak(resp)
        self.check_cookies(resp, final.scheme == "https")
        self.check_methods(resp.url)
        self.check_cors(resp.url)
        self.check_page_content(resp, final)
        if self.check_paths:
            self.check_exposed_paths(f"{final.scheme}://{final.netloc}")

        self.findings.sort(key=lambda f: -SEVERITY_ORDER[f["severity"]])
        result["findings"] = self.findings
        result["tls"] = self.tls_info
        result["score"], result["grade"] = calculate_grade(self.findings)
        result["elapsed_seconds"] = round(time.time() - started, 2)
        return result

    # -- 1. TLS ------------------------------------------------------------
    def check_tls(self, parsed):
        host, port = parsed.hostname, parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert, version = tls.getpeercert(), tls.version()
        except ssl.SSLCertVerificationError as exc:
            self.add("TLS", "HIGH", "TLS certificate failed verification",
                     exc.verify_message or str(exc),
                     "Install a valid certificate from a trusted CA (e.g. Let's Encrypt).",
                     "CWE-295")
            self.verify = False                  # keep auditing headers anyway
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            return
        except (OSError, ssl.SSLError):
            return                                # the normal request will report it

        days_left = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
        issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "unknown")
        self.tls_info = {"version": version, "issuer": issuer, "days_left": days_left}

        if days_left < 0:
            self.add("TLS", "HIGH", "TLS certificate has expired",
                     f"Expired {-days_left} day(s) ago.", "Renew the certificate.", "CWE-298")
        elif days_left < 15:
            self.add("TLS", "MEDIUM", "TLS certificate expires very soon",
                     f"{days_left} day(s) remaining.", "Renew / automate renewal.", "CWE-298")
        elif days_left < 30:
            self.add("TLS", "LOW", "TLS certificate expires within 30 days",
                     f"{days_left} day(s) remaining.", "Plan renewal.", "CWE-298")
        if version in ("TLSv1", "TLSv1.1", "SSLv3"):
            self.add("TLS", "HIGH", f"Obsolete protocol negotiated: {version}",
                     "Old protocols have known weaknesses.", "Allow TLS 1.2 or 1.3 only.", "CWE-327")
        self.add("TLS", "INFO", "TLS summary",
                 f"{version}, issuer: {issuer}, expires in {days_left} day(s).")

    # -- 2. transport ------------------------------------------------------
    def check_transport(self, final):
        if final.scheme == "http":
            if is_loopback(final.hostname):
                self.add("Transport", "INFO", "Plain HTTP on localhost",
                         "Acceptable for local testing only.")
            else:
                self.add("Transport", "HIGH", "Site served over plain HTTP",
                         "Traffic can be read or modified by anyone on the network.",
                         "Enable HTTPS with a valid TLS certificate.", "CWE-319")
            return
        if final.port:                            # custom port: skip redirect test
            return
        try:
            r = self.request("GET", f"http://{final.netloc}/", allow_redirects=False)
            loc = r.headers.get("Location", "")
            if not (300 <= r.status_code < 400 and loc.startswith("https://")):
                self.add("Transport", "MEDIUM", "HTTP does not redirect to HTTPS",
                         f"http:// returned status {r.status_code}.",
                         "Redirect all HTTP traffic to HTTPS (301).", "CWE-319")
        except requests.RequestException:
            pass                                  # port 80 closed is fine

    # -- 3. security headers ----------------------------------------------
    def check_security_headers(self, resp):
        for name, (sev, why, good, cwe) in SECURITY_HEADERS.items():
            value = resp.headers.get(name)
            if value is None:
                self.add("Security Header", sev, f"Missing header: {name}", why,
                         f"Add: {name}: {good}", cwe)
                continue
            low = value.lower()
            if name == "Strict-Transport-Security":
                try:
                    age = int(low.split("max-age=")[1].split(";")[0].strip())
                    if age < 15552000:
                        self.add("Security Header", "LOW", "HSTS max-age is short",
                                 f"max-age={age}s (< 180 days).", "Use max-age=31536000.", cwe)
                except (IndexError, ValueError):
                    self.add("Security Header", "MEDIUM", "HSTS value is malformed", value,
                             "Use max-age=31536000; includeSubDomains", cwe)
            elif name == "Content-Security-Policy":
                if "unsafe-inline" in low or "unsafe-eval" in low:
                    self.add("Security Header", "MEDIUM",
                             "CSP allows 'unsafe-inline' or 'unsafe-eval'", value[:120],
                             "Remove unsafe directives; use nonces/hashes.", cwe)
                if "*" in low.replace("'", "").split():
                    self.add("Security Header", "MEDIUM", "CSP uses wildcard source",
                             value[:120], "Whitelist specific trusted domains.", cwe)
            elif name == "X-Content-Type-Options" and low != "nosniff":
                self.add("Security Header", "LOW", "X-Content-Type-Options not 'nosniff'",
                         value, "Set value to: nosniff", cwe)
            elif name == "X-Frame-Options" and low not in ("deny", "sameorigin"):
                self.add("Security Header", "LOW", "X-Frame-Options has weak value",
                         value, "Use DENY or SAMEORIGIN.", cwe)

    # -- 4. information disclosure ----------------------------------------
    def check_info_leak(self, resp):
        for name in LEAKY_HEADERS:
            value = resp.headers.get(name)
            if value:
                self.add("Information Disclosure", "LOW",
                         f"Header reveals technology: {name}", f"{name}: {value}",
                         f"Remove or genericise the {name} header.", "CWE-200")

    # -- 5. cookies --------------------------------------------------------
    def check_cookies(self, resp, is_https):
        raw = []
        if hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "getlist"):
            raw = resp.raw.headers.getlist("Set-Cookie")
        for cookie in raw:
            name, low = cookie.split("=", 1)[0].strip(), cookie.lower()
            if is_https and "secure" not in low:
                self.add("Cookie", "MEDIUM", f"Cookie '{name}' missing Secure flag",
                         "Cookie can be sent over unencrypted HTTP.",
                         "Add the Secure attribute.", "CWE-614")
            if "httponly" not in low:
                self.add("Cookie", "MEDIUM", f"Cookie '{name}' missing HttpOnly flag",
                         "JavaScript (and therefore XSS) can read this cookie.",
                         "Add the HttpOnly attribute.", "CWE-1004")
            if "samesite" not in low:
                self.add("Cookie", "LOW", f"Cookie '{name}' missing SameSite attribute",
                         "Increases exposure to CSRF.", "Add SameSite=Lax or Strict.", "CWE-1275")
            elif "samesite=none" in low and "secure" not in low:
                self.add("Cookie", "MEDIUM", f"Cookie '{name}' uses SameSite=None without Secure",
                         "Browsers reject or mishandle such cookies.",
                         "Add Secure or use SameSite=Lax.", "CWE-1275")

    # -- 6. HTTP methods ---------------------------------------------------
    def check_methods(self, url):
        try:
            r = self.request("OPTIONS", url)
        except requests.RequestException:
            return
        allow = {m.strip().upper() for m in r.headers.get("Allow", "").split(",") if m.strip()}
        for method, sev in RISKY_METHODS.items():
            if method in allow:
                extra = " Can enable cross-site tracing." if method == "TRACE" else \
                        " Ensure it requires authentication."
                self.add("HTTP Methods", sev, f"Risky method enabled: {method}",
                         f"Allow: {', '.join(sorted(allow))}.{extra}",
                         f"Disable {method} unless it is required.", "CWE-16")

    # -- 7. CORS -----------------------------------------------------------
    def _cors_probe(self, url, origin):
        try:
            r = self.request("GET", url, headers={"Origin": origin})
        except requests.RequestException:
            return None, None
        return r.headers.get("Access-Control-Allow-Origin"), r.headers.get("Access-Control-Allow-Credentials")

    def check_cors(self, url):
        host = urlparse(url).hostname or ""
        acao, acac = self._cors_probe(url, EVIL_ORIGIN)
        creds = (acac or "").lower() == "true"
        if acao == EVIL_ORIGIN:
            self.add("CORS", "HIGH" if creds else "MEDIUM", "Server reflects arbitrary Origin",
                     f"Origin {EVIL_ORIGIN} was echoed back"
                     + (" with Allow-Credentials: true (attacker site can read authenticated "
                        "responses)." if creds else "."),
                     "Validate Origin against a strict allow-list.", "CWE-942")
        elif acao == "*":
            self.add("CORS", "HIGH" if creds else "LOW",
                     "Wildcard CORS policy (Access-Control-Allow-Origin: *)",
                     "Any website can read responses from this endpoint."
                     + (" Combined with credentials this is dangerous." if creds else ""),
                     "Replace * with specific trusted origins.", "CWE-942")

        a_null, c_null = self._cors_probe(url, "null")
        if a_null == "null":
            self.add("CORS", "HIGH" if (c_null or "").lower() == "true" else "MEDIUM",
                     "Server trusts the 'null' origin",
                     "Sandboxed iframes and local files can send Origin: null.",
                     "Never allow the 'null' origin.", "CWE-942")

        if host and acao != EVIL_ORIGIN:
            for label, crafted in (("suffix match", f"https://{host}.evil-attacker.example"),
                                   ("prefix match", f"https://evil-{host}")):
                a, _ = self._cors_probe(url, crafted)
                if a == crafted:
                    self.add("CORS", "HIGH", f"Weak origin validation ({label})",
                             f"Crafted origin {crafted} was accepted.",
                             "Compare the full origin exactly, not with startswith/endswith.",
                             "CWE-942")
                    break

        # preflight request
        try:
            r = self.request("OPTIONS", url, headers={
                "Origin": EVIL_ORIGIN, "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "Authorization"})
        except requests.RequestException:
            return
        p_origin = r.headers.get("Access-Control-Allow-Origin")
        p_methods = r.headers.get("Access-Control-Allow-Methods", "").upper()
        if p_origin in (EVIL_ORIGIN, "*") and any(m in p_methods for m in ("DELETE", "PUT", "PATCH")):
            self.add("CORS", "MEDIUM", "Preflight allows state-changing methods from untrusted origin",
                     f"Allow-Methods: {p_methods}", "Restrict allowed origins and methods.", "CWE-942")

    # -- 8. page content ---------------------------------------------------
    def check_page_content(self, resp, final):
        if "html" not in resp.headers.get("Content-Type", "").lower():
            return
        parser = PageParser()
        try:
            parser.feed(resp.text[:500_000])
        except Exception:                         # malformed HTML must never crash a scan
            return
        host, https = final.hostname, final.scheme == "https"

        # external resources without Subresource Integrity
        no_sri = []
        for tag in parser.scripts + parser.styles:
            src = urljoin(resp.url, tag.get("src") or tag.get("href"))
            u = urlparse(src)
            if u.hostname and u.hostname != host and not tag.get("integrity"):
                no_sri.append(src)
        if no_sri:
            self.add("Page Content", "LOW", "External resources loaded without SRI",
                     f"{len(no_sri)} resource(s), e.g. {no_sri[0]}",
                     "Add integrity=\"sha384-...\" and crossorigin attributes.", "CWE-353")

        # mixed content
        if https:
            resources = [urljoin(resp.url, t.get("src") or t.get("href"))
                         for t in parser.scripts + parser.styles] + \
                        [urljoin(resp.url, m) for m in parser.media]
            mixed = [r for r in resources if r.startswith("http://")]
            if mixed:
                self.add("Page Content", "MEDIUM", "Mixed content on HTTPS page",
                         f"{len(mixed)} resource(s) over HTTP, e.g. {mixed[0]}",
                         "Load every resource over HTTPS.", "CWE-319")

        # forms
        for form in parser.forms:
            action = urljoin(resp.url, form["action"]) if form["action"] else resp.url
            a = urlparse(action)
            if form["password"] and a.scheme == "http" and not is_loopback(a.hostname):
                self.add("Page Content", "HIGH", "Login form submits over plain HTTP",
                         f"Password field posts to {action}",
                         "Serve and submit login forms over HTTPS only.", "CWE-319")
            elif https and a.scheme == "http":
                self.add("Page Content", "HIGH", "HTTPS page posts a form to HTTP URL",
                         f"Form action: {action}", "Use an https:// form action.", "CWE-319")
            elif form["password"] and not https and not is_loopback(host):
                self.add("Page Content", "HIGH", "Password field on non-HTTPS page",
                         "Credentials can be intercepted.", "Use HTTPS.", "CWE-319")

        if parser.generator:
            self.add("Information Disclosure", "LOW", "Meta generator tag reveals software",
                     f"generator: {parser.generator}", "Remove the generator meta tag.", "CWE-200")

    # -- 9. exposed files --------------------------------------------------
    def check_exposed_paths(self, base):
        checks = [
            ("/.git/HEAD", "HIGH", "Exposed Git repository",
             lambda c, b: b.startswith(b"ref:"), "Block access to /.git and remove it from the web root.", "CWE-538"),
            ("/.env", "HIGH", "Exposed environment file (.env)",
             lambda c, b: bool(re.search(rb"^[A-Z][A-Z0-9_]*\s*=", b, re.M)) and b"<html" not in b.lower(),
             "Move secrets outside the web root and rotate them.", "CWE-538"),
            ("/backup.sql", "HIGH", "Database backup exposed",
             lambda c, b: b"CREATE TABLE" in b or b"INSERT INTO" in b,
             "Delete backups from the web root.", "CWE-538"),
            ("/backup.zip", "HIGH", "Backup archive exposed",
             lambda c, b: b.startswith(b"PK\x03\x04"),
             "Delete backups from the web root.", "CWE-538"),
            ("/phpinfo.php", "MEDIUM", "phpinfo() page exposed",
             lambda c, b: b"phpinfo()" in b or b"PHP Version" in b,
             "Remove phpinfo files from production.", "CWE-200"),
            ("/server-status", "MEDIUM", "Apache server-status exposed",
             lambda c, b: b"Apache Server Status" in b,
             "Restrict /server-status to localhost.", "CWE-200"),
        ]
        for path, sev, title, matcher, fix, cwe in checks:
            body = self._peek(base + path)
            if body is not None and matcher("", body):
                self.add("Exposed Files", sev, title, f"{base}{path} is publicly readable.", fix, cwe)

        robots = self._peek(base + "/robots.txt")
        if robots and b"disallow" in robots.lower():
            hidden = [ln.split(":", 1)[1].strip() for ln in robots.decode("utf-8", "ignore").splitlines()
                      if ln.lower().startswith("disallow:") and ln.split(":", 1)[1].strip() not in ("", "/")]
            if hidden:
                self.add("Exposed Files", "INFO", "robots.txt lists hidden paths",
                         "Disallow: " + ", ".join(hidden[:5]) + "  (do not rely on robots.txt for secrecy)")
        sectxt = self._peek(base + "/.well-known/security.txt")
        if not (sectxt and b"contact" in sectxt.lower()):
            self.add("Best Practice", "INFO", "No security.txt found",
                     "RFC 9116 recommends a /.well-known/security.txt contact file.",
                     "Publish a security.txt with a Contact: line.")

    def _peek(self, url):
        """Return up to 2 KB of a 200 response body, else None. Never follows redirects."""
        try:
            r = self.request("GET", url, allow_redirects=False, stream=True)
            body = r.raw.read(2048, decode_content=True) if r.status_code == 200 else None
            r.close()
            return body
        except requests.RequestException:
            return None


# ---------------------------------------------------------------------------
# Scoring and reporting
# ---------------------------------------------------------------------------
def calculate_grade(findings):
    score = max(0, 100 - sum(PENALTY[f["severity"]] for f in findings))
    grade = ("A" if score >= 90 else "B" if score >= 75 else
             "C" if score >= 60 else "D" if score >= 40 else "F")
    return score, grade


def count_by_severity(findings):
    return {s: sum(1 for f in findings if f["severity"] == s) for s in ("HIGH", "MEDIUM", "LOW", "INFO")}


def print_report(result, min_severity="INFO"):
    line = "=" * 70
    print(f"\n{line}\nTarget : {result['target']}\nTime   : {result['scanned_at']}")
    if result["error"]:
        print(f"{Fore.RED}Could not scan target: {result['error']}{Style.RESET_ALL}\n{line}")
        return
    print(f"Status : HTTP {result['status_code']}   Scan time: {result['elapsed_seconds']}s\n{line}")
    shown = [f for f in result["findings"]
             if SEVERITY_ORDER[f["severity"]] >= SEVERITY_ORDER[min_severity]]
    if not shown:
        print(f"{Fore.GREEN}No issues to display.{Style.RESET_ALL}")
    for f in shown:
        color = SEVERITY_COLOR[f["severity"]]
        cwe = f"  [{f['cwe']}]" if f["cwe"] else ""
        print(f"{color}[{f['severity']:<6}]{Style.RESET_ALL} ({f['category']}) {f['title']}{cwe}")
        print(f"          Detail: {f['detail']}")
        if f["recommendation"]:
            print(f"          Fix   : {f['recommendation']}")
    c = count_by_severity(result["findings"])
    gcolor = Fore.GREEN if result["grade"] in "AB" else Fore.YELLOW if result["grade"] == "C" else Fore.RED
    print(f"{line}\nSummary: {c['HIGH']} High, {c['MEDIUM']} Medium, {c['LOW']} Low, {c['INFO']} Info")
    print(f"Security score: {gcolor}{result['score']}/100   Grade: {result['grade']}{Style.RESET_ALL}\n{line}")


def print_comparison(results):
    ok = [r for r in results if not r["error"]]
    if len(ok) < 2:
        return
    print(f"\n{'COMPARISON':^70}\n{'-' * 70}")
    print(f"{'Target':<34}{'High':>6}{'Med':>6}{'Low':>6}{'Score':>8}{'Grade':>8}")
    for r in ok:
        c = count_by_severity(r["findings"])
        print(f"{r['target'][:33]:<34}{c['HIGH']:>6}{c['MEDIUM']:>6}{c['LOW']:>6}"
              f"{r['score']:>8}{r['grade']:>8}")
    print("-" * 70)


def save_json(results, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"JSON report saved to {path}")


def save_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["target", "severity", "category", "title", "detail", "recommendation", "cwe"])
        for r in results:
            for f in r["findings"]:
                w.writerow([r["target"], f["severity"], f["category"], f["title"],
                            f["detail"], f["recommendation"], f["cwe"]])
    print(f"CSV report saved to {path}")


def save_html(results, path):
    esc = html.escape
    css = """body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6fa;color:#1c2333;margin:0;padding:24px}
h1{color:#1f3864}.card{background:#fff;border-radius:10px;padding:20px;margin:18px 0;box-shadow:0 1px 4px #0002}
.grade{float:right;font-size:38px;font-weight:700;padding:6px 22px;border-radius:10px;color:#fff}
.A,.B{background:#2e9e5b}.C{background:#e0a800}.D,.F{background:#d64545}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:14px}
th{background:#1f3864;color:#fff;text-align:left;padding:8px}td{padding:8px;border-bottom:1px solid #e3e7ee;vertical-align:top}
.b{padding:2px 9px;border-radius:12px;color:#fff;font-size:12px;font-weight:600}
.HIGH{background:#d64545}.MEDIUM{background:#e0a800}.LOW{background:#2a8fbd}.INFO{background:#8a94a6}
.small{color:#667;font-size:13px}"""
    out = [f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>Web Scan Report</title>"
           f"<style>{css}</style></head><body><h1>Web Security Scan Report</h1>"
           f"<p class='small'>Generated {datetime.now():%Y-%m-%d %H:%M} by Automated Web Scanner v{VERSION}. "
           f"Authorised testing only.</p>"]
    for r in results:
        out.append("<div class='card'>")
        if r["error"]:
            out.append(f"<h2>{esc(r['target'])}</h2><p>Scan failed: {esc(r['error'])}</p></div>")
            continue
        c = count_by_severity(r["findings"])
        out.append(f"<div class='grade {r['grade']}'>{r['grade']}</div><h2>{esc(r['target'])}</h2>"
                   f"<p class='small'>HTTP {r['status_code']} &middot; score {r['score']}/100 &middot; "
                   f"{c['HIGH']} high, {c['MEDIUM']} medium, {c['LOW']} low, {c['INFO']} info</p>"
                   "<table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Detail</th><th>Fix</th></tr>")
        for f in r["findings"]:
            cwe = f" <span class='small'>{esc(f['cwe'])}</span>" if f["cwe"] else ""
            out.append(f"<tr><td><span class='b {f['severity']}'>{f['severity']}</span></td>"
                       f"<td>{esc(f['category'])}</td><td>{esc(f['title'])}{cwe}</td>"
                       f"<td>{esc(f['detail'])}</td><td>{esc(f['recommendation'])}</td></tr>")
        out.append("</table></div>")
    out.append("</body></html>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(out))
    print(f"HTML report saved to {path}")


# ---------------------------------------------------------------------------
# Built-in demo servers (localhost only)
# ---------------------------------------------------------------------------
class VulnerableDemoHandler(BaseHTTPRequestHandler):
    """Deliberately misconfigured server for safe testing."""
    server_version, sys_version = "Apache/2.2.8 (Demo)", ""
    PAGE = (b"<html><head><meta name='generator' content='WordPress 4.1'>"
            b"<script src='https://cdn.example.com/lib.js'></script></head><body>"
            b"<form action='http://shop.example.com/login' method='post'>"
            b"<input type='text' name='u'><input type='password' name='p'></form></body></html>")
    FILES = {"/.git/HEAD": b"ref: refs/heads/main\n",
             "/.env": b"DB_PASSWORD=secret123\nAPI_KEY=abc123\n",
             "/phpinfo.php": b"<title>phpinfo()</title> PHP Version 5.2.4",
             "/robots.txt": b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n"}

    def _cors(self):
        origin = self.headers.get("Origin")
        if origin:                                # reflects any origin + credentials
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")

    def do_GET(self):
        body = self.PAGE if self.path == "/" else self.FILES.get(self.path)
        if body is None:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html" if self.path == "/" else "text/plain")
        self.send_header("X-Powered-By", "PHP/5.2.4")
        if self.path == "/":
            self.send_header("Set-Cookie", "sessionid=abc123")
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, TRACE, OPTIONS")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
        self._cors()
        self.end_headers()

    def log_message(self, *args):
        pass


class HardenedDemoHandler(BaseHTTPRequestHandler):
    """Well-configured server, used to show what a good result looks like."""
    TRUSTED = "https://trusted.example"
    PAGE = (b"<html><head><script src='https://cdn.example.com/lib.js' "
            b"integrity='sha384-abc' crossorigin='anonymous'></script></head>"
            b"<body><h1>Hardened demo</h1></body></html>")

    def version_string(self):
        return ""                                  # hide server banner

    def _common(self):
        for k, v in (("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
                     ("Content-Security-Policy", "default-src 'self'"),
                     ("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff"),
                     ("Referrer-Policy", "strict-origin-when-cross-origin"),
                     ("Permissions-Policy", "geolocation=(), camera=(), microphone=()"),
                     ("Cross-Origin-Opener-Policy", "same-origin")):
            self.send_header(k, v)
        if self.headers.get("Origin") == self.TRUSTED:     # strict allow-list
            self.send_header("Access-Control-Allow-Origin", self.TRUSTED)

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Strict")
            self._common(); self.end_headers(); self.wfile.write(self.PAGE)
        elif self.path == "/.well-known/security.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers(); self.wfile.write(b"Contact: mailto:security@trusted.example\n")
        else:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self._common(); self.end_headers()

    def log_message(self, *args):
        pass


def start_demo_servers():
    servers, urls = [], []
    for handler in (VulnerableDemoHandler, HardenedDemoHandler):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        urls.append(f"http://127.0.0.1:{srv.server_address[1]}")
    return servers, urls


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def scan_one(args_tuple):
    url, timeout, check_paths = args_tuple
    return WebScanner(url, timeout, check_paths).run()


def build_parser():
    p = argparse.ArgumentParser(
        description="Audit websites for security headers, TLS, cookies, CORS and exposed files.")
    p.add_argument("url", nargs="?", help="Target URL (e.g. https://example.com)")
    p.add_argument("--file", help="Text file with one URL per line (# for comments)")
    p.add_argument("--json", help="Save results to a JSON file")
    p.add_argument("--csv", help="Save results to a CSV file")
    p.add_argument("--html", help="Save a styled HTML report")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    p.add_argument("--threads", type=int, default=3, help="Parallel scans for multiple targets")
    p.add_argument("--no-paths", action="store_true", help="Skip exposed-file probing")
    p.add_argument("--min-severity", choices=["info", "low", "medium", "high"], default="info",
                   help="Hide findings below this severity in the console")
    p.add_argument("--fail-on", choices=["low", "medium", "high"],
                   help="Exit with code 2 if a finding at/above this level exists (CI/CD gate)")
    p.add_argument("--demo", action="store_true",
                   help="Scan two built-in local servers (vulnerable vs hardened) - safe, offline")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def main():
    args = build_parser().parse_args()
    servers = []
    if args.demo:
        servers, targets = start_demo_servers()
        print(f"Demo servers started: {targets[0]} (vulnerable), {targets[1]} (hardened)")
    else:
        targets = [args.url] if args.url else []
        if args.file:
            with open(args.file, encoding="utf-8") as fh:
                targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        if not targets:
            build_parser().print_help()
            sys.exit(1)
        print(f"{Fore.YELLOW}Reminder: scan only systems you own or are authorised to test."
              f"{Style.RESET_ALL}")

    jobs = [(t, args.timeout, not args.no_paths) for t in targets]
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        results = list(pool.map(scan_one, jobs))
    for s in servers:
        s.shutdown()

    for r in results:
        print_report(r, args.min_severity.upper())
    print_comparison(results)
    if args.json:
        save_json(results, args.json)
    if args.csv:
        save_csv(results, args.csv)
    if args.html:
        save_html(results, args.html)

    if args.fail_on and not args.demo:
        if any(r["error"] for r in results):
            print(f"{Fore.RED}Some targets could not be scanned.{Style.RESET_ALL}")
            sys.exit(3)
        limit = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER[f["severity"]] >= limit for r in results for f in r["findings"]):
            print(f"{Fore.RED}Failing build: finding at or above '{args.fail_on}'.{Style.RESET_ALL}")
            sys.exit(2)


if __name__ == "__main__":
    main()
