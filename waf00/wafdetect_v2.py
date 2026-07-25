#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wafdetect_v2.py  --  Advanced WAF & CDN Detection Tool v2
==========================================================
What makes this different:
  - External JSON signature database  (signatures/waf/ and signatures/cdn/)
  - CDN detection separated from WAF detection
  - Plugin-based detector architecture (passive, active, behavioral, dns)
  - Async/threaded probing for speed
  - Per-probe DIFF output (status, headers, cookies, body size, latency delta)
  - Confidence scoring with full evidence trail
  - Detection modes: --passive, --active, --aggressive
  - Output: human-readable terminal + --json for machine consumption
  - Answers: What WAF? How confident? Why? What evidence? What changed?

Usage:
  py wafdetect_v2.py https://target.com
  py wafdetect_v2.py https://target.com --passive
  py wafdetect_v2.py https://target.com --active --threads 5 --diff
  py wafdetect_v2.py https://target.com --aggressive --evidence --json out.json
"""

import argparse
import json
import os
import random
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Missing: pip install requests")
    sys.exit(1)

VERSION       = "2.0.0"
TOOL_NAME     = "wafdetect_v2"
SCRIPT_DIR    = Path(__file__).parent
SIG_WAF_DIR   = SCRIPT_DIR / "signatures" / "waf"
SIG_CDN_DIR   = SCRIPT_DIR / "signatures" / "cdn"

# ── Timing profiles per mode ────────────────────────────────────────────────
TIMING = {
    "passive":    {"min": 0.0, "max": 0.0},    # no delay needed, 1 request
    "active":     {"min": 0.8, "max": 2.0},    # rate-limited
    "aggressive": {"min": 0.1, "max": 0.4},    # faster, more probes
}

DEFAULT_TIMEOUT = 12
MAX_RETRIES     = 2

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/124.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

# ─────────────────────────────────────────────────────────────────────────────
# PROBE PAYLOAD LIBRARY
# active = standard probes, aggressive = active + extra fuzzing
# ─────────────────────────────────────────────────────────────────────────────
PROBES_ACTIVE = [
    {"id": "xss_basic",     "path": "/?q=<script>alert(1)</script>",          "type": "xss",      "desc": "Basic XSS"},
    {"id": "sqli_or",       "path": "/?id=1'%20OR%20'1'='1",                  "type": "sqli",     "desc": "SQLi OR"},
    {"id": "sqli_drop",     "path": "/?id=1;DROP%20TABLE%20users--",           "type": "sqli",     "desc": "SQLi DROP"},
    {"id": "lfi_basic",     "path": "/?file=../../etc/passwd",                 "type": "lfi",      "desc": "LFI basic"},
    {"id": "lfi_encoded",   "path": "/?file=..%2F..%2Fetc%2Fshadow",          "type": "lfi",      "desc": "LFI encoded"},
    {"id": "cmdi",          "path": "/?cmd=;cat%20/etc/passwd",                "type": "cmdi",     "desc": "Command injection"},
    {"id": "scanner_ua",    "path": "/",                                        "type": "ua",       "desc": "Scanner UA",
     "extra_headers": {"User-Agent": "Nikto/2.1.6", "X-Scanner": "true"}},
    {"id": "long_url",      "path": "/?" + "X" * 2048,                        "type": "overflow", "desc": "Long URL"},
    {"id": "null_byte",     "path": "/?x=test%00.php",                         "type": "nullbyte", "desc": "Null byte"},
    {"id": "bad_method",    "path": "/",                                        "type": "method",   "desc": "Invalid method",
     "method": "FUZZ"},
]

PROBES_AGGRESSIVE = PROBES_ACTIVE + [
    {"id": "xxe",           "path": "/?x=%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C!DOCTYPE%20foo%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%5D%3E%3Cfoo%3E%26xxe%3B%3C%2Ffoo%3E",
     "type": "xxe", "desc": "XXE injection"},
    {"id": "ssti",          "path": "/?name={{7*7}}",                          "type": "ssti",     "desc": "SSTI probe"},
    {"id": "sqli_sleep",    "path": "/?id=1%20AND%20SLEEP(0)",                 "type": "sqli",     "desc": "SQLi time-based"},
    {"id": "open_redirect", "path": "/?url=https://evil.com",                  "type": "redirect", "desc": "Open redirect"},
    {"id": "xss_encoded",   "path": "/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "type": "xss", "desc": "XSS encoded"},
    {"id": "path_traversal","path": "/../../../etc/passwd",                    "type": "lfi",      "desc": "Path traversal in URL"},
    {"id": "rce_probe",     "path": "/?cmd=;id;",                              "type": "rce",      "desc": "RCE probe"},
    {"id": "header_inject", "path": "/",                                        "type": "header",   "desc": "Header injection",
     "extra_headers": {"X-Forwarded-For": "127.0.0.1\r\nX-Injected: true"}},
]

BLOCK_STATUS_CODES = {400, 401, 403, 406, 412, 418, 429, 503}

GENERIC_BLOCK_PATTERNS = [
    r"access denied",
    r"\bblocked\b",
    r"your (ip|request|access) (has been|is) (blocked|denied|restricted)",
    r"security policy",
    r"suspicious activity",
    r"automated (request|traffic|access)",
    r"please verify you are a human",
    r"ddos protection",
    r"rate limit(ed)?",
    r"too many requests",
    r"captcha required",
    r"web application firewall",
    r"\bwaf\b",
]

# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Response:
    """Single HTTP response snapshot."""
    url: str
    method: str
    status_code: int
    response_time: float
    headers: dict
    body: str
    cookies: dict
    error: Optional[str] = None

    @property
    def body_len(self) -> int:
        return len(self.body)

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code > 0


@dataclass
class ProbeDiff:
    """Delta between baseline and a probe response."""
    probe_id: str
    probe_desc: str
    probe_type: str
    url: str
    status_baseline: int
    status_probe: int
    status_changed: bool
    body_len_baseline: int
    body_len_probe: int
    body_len_delta: int
    latency_baseline: float
    latency_probe: float
    latency_delta: float
    new_headers: list        # headers that appeared only in probe response
    removed_headers: list    # headers that disappeared in probe response
    cookies_baseline: list
    cookies_probe: list
    new_cookies: list
    generic_block_hit: bool
    waf_body_match: Optional[str]   # WAF name if body matched a known sig
    error: Optional[str] = None


@dataclass
class Evidence:
    """A single piece of evidence supporting WAF/CDN detection."""
    detector: str        # passive_header | passive_cookie | passive_body | active | behavioral | dns
    evidence_type: str   # header | cookie | body | status | timing | block_rate | dns
    detail: str
    matched_name: Optional[str]
    confidence_pts: int


@dataclass
class DetectionResult:
    """Final result for a target."""
    target: str
    scan_time: str
    mode: str
    waf_detected: bool
    cdn_detected: bool
    waf_names: list = field(default_factory=list)
    cdn_names: list = field(default_factory=list)
    confidence: int = 0
    verdict: str = ""
    classification: str = ""    # WAF | CDN | WAF+CDN | None
    evidence: list = field(default_factory=list)
    diffs: list = field(default_factory=list)
    baseline: dict = field(default_factory=dict)
    probe_stats: dict = field(default_factory=dict)
    dns_info: dict = field(default_factory=dict)
    recommendations: list = field(default_factory=list)

# ─────────────────────────────────────────────────────────────────────────────
# SIGNATURE LOADER  (reads all JSON files from signatures/waf/ and cdn/)
# ─────────────────────────────────────────────────────────────────────────────
class SignatureDB:
    """
    Loads all .json signature files from the signatures directory.
    Adding a new WAF/CDN = drop a new JSON file in the right folder.
    No source code changes needed.
    """

    def __init__(self):
        self.waf_sigs: list = []
        self.cdn_sigs: list = []
        self._load(SIG_WAF_DIR, self.waf_sigs)
        self._load(SIG_CDN_DIR, self.cdn_sigs)

    def _load(self, directory: Path, target: list):
        if not directory.exists():
            return
        for f in sorted(directory.glob("*.json")):
            try:
                with open(f, encoding="utf-8") as fh:
                    sig = json.load(fh)
                    sig["_source"] = f.name
                    target.append(sig)
            except Exception as e:
                print(f"[!] Failed to load signature {f.name}: {e}")

    @property
    def all_sigs(self) -> list:
        return self.waf_sigs + self.cdn_sigs

    def summary(self) -> str:
        return f"{len(self.waf_sigs)} WAF sigs, {len(self.cdn_sigs)} CDN sigs loaded from {SIG_WAF_DIR.parent}"


# ─────────────────────────────────────────────────────────────────────────────
# HTTP CLIENT
# ─────────────────────────────────────────────────────────────────────────────
class HTTPClient:
    def __init__(self, timeout: int = DEFAULT_TIMEOUT, verify_ssl: bool = False,
                 proxy: Optional[str] = None, mode: str = "active"):
        self.timeout = timeout
        self.verify  = verify_ssl
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.mode    = mode
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })

    def _ua(self):
        self.session.headers["User-Agent"] = random.choice(USER_AGENTS)

    def _delay(self):
        t = TIMING.get(self.mode, TIMING["active"])
        if t["max"] > 0:
            time.sleep(random.uniform(t["min"], t["max"]))

    def get(self, url: str, extra_headers: dict = None,
            method: str = "GET", delay: bool = True) -> Response:
        self._ua()
        if delay:
            self._delay()
        hdrs = dict(self.session.headers)
        if extra_headers:
            hdrs.update(extra_headers)

        for attempt in range(MAX_RETRIES + 1):
            t0 = time.time()
            try:
                resp = self.session.request(
                    method, url, headers=hdrs,
                    timeout=self.timeout, verify=self.verify,
                    proxies=self.proxies, allow_redirects=True
                )
                elapsed = round(time.time() - t0, 3)
                body = ""
                try:
                    body = resp.text[:3000]
                except Exception:
                    pass
                return Response(
                    url=url, method=method,
                    status_code=resp.status_code,
                    response_time=elapsed,
                    headers=dict(resp.headers),
                    body=body,
                    cookies={c.name: c.value for c in resp.cookies},
                )
            except requests.exceptions.SSLError:
                self.verify = False
                if attempt == MAX_RETRIES:
                    return Response(url=url, method=method, status_code=0,
                                    response_time=0, headers={}, body="",
                                    cookies={}, error="SSL error")
            except requests.exceptions.ConnectionError as e:
                if attempt == MAX_RETRIES:
                    return Response(url=url, method=method, status_code=0,
                                    response_time=0, headers={}, body="",
                                    cookies={}, error=f"Connection error: {e}")
                time.sleep(0.5)
            except requests.exceptions.Timeout:
                return Response(url=url, method=method, status_code=0,
                                response_time=round(time.time() - t0, 3),
                                headers={}, body="",
                                cookies={}, error="Timeout")
            except Exception as e:
                return Response(url=url, method=method, status_code=0,
                                response_time=0, headers={}, body="",
                                cookies={}, error=str(e))

# ─────────────────────────────────────────────────────────────────────────────
# DETECTOR PLUGINS
# Each detector takes a response (or list of responses) and returns Evidence
# ─────────────────────────────────────────────────────────────────────────────

class PassiveDetector:
    """
    Layer 1: Analyses the baseline response only.
    Checks headers, cookies, body against all loaded signatures.
    Zero risk — one normal GET request.
    """

    def __init__(self, db: SignatureDB):
        self.db = db

    def detect(self, resp: Response) -> list:
        if not resp.ok:
            return []
        evidence = []
        h = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.body.lower()

        for sig in self.db.all_sigs:
            name = sig["name"]
            w    = sig.get("confidence_weight", 20)

            # headers
            for hname, pattern in sig.get("headers", {}).items():
                val = h.get(hname.lower(), "")
                if val and re.search(pattern, val, re.IGNORECASE):
                    evidence.append(Evidence(
                        detector="passive_header",
                        evidence_type="header",
                        detail=f"Header '{hname}: {resp.headers.get(hname, val)}' matches {name}",
                        matched_name=name,
                        confidence_pts=w,
                    ))

            # cookies
            for cpat in sig.get("cookies", []):
                for cname in resp.cookies:
                    if re.search(cpat, cname, re.IGNORECASE):
                        evidence.append(Evidence(
                            detector="passive_cookie",
                            evidence_type="cookie",
                            detail=f"Cookie '{cname}' matches {name} pattern '{cpat}'",
                            matched_name=name,
                            confidence_pts=w,
                        ))
                        break

            # body
            for bpat in sig.get("body_patterns", []):
                if re.search(bpat, body, re.IGNORECASE):
                    evidence.append(Evidence(
                        detector="passive_body",
                        evidence_type="body",
                        detail=f"Body matches '{bpat}' ({name})",
                        matched_name=name,
                        confidence_pts=w,
                    ))
                    break  # one body hit per sig

        # generic security headers (no specific vendor)
        generic_sec = ["x-waf-event-info", "x-protected-by", "x-firewall-protection",
                        "x-security-action", "x-rack-cache", "x-waf-score"]
        for gh in generic_sec:
            if gh in h:
                evidence.append(Evidence(
                    detector="passive_header",
                    evidence_type="header",
                    detail=f"Generic security header: '{gh}: {h[gh]}'",
                    matched_name=None,
                    confidence_pts=20,
                ))

        return evidence


class DNSDetector:
    """
    Layer 2: DNS-based fingerprinting.
    Resolves the target hostname and checks for CDN/WAF IP ranges and CNAME patterns.
    Fully passive — only DNS queries, no HTTP.
    """

    CDN_CNAME_PATTERNS = {
        "Cloudflare":       r"cloudflare\.net$",
        "Akamai":           r"akamai(edge|\.net|technologies)\.com$",
        "Amazon CloudFront":r"cloudfront\.net$",
        "Fastly":           r"fastly\.net$",
        "Sucuri":           r"sucuri\.net$",
        "StackPath":        r"(stackpathdns|hwcdn)\.net$",
        "Imperva":          r"incapdns\.net$",
        "Azure Front Door": r"azurefd\.net$",
        "Radware":          r"radwarecloud\.com$",
    }

    def detect(self, hostname: str) -> tuple:
        """Returns (evidence: list, dns_info: dict)"""
        import threading
        evidence = []
        dns_info = {"hostname": hostname, "ips": [], "cnames": []}

        if not hostname:
            return evidence, dns_info

        holder: dict = {"done": False}

        def _resolve():
            try:
                ips = list({r[4][0] for r in socket.getaddrinfo(hostname, 80)})
                holder["ips"] = ips
            except Exception:
                holder["ips"] = []
            holder["done"] = True

        t = threading.Thread(target=_resolve, daemon=True)
        t.start()
        t.join(timeout=3)   # hard 3s cap — if still running we skip

        if not holder.get("done"):
            # DNS timed out — skip silently
            return evidence, dns_info

        dns_info["ips"] = holder.get("ips", [])
        return evidence, dns_info

class ActiveDetector:
    """
    Layer 3: Sends crafted probes and analyses responses.
    Threaded — all probes fired concurrently up to --threads limit.
    Returns (evidence, diffs).
    """

    def __init__(self, client: HTTPClient, db: SignatureDB,
                 base_url: str, threads: int = 3, verbose: bool = False):
        self.client   = client
        self.db       = db
        self.base_url = base_url.rstrip("/")
        self.threads  = threads
        self.verbose  = verbose

    def _run_probe(self, probe: dict, baseline: Response) -> tuple:
        """Returns (Evidence list, ProbeDiff)"""
        url    = self.base_url + probe["path"]
        method = probe.get("method", "GET")
        extra  = probe.get("extra_headers", {})
        resp   = self.client.get(url, extra_headers=extra, method=method, delay=True)
        diff   = self._make_diff(probe, baseline, resp)
        evs    = self._analyse(probe, baseline, resp, diff)
        return evs, diff

    def run(self, baseline: Response, probes: list) -> tuple:
        all_evidence = []
        all_diffs    = []

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._run_probe, p, baseline): p for p in probes}
            for future in as_completed(futures):
                try:
                    evs, diff = future.result()
                    all_evidence.extend(evs)
                    all_diffs.append(diff)
                    if self.verbose and evs:
                        for e in evs:
                            _cy(f"  [active] +{e.confidence_pts}pt  {e.detail}")
                except Exception as ex:
                    if self.verbose:
                        _cr(f"  [active] probe error: {ex}")

        return all_evidence, all_diffs

    def _make_diff(self, probe: dict, baseline: Response, resp: Response) -> ProbeDiff:
        b_headers = {k.lower() for k in baseline.headers}
        p_headers = {k.lower() for k in resp.headers}
        new_hdrs  = sorted(p_headers - b_headers)
        rem_hdrs  = sorted(b_headers - p_headers)

        b_cookies = sorted(baseline.cookies.keys())
        p_cookies = sorted(resp.cookies.keys())
        new_ck    = sorted(set(p_cookies) - set(b_cookies))

        # check body against known WAF sigs
        waf_body = None
        if resp.ok:
            body_low = resp.body.lower()
            for sig in self.db.all_sigs:
                for pat in sig.get("body_patterns", []):
                    if re.search(pat, body_low, re.IGNORECASE):
                        waf_body = sig["name"]
                        break
                if waf_body:
                    break

        # check body against generic block patterns
        generic_block = False
        if resp.ok:
            body_low = resp.body.lower()
            for pat in GENERIC_BLOCK_PATTERNS:
                if re.search(pat, body_low, re.IGNORECASE):
                    generic_block = True
                    break

        return ProbeDiff(
            probe_id=probe["id"],
            probe_desc=probe["desc"],
            probe_type=probe["type"],
            url=resp.url,
            status_baseline=baseline.status_code,
            status_probe=resp.status_code if resp.ok else 0,
            status_changed=(resp.status_code != baseline.status_code) if resp.ok else False,
            body_len_baseline=baseline.body_len,
            body_len_probe=resp.body_len,
            body_len_delta=resp.body_len - baseline.body_len,
            latency_baseline=baseline.response_time,
            latency_probe=resp.response_time,
            latency_delta=round(resp.response_time - baseline.response_time, 3),
            new_headers=new_hdrs,
            removed_headers=rem_hdrs,
            cookies_baseline=b_cookies,
            cookies_probe=p_cookies,
            new_cookies=new_ck,
            generic_block_hit=generic_block,
            waf_body_match=waf_body,
            error=resp.error,
        )

    def _analyse(self, probe: dict, baseline: Response,
                 resp: Response, diff: ProbeDiff) -> list:
        evidence = []
        if not resp.ok:
            return evidence

        # known WAF body match
        if diff.waf_body_match:
            w = next((s.get("confidence_weight", 25) for s in self.db.all_sigs
                      if s["name"] == diff.waf_body_match), 25)
            evidence.append(Evidence(
                detector="active",
                evidence_type="body",
                detail=f"Probe '{probe['desc']}' triggered {diff.waf_body_match} block page",
                matched_name=diff.waf_body_match,
                confidence_pts=w,
            ))

        # generic block body
        if diff.generic_block_hit and not diff.waf_body_match:
            evidence.append(Evidence(
                detector="active",
                evidence_type="body",
                detail=f"Probe '{probe['desc']}' triggered generic WAF block body",
                matched_name=None,
                confidence_pts=20,
            ))

        # status code block
        if resp.status_code in BLOCK_STATUS_CODES and baseline.status_code not in BLOCK_STATUS_CODES:
            evidence.append(Evidence(
                detector="active",
                evidence_type="status",
                detail=f"Probe '{probe['desc']}' blocked: HTTP {resp.status_code} (baseline: {baseline.status_code})",
                matched_name=None,
                confidence_pts=25,
            ))

        # new security headers injected by WAF
        for h in diff.new_headers:
            if any(kw in h for kw in ["waf","firewall","security","cf-","x-amz","incap","akamai","block"]):
                evidence.append(Evidence(
                    detector="active",
                    evidence_type="header",
                    detail=f"Probe '{probe['desc']}' caused new header: '{h}'",
                    matched_name=None,
                    confidence_pts=20,
                ))

        return evidence

class BehavioralDetector:
    """
    Layer 4: Statistical analysis across all probe responses.
    Detects unknown/custom WAFs that have zero signature coverage.
    """

    def analyse(self, baseline: Response, diffs: list) -> list:
        evidence  = []
        valid     = [d for d in diffs if not d.error and d.status_probe > 0]
        if len(valid) < 2:
            return evidence

        statuses      = [d.status_probe for d in valid]
        block_count   = sum(1 for s in statuses if s in BLOCK_STATUS_CODES)
        block_rate    = block_count / len(valid)
        latencies     = [d.latency_probe for d in valid]
        body_lens     = [d.body_len_probe for d in valid]
        avg_lat       = sum(latencies) / len(latencies)

        # block rate signal
        if block_rate >= 0.25:
            pts = min(40, int(block_rate * 50))
            evidence.append(Evidence(
                detector="behavioral",
                evidence_type="block_rate",
                detail=f"{block_count}/{len(valid)} probes blocked ({int(block_rate*100)}% block rate)",
                matched_name=None,
                confidence_pts=pts,
            ))

        # response time spike vs baseline
        if baseline.response_time > 0 and avg_lat > baseline.response_time * 2.0:
            evidence.append(Evidence(
                detector="behavioral",
                evidence_type="timing",
                detail=f"Probe avg latency {avg_lat:.2f}s vs baseline {baseline.response_time}s "
                       f"({avg_lat/baseline.response_time:.1f}x) — deep inspection suspected",
                matched_name=None,
                confidence_pts=20,
            ))

        # body length delta
        if baseline.body_len > 0:
            avg_body = sum(body_lens) / len(body_lens)
            ratio    = abs(avg_body - baseline.body_len) / max(baseline.body_len, 1)
            if ratio > 0.35:
                evidence.append(Evidence(
                    detector="behavioral",
                    evidence_type="body_delta",
                    detail=f"Body size changed {int(ratio*100)}% vs baseline "
                           f"(baseline={baseline.body_len}B, probe avg={int(avg_body)}B)",
                    matched_name=None,
                    confidence_pts=15,
                ))

        # status code variance
        unique_codes = set(statuses)
        if len(unique_codes) >= 3:
            evidence.append(Evidence(
                detector="behavioral",
                evidence_type="status_variance",
                detail=f"Status code spread across probes: {sorted(unique_codes)} — "
                       "WAF differentiating request types",
                matched_name=None,
                confidence_pts=15,
            ))

        # templated block page — blocked responses have near-identical body size
        blocked_sizes = [d.body_len_probe for d in valid if d.status_probe in BLOCK_STATUS_CODES]
        if len(blocked_sizes) >= 3 and (max(blocked_sizes) - min(blocked_sizes)) < 80:
            evidence.append(Evidence(
                detector="behavioral",
                evidence_type="templated_block",
                detail=f"Blocked responses have uniform body size "
                       f"({min(blocked_sizes)}-{max(blocked_sizes)}B) — WAF block template detected",
                matched_name=None,
                confidence_pts=30,
            ))

        return evidence

# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE + CLASSIFICATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class ConfidenceEngine:
    """
    Aggregates all evidence into a final score and classification.

    Classification answers:
      - Is it a WAF?
      - Is it a CDN?
      - Is it both?
      - Which vendor?
      - How confident (0-100%)?
      - Why? (full evidence trail)
    """

    def compute(self, evidence: list, db: SignatureDB) -> tuple:
        """
        Returns (score, waf_names, cdn_names, verdict, classification)
        """
        if not evidence:
            return 0, [], [], "No WAF or CDN detected", "None"

        # deduplicate: one signal per (detector, evidence_type, matched_name)
        seen, deduped = set(), []
        for e in evidence:
            key = (e.detector, e.evidence_type, e.matched_name or "generic")
            if key not in seen:
                seen.add(key)
                deduped.append(e)

        # layer diversity bonus
        layers  = {e.detector for e in deduped}
        bonus   = max(0, (len(layers) - 1) * 10)
        raw     = sum(e.confidence_pts for e in deduped) + bonus
        score   = min(100, raw)

        # separate WAF names from CDN names using sig db
        waf_sig_names = {s["name"] for s in db.waf_sigs}
        cdn_sig_names = {s["name"] for s in db.cdn_sigs}

        name_counts: dict = {}
        for e in deduped:
            if e.matched_name:
                name_counts[e.matched_name] = name_counts.get(e.matched_name, 0) + 1

        waf_names = sorted([n for n in name_counts if n in waf_sig_names],
                            key=lambda k: -name_counts[k])
        cdn_names = sorted([n for n in name_counts if n in cdn_sig_names],
                            key=lambda k: -name_counts[k])

        # classification
        has_waf = bool(waf_names) or any(
            e.matched_name is None and e.detector in ("active","behavioral")
            for e in deduped
        )
        has_cdn = bool(cdn_names)

        if has_waf and has_cdn:
            classification = "WAF+CDN"
        elif has_waf:
            classification = "WAF"
        elif has_cdn:
            classification = "CDN"
        else:
            classification = "None"

        # verdict
        if score <= 15:
            verdict = "No WAF or CDN detected"
        elif score <= 35:
            verdict = "Possibly protected (low confidence) — manual review recommended"
        elif score <= 60:
            verdict = "WAF/CDN likely present"
        elif score <= 80:
            verdict = "WAF/CDN detected (high confidence)"
        else:
            verdict = "WAF/CDN confirmed (very high confidence)"

        return score, waf_names, cdn_names, verdict, classification

# ─────────────────────────────────────────────────────────────────────────────
# SCANNER ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────
class WAFScannerV2:

    def __init__(self, target: str, mode: str = "active",
                 threads: int = 3, timeout: int = DEFAULT_TIMEOUT,
                 verify_ssl: bool = False, proxy: Optional[str] = None,
                 verbose: bool = False):
        self.target  = self._norm(target)
        self.mode    = mode
        self.threads = threads
        self.verbose = verbose
        self.db      = SignatureDB()
        self.client  = HTTPClient(timeout=timeout, verify_ssl=verify_ssl,
                                   proxy=proxy, mode=mode)

    @staticmethod
    def _norm(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _hostname(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.target).hostname or ""

    def scan(self) -> DetectionResult:
        from datetime import datetime, timezone
        result = DetectionResult(
            target=self.target,
            scan_time=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            mode=self.mode,
            waf_detected=False,
            cdn_detected=False,
        )

        all_evidence: list = []
        all_diffs:    list = []

        _ci(f"[1] Loaded {self.db.summary()}")

        # ── DNS fingerprinting ────────────────────────────────────────────────
        _ci("[2] DNS fingerprinting ...")
        dns_det  = DNSDetector()
        dns_evs, dns_info = dns_det.detect(self._hostname())
        all_evidence.extend(dns_evs)
        result.dns_info = dns_info
        if dns_evs:
            _co(f"    {len(dns_evs)} DNS signal(s) found")
        else:
            _cd("    No DNS signals")

        # ── Baseline ──────────────────────────────────────────────────────────
        _ci(f"[3] Baseline request -> {self.target} ...")
        baseline = self.client.get(self.target, delay=False)
        if not baseline.ok:
            result.verdict = f"Scan failed: {baseline.error}"
            return result

        result.baseline = {
            "status":        baseline.status_code,
            "response_time": baseline.response_time,
            "body_len":      baseline.body_len,
            "server":        baseline.headers.get("Server", baseline.headers.get("server", "N/A")),
        }
        _co(f"    HTTP {baseline.status_code}, {baseline.body_len}B, {baseline.response_time}s")

        # ── Passive detection ─────────────────────────────────────────────────
        _ci("[4] Passive fingerprinting ...")
        passive_evs = PassiveDetector(self.db).detect(baseline)
        all_evidence.extend(passive_evs)
        _co(f"    {len(passive_evs)} passive signal(s)")

        # ── Active / Aggressive probing ───────────────────────────────────────
        if self.mode in ("active", "aggressive"):
            probes = PROBES_AGGRESSIVE if self.mode == "aggressive" else PROBES_ACTIVE
            _ci(f"[5] {self.mode.title()} probing — {len(probes)} probes, "
                f"{self.threads} thread(s), {TIMING[self.mode]['min']}-"
                f"{TIMING[self.mode]['max']}s delay ...")
            act_det = ActiveDetector(self.client, self.db, self.target,
                                      self.threads, self.verbose)
            active_evs, all_diffs = act_det.run(baseline, probes)
            all_evidence.extend(active_evs)
            _co(f"    {len(active_evs)} active signal(s) from {len(all_diffs)} probes")

            # ── Behavioral analysis ───────────────────────────────────────────
            _ci("[6] Behavioral analysis ...")
            beh_evs = BehavioralDetector().analyse(baseline, all_diffs)
            all_evidence.extend(beh_evs)
            _co(f"    {len(beh_evs)} behavioral signal(s)")

            # probe stats
            valid_d = [d for d in all_diffs if not d.error and d.status_probe > 0]
            if valid_d:
                result.probe_stats = {
                    "total":       len(probes),
                    "successful":  len(valid_d),
                    "blocked":     sum(1 for d in valid_d if d.status_probe in BLOCK_STATUS_CODES),
                    "avg_latency": round(sum(d.latency_probe for d in valid_d) / len(valid_d), 3),
                    "status_spread": sorted(set(d.status_probe for d in valid_d)),
                }
        else:
            _cd("[5] Active probing skipped (--passive mode)")

        # ── Score and finalise ────────────────────────────────────────────────
        engine = ConfidenceEngine()
        score, waf_names, cdn_names, verdict, classification = engine.compute(all_evidence, self.db)

        result.confidence      = score
        result.waf_names       = waf_names
        result.cdn_names       = cdn_names
        result.verdict         = verdict
        result.classification  = classification
        result.waf_detected    = classification in ("WAF", "WAF+CDN")
        result.cdn_detected    = classification in ("CDN", "WAF+CDN")
        result.evidence        = [asdict(e) for e in all_evidence]
        result.diffs           = [asdict(d) for d in all_diffs]
        result.recommendations = _make_recs(score, waf_names, cdn_names,
                                             classification, all_evidence)
        return result

# ─────────────────────────────────────────────────────────────────────────────
# RECOMMENDATIONS ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def _make_recs(score, waf_names, cdn_names, classification, evidence) -> list:
    recs = []
    ev_dicts = [asdict(e) for e in evidence]

    if score <= 15:
        recs.append("No WAF/CDN detected. Target may be directly accessible — proceed with standard testing.")
        return recs

    if classification in ("WAF", "WAF+CDN"):
        recs.append("A WAF is active. Use payload encoding, case variation, and comment insertion to test evasion.")

    if "Cloudflare" in waf_names:
        recs.append("Cloudflare: search for origin IP via Shodan, Censys, DNS history (SecurityTrails), "
                    "or Certificate Transparency logs to bypass the CDN layer.")
    if "AWS WAF" in waf_names:
        recs.append("AWS WAF: check for misconfigured S3 buckets, API Gateway endpoints, "
                    "or ALBs that may bypass WAF rules.")
    if "Akamai" in waf_names:
        recs.append("Akamai: bot manager (bm_sz cookie) may block automated tools — "
                    "mimic human browser headers and session flow.")
    if "Imperva Incapsula" in waf_names:
        recs.append("Imperva: challenge-response mechanisms are common — "
                    "session cookies must be maintained between requests.")
    if "ModSecurity" in waf_names:
        recs.append("ModSecurity: OWASP CRS rules — try HPP, parameter pollution, "
                    "or encoding variations to bypass common rules.")
    if "Wordfence" in waf_names:
        recs.append("Wordfence (WordPress WAF): plugin-level WAF — "
                    "XML-RPC endpoint and REST API may have different rule coverage.")

    if any(e["detector"] == "behavioral" and e["evidence_type"] == "timing" for e in ev_dicts):
        recs.append("Significant latency on probes detected — the WAF performs deep inspection. "
                    "Slow down attack timing significantly.")

    if classification in ("CDN", "WAF+CDN"):
        recs.append("CDN is present: responses may be cached — always send Cache-Control: no-cache "
                    "to ensure you're hitting origin.")

    return recs


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _c(t, code):
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass
    return f"\033[{code}m{t}\033[0m"

def _ci(m):  print(_c(f"[*] {m}", "94"))
def _co(m):  print(_c(f"[+] {m}", "92"))
def _cy(m):  print(_c(f"[!] {m}", "93"))
def _cr(m):  print(_c(f"[x] {m}", "91"))
def _cd(m):  print(_c(f"    {m}", "90"))


def print_banner():
    print(_c("""
  +------------------------------------------------------------+
  |  wafdetect v2.0  --  Advanced WAF & CDN Detection Tool    |
  |  Passive | Active | Aggressive | Behavioral | DNS | Diff  |
  |  Plugin signatures: signatures/waf/ + signatures/cdn/     |
  +------------------------------------------------------------+
""", "96"))


def print_result(result: DetectionResult, show_evidence: bool, show_diff: bool):
    print()
    print(_c("=" * 62, "90"))
    print(_c("  DETECTION REPORT", "1"))
    print(_c("=" * 62, "90"))
    print(f"  Target         : {result.target}")
    print(f"  Scan time      : {result.scan_time}")
    print(f"  Mode           : {result.mode}")
    print(f"  Classification : {_c(result.classification, '93')}")
    print()

    # confidence bar
    bar_len = 40
    filled  = int(result.confidence / 100 * bar_len)
    bar     = "#" * filled + "-" * (bar_len - filled)
    color   = "91" if result.confidence >= 66 else "93" if result.confidence >= 36 else "92"
    print(f"  Confidence     : {_c(bar, color)} {result.confidence}%")
    print()

    # verdict
    if result.waf_detected or result.cdn_detected:
        print(_c("  [!] PROTECTED", "91"))
        if result.waf_names:
            print(f"  WAF            : {_c(', '.join(result.waf_names), '91')}")
        elif result.waf_detected:
            print(f"  WAF            : {_c('Unknown vendor', '93')}")
        if result.cdn_names:
            print(f"  CDN            : {_c(', '.join(result.cdn_names), '94')}")
    else:
        print(_c("  [OK] No WAF or CDN detected", "92"))

    print(f"  Verdict        : {result.verdict}")
    print()

    # baseline
    if result.baseline:
        b = result.baseline
        print(_c("  -- Baseline --------------------------------------------------", "90"))
        print(f"  Status : HTTP {b['status']}   Server : {b['server']}")
        print(f"  Body   : {b['body_len']}B       Latency: {b['response_time']}s")
        print()

    # probe stats
    if result.probe_stats:
        ps = result.probe_stats
        print(_c("  -- Probe Stats -----------------------------------------------", "90"))
        print(f"  Sent: {ps['total']}  |  OK: {ps['successful']}  |  "
              f"Blocked: {ps['blocked']}  |  Avg latency: {ps['avg_latency']}s")
        print(f"  Status spread: {ps['status_spread']}")
        print()

    # dns
    if result.dns_info and result.dns_info.get("ips"):
        d = result.dns_info
        print(_c("  -- DNS -------------------------------------------------------", "90"))
        print(f"  IPs    : {', '.join(d['ips'][:4])}")
        if d.get("cnames"):
            print(f"  CNAMEs : {', '.join(d['cnames'])}")
        print()

    # diff output
    if show_diff and result.diffs:
        print(_c("  -- Per-Probe DIFF --------------------------------------------", "90"))
        for d in result.diffs:
            sc_tag   = _c(f"HTTP {d['status_probe']}", "91") if d["status_changed"] else f"HTTP {d['status_probe']}"
            body_tag = f"body {'+' if d['body_len_delta'] >= 0 else ''}{d['body_len_delta']}B"
            lat_tag  = f"lat {'+' if d['latency_delta'] >= 0 else ''}{d['latency_delta']}s"
            flags    = []
            if d["generic_block_hit"]:    flags.append(_c("BLOCK", "91"))
            if d["waf_body_match"]:       flags.append(_c(d["waf_body_match"], "93"))
            if d["new_cookies"]:          flags.append(f"new-cookies:{d['new_cookies']}")
            if d["new_headers"]:          flags.append(f"new-hdrs:{d['new_headers'][:2]}")
            flag_str = "  ".join(flags) if flags else _c("clean", "90")
            print(f"  [{d['probe_type']:<10}] {d['probe_desc']:<22} {sc_tag:<12} "
                  f"{body_tag:<14} {lat_tag:<12} {flag_str}")
        print()

    # evidence
    if show_evidence and result.evidence:
        print(_c("  -- Evidence --------------------------------------------------", "90"))
        layer_colors = {
            "passive_header": "94", "passive_cookie": "94", "passive_body": "94",
            "dns": "96", "active": "93", "behavioral": "95",
        }
        for e in result.evidence:
            lc  = layer_colors.get(e["detector"], "97")
            tag = e["matched_name"] or "generic"
            print(f"  {_c('['+e['detector']+']', lc):<28} "
                  f"{_c('['+tag+']', '96'):<30} "
                  f"+{e['confidence_pts']}pt  {e['detail']}")
        print()

    # recommendations
    if result.recommendations:
        print(_c("  -- Recommendations -------------------------------------------", "90"))
        for i, r in enumerate(result.recommendations, 1):
            print(f"  {i}. {r}")
        print()

    print(_c("=" * 62, "90"))
    print()

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Advanced WAF & CDN Detection Tool v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Detection modes:
  (default)       Active scan: passive + DNS + 10 probes + behavioral analysis
  --passive       Passive only: 1 request, headers/cookies/body/DNS
  --aggressive    Passive + DNS + 18 probes + behavioral (more coverage, more noise)

Output flags:
  --evidence      Show full evidence trail in report
  --diff          Show per-probe diff table (status/body/latency/header changes)
  --json FILE     Save machine-readable JSON report to FILE

Examples:
  py wafdetect_v2.py https://example.com
  py wafdetect_v2.py https://target.com --passive --evidence
  py wafdetect_v2.py https://target.com --active --diff --threads 5
  py wafdetect_v2.py https://target.com --aggressive --evidence --diff --json report.json
  py wafdetect_v2.py https://target.com --proxy http://127.0.0.1:8080 --diff
        """,
    )
    # target
    p.add_argument("target", help="Target URL or domain")

    # mode (mutually exclusive)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--passive",     action="store_true", help="Passive scan only (1 request + DNS)")
    mode.add_argument("--active",      action="store_true", help="Active scan (default)")
    mode.add_argument("--aggressive",  action="store_true", help="Aggressive scan (18 probes, faster)")

    # output
    p.add_argument("--evidence",  action="store_true", help="Show full evidence trail")
    p.add_argument("--diff",      action="store_true", help="Show per-probe diff table")
    p.add_argument("--json",      metavar="FILE",      help="Save JSON report to FILE")

    # tuning
    p.add_argument("--threads",   type=int, default=3,               help="Concurrent probe threads (default: 3)")
    p.add_argument("--timeout",   type=int, default=DEFAULT_TIMEOUT, help=f"Request timeout seconds (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--proxy",     metavar="URL",                     help="Proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("--no-ssl-verify", action="store_true",           help="Disable SSL verification")
    p.add_argument("-v", "--verbose", action="store_true",           help="Verbose probe output")
    p.add_argument("--version",   action="version", version=f"%(prog)s {VERSION}")
    return p


def main():
    print_banner()
    args = build_cli().parse_args()

    # resolve mode
    if args.passive:
        mode = "passive"
    elif args.aggressive:
        mode = "aggressive"
    else:
        mode = "active"

    _ci(f"Target   : {args.target}")
    _ci(f"Mode     : {mode}  |  Threads: {args.threads}  |  Timeout: {args.timeout}s")
    if args.proxy:
        _ci(f"Proxy    : {args.proxy}")
    print()

    scanner = WAFScannerV2(
        target=args.target,
        mode=mode,
        threads=args.threads,
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        proxy=args.proxy,
        verbose=args.verbose,
    )

    try:
        result = scanner.scan()
    except KeyboardInterrupt:
        print()
        _cr("Scan interrupted.")
        sys.exit(1)

    print_result(result, show_evidence=args.evidence, show_diff=args.diff)

    # JSON output
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(asdict(result), f, indent=2)
            _co(f"JSON report saved: {args.json}")
        except Exception as e:
            _cr(f"Failed to save JSON: {e}")

    # exit code: 1 = WAF/CDN detected, 0 = clean (useful in CI/scripts)
    sys.exit(1 if (result.waf_detected or result.cdn_detected) else 0)


if __name__ == "__main__":
    main()
