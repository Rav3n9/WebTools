# WAF00

WAF00 is a lightweight Python tool for identifying Web Application Firewalls (WAFs). It combines passive fingerprinting with active probing to improve detection accuracy while showing the evidence behind each result instead of simply guessing.

Instead of relying only on static signatures, waf00 compares how a target responds to normal and suspicious requests, making it useful for identifying both well-known WAFs and custom filtering behavior.


> Built for penetration testers, bug bounty hunters, and security researchers.

---

## Features

- Passive mode (only one request)
- Active probing with built-in rate limiting
- Aggressive mode for higher confidence
- Evidence-based detections
- Response comparison (`--diff`)
- JSON output for automation
- Proxy support (Burp Suite, ZAP, etc.)
- Simple command-line interface

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Rav3n9/WebTools/WAF00.git
cd WebTools/WAF00
```

Install the required packages:

```bash
pip install -r requirements.txt
```

---

## Examples

### Passive scan

Only sends a single request.

```bash
py waf00.py https://target.com --passive --evidence
```

### Active scan

Uses multiple probes to increase detection accuracy.

```bash
py waf00.py https://target.com --diff --evidence
```

### Aggressive mode

Runs additional probes to gather more evidence.

```bash
py waf00.py https://target.com --aggressive --diff --evidence
```

### Save results as JSON

```bash
py waf00.py https://target.com --evidence --json report.json
```

### Send traffic through Burp Suite

```bash
py waf00.py https://target.com --proxy http://127.0.0.1:8080 --diff
```

---

## Options

| Option | Description |
|--------|-------------|
| `--passive` | Perform passive detection with a single request |
| `--aggressive` | Use additional probes for better confidence |
| `--diff` | Compare responses between requests |
| `--evidence` | Show why a WAF was detected |
| `--json FILE` | Save results as JSON |
| `--proxy URL` | Route traffic through a proxy |

---

## Why waf00?

Signature-based detection is fast, but modern WAF deployments are often customized or sit behind CDNs, making identification more difficult.

waf00 combines traditional fingerprinting with behavioral analysis and evidence-based scoring to provide more transparent results. Rather than simply reporting a possible vendor, it shows the indicators that contributed to the detection, making the output easier to validate and investigate.

---

## Disclaimer

Only use this tool against systems you own or have permission to test. The author is not responsible for any misuse.

GG
