# 🛡️ Shadow API Scanner

**Automated Shadow API Detection & Security Testing Tool for Single-Page Applications (SPAs)**

Detects undocumented (shadow) API endpoints in SPAs through static JavaScript analysis and dynamic traffic monitoring, then runs OWASP API Security Top 10 tests against them.

---

## ⚡ Quick Start

### Linux
```bash
# Setup (installs deps + Playwright)
./run.sh setup

# Scan a target
./run.sh run https://target-spa.com

# Or directly
./run.sh https://target-spa.com --verbose
```

### Windows
```cmd
REM Setup
run.bat setup

REM Scan a target
run.bat run https://target-spa.com
```

---

## 📋 Features

### Phase 1: Static JavaScript Analysis
- Crawls and downloads all frontend JS files (external + inline + webpack chunks)
- Extracts API endpoints via regex patterns (fetch, axios, XHR, WebSocket, GraphQL)
- Detects hardcoded API keys, tokens, and secrets
- Discovers base URLs, route patterns, and request configurations

### Phase 2: Dynamic Traffic Monitoring
- Launches headless Chromium via Playwright
- Captures live XHR/Fetch/WebSocket traffic
- Interacts with the page (scrolling, clicking nav) to trigger hidden APIs
- Compares against OpenAPI/Swagger specs (auto-discovered or user-provided)
- Identifies **shadow APIs** (undocumented endpoints)

### Phase 3: OWASP API Security Top 10 Testing
Tests each shadow endpoint for:
1. **BOLA** — Object ID manipulation (IDOR)
2. **Broken Auth** — Token removal/tampering
3. **Property-Level Auth** — Mass assignment, excessive data exposure
4. **Resource Consumption** — Rate limiting checks
5. **Function-Level Auth** — Method switching, admin path probing
6. **Sensitive Business Flows** — Anti-automation detection
7. **SSRF** — Internal URL injection
8. **Security Misconfiguration** — CORS, headers, error leaks
9. **Improper Inventory** — Old API versions, shadow documentation
10. **Unsafe Consumption** — SQL injection, XSS reflection

### Phase 4: Risk Scoring & Reporting
- Per-vulnerability risk scores (0-10) based on OWASP severity + exploit evidence
- Overall scan risk level (Critical/High/Medium/Low/Info)
- Reports in **JSON** (machine-readable) and **HTML** (visual dashboard)
- Proof-of-concept request/response pairs
- Remediation guidance per finding

---

## 🔧 CLI Options

```
Usage: shadow-scan [OPTIONS] TARGET_URL

Options:
  -o, --output TEXT       Output directory for reports [default: reports]
  --openapi-spec TEXT     Path or URL to OpenAPI spec file
  --auth-token TEXT       Authorization token (e.g., 'Bearer xxx')
  --auth-header TEXT      Auth header name [default: Authorization]
  --no-browser            Skip Phase 2 dynamic monitoring
  --no-fuzz               Skip fuzzing in Phase 3
  --headed                Show browser window (not headless)
  --timeout INTEGER       Browser timeout in seconds [default: 60]
  --concurrency INTEGER   Max concurrent test requests [default: 10]
  --format TEXT           Report formats: json,html [default: json,html]
  -v, --verbose           Verbose output
  --help                  Show this message and exit
```

---

## 🏗️ Build Standalone Binary

### Linux
```bash
./run.sh build
# Output: dist/shadow-scan
```

### Windows
```cmd
run.bat build
REM Output: dist\shadow-scan.exe
```

---

## 📁 Project Structure

```
shadow-api-scanner/
├── shadow_api_scanner/
│   ├── __init__.py          # Package metadata
│   ├── __main__.py          # python -m entry point
│   ├── cli.py               # CLI argument parsing + orchestration
│   ├── core/
│   │   ├── config.py        # OWASP categories, payloads, scan settings
│   │   └── models.py        # APIEndpoint, Vulnerability, ScanResult
│   ├── phase1/
│   │   ├── crawler.py       # JS file crawler (external + chunks)
│   │   ├── js_parser.py     # Regex-based API extraction from JS
│   │   └── static_analyzer.py  # Phase 1 orchestrator
│   ├── phase2/
│   │   ├── traffic_monitor.py  # Playwright network interception
│   │   ├── spec_comparator.py  # OpenAPI spec parsing + comparison
│   │   └── shadow_detector.py  # Shadow API classification
│   ├── phase3/
│   │   ├── fuzzer.py        # Fuzz payload generation
│   │   ├── owasp_tests.py   # All 10 OWASP test implementations
│   │   └── security_tester.py  # Phase 3 orchestrator
│   ├── phase4/
│   │   ├── risk_scorer.py   # Risk score calculation
│   │   └── report_generator.py  # JSON + HTML report output
│   └── utils/
│       ├── http_client.py   # Async httpx client with rate limiting
│       └── helpers.py       # URL normalization, logging, utilities
├── requirements.txt
├── setup.py
├── run.sh                   # Linux build/run script
└── run.bat                  # Windows build/run script
```

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Always obtain proper authorization before scanning any target. Unauthorized testing may violate laws. Use responsibly.
