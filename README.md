# AUTHRIFT

**Offensive API Authorization Differential Testing Framework**

AUTHRIFT is a security research tool for detecting authorization flaws in APIs through controlled differential testing. It compares how the same API request behaves when executed with different authorized test identities, surfacing potential BOLA/IDOR, horizontal/vertical privilege escalation, broken function-level authorization, and tenant isolation failures.

> **AUTHRIFT is intended only for systems the researcher owns or has explicit written authorization to test.** Do not use AUTHRIFT against systems without proper authorization.

## What AUTHRIFT Detects

- **BOLA / IDOR** — Actor B accessing objects owned by Actor A
- **Broken Function-Level Authorization** — Normal users accessing admin-only endpoints
- **Horizontal privilege escalation** — Cross-user data access at the same permission level
- **Vertical privilege escalation** — Lower-privilege users performing higher-privilege operations
- **Tenant isolation failures** — Cross-tenant data leakage
- **Object ownership bypass** — Accessing resources despite ownership checks
- **Session/authorization inconsistencies** — Unexpected response patterns under different sessions

## How It Works

```
1. Researcher provides HTTP requests + actor identities
2. AUTHRIFT detects object identifiers in URLs, query params, and request bodies
3. Controlled mutations are generated (session swap, object substitution, function-level)
4. Each mutation is replayed and the response is compared to the baseline
5. Differential analysis scores the likelihood of an authorization flaw
6. Findings are reported with full evidence for manual verification
```

AUTHRIFT does **not**:
- Blindly exploit targets
- Claim confirmed vulnerabilities (only candidates for manual verification)
- Run state-changing requests by default
- Bypass CAPTCHAs or authentication mechanisms
- Scan arbitrary Internet targets

## Architecture

```
authrift/
├── authrift/
│   ├── cli.py              # Typer CLI entry point
│   ├── config.py            # YAML config and scan settings
│   ├── models.py            # Pydantic data models
│   ├── parser/              # Request import (raw HTTP, cURL, HAR)
│   ├── actors/              # Actor/session management
│   ├── detection/           # Identifier detection, response diff, scoring
│   ├── engine/              # Mutation generation, HTTP replay, scan runner
│   ├── reporting/           # Markdown and JSON report generation
│   └── utils/               # Redaction, logging
├── tests/                   # pytest suite + intentionally vulnerable mock API
├── examples/                # Sample configs and requests
└── pyproject.toml
```

## Installation

Requires Python 3.12+.

```bash
git clone https://github.com/gustiakmal52/AUTHRIFT.git
cd AUTHRIFT
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick Start

### 1. Start the test target (mock API)

```bash
uvicorn tests.mock_api:app --port 9777
```

This starts a local API with two endpoint families:
- `/api/secure/orders/{id}` — properly validates ownership
- `/api/vulnerable/orders/{id}` — only validates authentication (intentionally flawed)

### 2. Create an actors config

```yaml
actors:
  user_a:
    headers:
      Authorization: "Bearer TOKEN_A"
    owned_objects:
      orders: "1001"

  user_b:
    headers:
      Authorization: "Bearer TOKEN_B"
    owned_objects:
      orders: "2001"
```

### 3. Create a request file

```http
GET /api/vulnerable/orders/1001 HTTP/1.1
Host: 127.0.0.1:9777
Authorization: Bearer TOKEN_A
###
GET /api/secure/orders/1001 HTTP/1.1
Host: 127.0.0.1:9777
Authorization: Bearer TOKEN_A
```

### 4. Run the scan

```bash
authrift test examples/requests.txt --actors examples/actors.yaml
```

### 5. Review reports

```bash
authrift report
cat reports/summary.md
```

## CLI Reference

```bash
authrift import requests.har
authrift test requests.txt --actors actors.yaml
authrift test traffic.har \
  --actors actors.yaml \
  --actor-a user_a \
  --actor-b user_b \
  --admin admin \
  --allow-state-changing \
  --max-requests 50 \
  --delay 100 \
  --timeout 15
authrift report
```

## Supported Import Formats

| Format | Extension | Source |
|--------|-----------|--------|
| Raw HTTP | `.txt`, `.http` | Manual or proxy export |
| cURL | `.txt` | Browser DevTools, Burp, Caido |
| HAR | `.har`, `.json` | Chrome DevTools, Burp, Caido |

## Differential Scoring Model

AUTHRIFT uses a transparent scoring system to classify potential findings:

| Signal | Points |
|--------|--------|
| Unauthorized actor receives 2xx | +30 |
| Substituted object ID appears in response | +20 |
| Sensitive fields present in response | +20 |
| JSON structure similarity ≥ 90% | +15 |
| Body similarity ≥ 90% | +10 |
| Owner field references another actor | +10 |
| Sanitized/minimal response (similarity < 20%) | −30 |
| Authorization error detected | −40 |
| Test response is 4xx/5xx | −10 |

### Confidence Levels

| Score Range | Classification |
|-------------|----------------|
| 0–29 | Low signal |
| 30–59 | Interesting |
| 60–79 | Likely authorization issue |
| 80–100 | High-confidence candidate |

These are **confidence scores**, not CVSS severity ratings. Every finding requires manual verification.

## Safety

AUTHRIFT defaults to safe operation:

- Only `GET`, `HEAD`, and `OPTIONS` requests run by default
- `POST`, `PUT`, `PATCH`, `DELETE` require `--allow-state-changing`
- Configurable `--max-requests`, `--delay`, `--timeout`, `--rate-limit`
- Credentials are automatically redacted in all reports
- No stealth, no CAPTCHA bypass, no credential attacks

## Threat Model

AUTHRIFT assumes:
- The researcher has explicit authorization to test the target
- Actor credentials are provided by the researcher (not brute-forced)
- The target is a researcher-controlled lab, a bug bounty program target, or an owned system
- All testing is conducted within the researcher's authorized scope

AUTHRIFT does **not** perform:
- Authentication attacks (credential stuffing, brute force)
- Network scanning or port scanning
- Denial of service
- Automatic destructive exploitation
- Any testing outside the configured target

## Running Tests

```bash
pytest -v
pytest tests/test_parser.py tests/test_identifiers.py tests/test_detection.py tests/test_redact.py -v
pytest tests/test_integration.py -v
```

## Roadmap

### v0.2
- OpenAPI/Swagger import
- GraphQL operation parsing
- Enhanced ID relationship discovery
- Burp Suite export improvements

### v0.3
- Role matrix testing
- Tenant boundary testing
- Session lifecycle testing
- Token revocation testing

### v0.4
- Local web dashboard (FastAPI)
- Finding review workflow
- AI-assisted candidate analysis (optional, deterministic engine remains the foundation)

## Limitations (v0.1)

- No OpenAPI or GraphQL support yet
- No automatic HAR session grouping
- Identity-marker configuration is recommended for precise session-isolation checks
- Report format is basic markdown — no interactive HTML
- Single-threaded request execution
- No persistent scan history (SQLite planned for v0.2)

## License

MIT — see [LICENSE](LICENSE).
