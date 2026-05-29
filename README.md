# HeaderShield

> Lightweight security header audit engine. Maps missing HTTP hardening configurations to exploitable risk paths — with redirect-aware evaluation and confidence-calibrated findings.

Built for security engineers, DevOps teams, and infrastructure operators who need fast, reproducible posture checks without deploying heavy scanners.

---

## Who This Is For

| Role | Use Case |
|---|---|
| **Security Engineers** | Quick external posture assessment before deeper testing. Redirect-aware evaluation prevents false positives on modern web stacks. |
| **DevOps / SRE** | Validate deployment hardening in CI/CD pipelines. Confidence scoring tells you which findings need immediate attention vs. further investigation. |
| **Bug Bounty Hunters** | Passive reconnaissance — find low-hanging misconfigurations fast, with calibrated severity that won't waste your time on ambiguous redirects. |
| **Startup CTOs** | Audit vendor or own infrastructure without security team overhead. Get audit-grade reports you can share with stakeholders. |
| **Security Consultants** | Generate structured, evidence-backed audit reports for client delivery. Every finding includes reproducibility artifacts. |

If you need a full DAST suite, use OWASP ZAP or Burp Suite. If you need a focused, fast, and accurate header audit that understands modern redirect chains, use this.

---

## What It Detects

| Missing / Weak Header | Exploitable Risk Path |
|---|---|
| `Strict-Transport-Security` | SSL stripping / downgrade attack |
| `Content-Security-Policy` | XSS injection surface |
| `X-Frame-Options` | Clickjacking |
| `X-Content-Type-Options` | MIME sniffing attack |
| `Referrer-Policy` | Session data leakage via referrer |
| `Permissions-Policy` | Unwanted browser feature abuse |
| `Server` (exposed version) | Information disclosure |

Output includes: severity classification (P0–P3), confidence scoring (HIGH/MEDIUM/LOW), risk path mapping, evidence capture, and copy-paste remediation.

---

## Why HeaderShield Is Different

### Redirect-Aware Evaluation

Most header scanners check only the final response. HeaderShield inspects the **entire redirect chain**, merges headers across hops, and applies sticky rules (HSTS from any hop applies to the whole domain). This prevents false negatives on modern architectures that redirect before serving content.

### Confidence-Calibrated Findings

Not all findings are equal. HeaderShield assigns confidence levels:

| Confidence | Meaning |
|---|---|
| **HIGH** | Direct scan, no redirects. Finding is definitive. |
| **MEDIUM** | Redirect chain detected. Missing header may exist on intermediate hop. Severity downgraded one level. |
| **LOW** | Scan error or incomplete response. Finding requires manual verification. |

### Measured Risk Language

Security engineers trust calibrated output. HeaderShield avoids dramatic warnings. Instead:

- Missing headers after redirects: "not found in final response; may exist on intermediate hop"
- Weak values: "present but misconfigured" with exact raw value shown
- Correct headers: "correctly configured" with no risk paths assigned

---

## Real-World Example: Vercel.com

```bash
$ headershield scan https://vercel.com
Scanning: https://vercel.com
Analyzing headers...
Finding: outputs/findings/vercel.com.json
Evidence: outputs/findings/vercel.com_evidence.json
Report: outputs/reports/vercel.com_audit.md

Scan Complete: https://vercel.com
   Issues: 3 | Score: 7
   P0: 0 | P1: 0 | P2: 2 | P3: 1

Active Risk Paths:
   - Session data leakage via referrer
   - Unwanted browser feature abuse possible
   - Information disclosure via server metadata
```

Vercel is a well-hardened platform. HeaderShield found **3 real gaps**, **0 false alarms**, and correctly calibrated severity to MEDIUM/LOW because the base posture is strong. No dramatic warnings. Just measured, actionable findings.

**Full report:** See `outputs/reports/vercel.com_audit.md` after running the scan.

---

## Install

```bash
git clone https://github.com/EmmanuelAdesina/headershield.git
cd headershield
pip install -r requirements.txt
pip install -e .
```

Requires Python 3.8+.

---

## Quick Start

### Single Target

```bash
headershield scan https://example.com
```

### With Report

```bash
headershield scan https://example.com
```

Generates `outputs/reports/example.com_audit.md` — full audit report with redirect chain table, confidence levels, and remediation steps.

### Batch Scan

Create `targets.csv`:
```csv
url
https://example.com
https://another-site.com
```

```bash
headershield batch targets.csv
```

Outputs individual JSON findings + `_batch_summary.json` + `_batch_report.md`.

---

## Output Formats

### JSON (machine-readable, timestamped, reproducible)

```json
{
  "url": "https://vercel.com",
  "status_code": 200,
  "timestamp": "2026-05-29 21:18:26 UTC",
  "redirect_count": 0,
  "severity_score": 7,
  "issue_counts": {
    "critical": 0,
    "high": 0,
    "medium": 2,
    "low": 1,
    "total": 3
  },
  "active_risk_paths": {
    "Session data leakage via referrer": 1,
    "Unwanted browser feature abuse possible": 1,
    "Information disclosure via server metadata": 1
  },
  "findings": [...]
}
```

### Markdown (human-readable, audit-grade)

- Executive summary with redirect awareness
- Per-finding detail with confidence levels
- Redirect chain table (if applicable)
- Active risk paths
- Copy-paste remediation
- Evidence and reproducibility curl command

---

## Methodology

HeaderShield operates on a **passive audit model** with three trust layers:

1. **Extraction** — HTTP GET with full redirect chain capture. Headers merged across hops with sticky rules.
2. **Analysis** — Rule-based evaluation with confidence scoring and severity calibration. Redirects trigger automatic downgrades.
3. **Reporting** — Structured output with evidence, reproducibility, and measured language.

No active exploitation. No payload injection. Safe for production endpoints.

---

## Architecture

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for system design, data flow, and component breakdown.

**Core layers:**
- `scanner/` — Raw data extraction only
- `analyzer/` — Judgment, risk mapping, confidence scoring
- `evidence/` — Reproducibility artifacts
- `reports/` — Audit-grade output

---

## Sample Reports

Run against any URL to generate your own. Example reports are stored in `outputs/reports/` after scanning.

---

## Roadmap

| Version | Feature |
|---|---|
| v2.1 | ✅ Redirect-aware evaluation, confidence scoring, calibrated severity |
| v2.2 | Framework / CDN detection for context-aware scoring |
| v2.3 | Trend analysis across batch scans |
| v3.0 | Comparative reporting and industry benchmarking |

---

## Contributing

This is a security research and audit tool. Use responsibly and only against targets you have permission to scan.

---

## License

MIT
