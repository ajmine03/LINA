# LINA Security Testing Methodology

LINA operates strictly under an evidence-driven, bounded assessment methodology.

---

## Assessment Phases

```
1. Scope Validation
       ↓
2. Passive Reconnaissance (DNS, Certificate Inspection)
       ↓
3. Non-Destructive Active Probing (HTTP Headers, Safe Port Discovery)
       ↓
4. Policy & Approval Gates (Operator sign-off on active checks)
       ↓
5. Evidence Analysis (Observation vs. Hypothesis Separation)
       ↓
6. Audit Logging & Reporting (Remediation Guidance)
```

### Phase 1: Scope Validation
- Validate target against IP/CIDR/domain whitelist.
- Refuse testing on any host outside explicit authorization.
- Guard against redirection hijacking.

### Phase 2: Passive Discovery
- Query DNS records (`A`, `AAAA`, `CNAME`, `PTR`).
- Inspect TLS/SSL certificates (`tls_check`) for expiry, weak protocols, or untrusted issuers.

### Phase 3: Non-Destructive Surface Probing
- Perform HTTP metadata analysis (`http_probe`) checking for missing defensive headers (HSTS, CSP, X-Frame-Options).
- If Nmap is available, run safe port enumeration limited to `--top-ports 100` with standard timing (`-T3`).
- Reject destructive flags, brute force, and exploit scripts.

### Phase 4: Policy & Safety Check
- Every proposed active command is screened by the Policy Engine.
- High-impact or active actions require operator interactive confirmation (`y/N`).

### Phase 5: Evidence Analysis
- Findings are substantiated by exact raw observations.
- Version banners are explicitly flagged as unverified indicators, not confirmed vulnerabilities.

### Phase 6: Reporting & Remediation
- Comprehensive Markdown and JSON reports are compiled in `reports/`.
- Every finding includes actionable defensive hardening instructions.
