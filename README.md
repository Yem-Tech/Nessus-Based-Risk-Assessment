# 🛡️ Nessus-Based Risk Assessment — halisans.com

> **Target:** `www.halisans.com` (IP: `66.29.153.49`)  
> **Tool:** Tenable Nessus Essentials  
> **Scan Policy:** Basic Network Scan | Severity Base: CVSS v3.0  
> **Environment:** Kali Linux | Authorized academic/lab assessment  
> **Date:** March 2026

---

## 📋 Table of Contents

- [Overview](#overview)
- [Methodology](#methodology)
- [1. Risk Identification — Nessus Scan Results](#1-risk-identification--nessus-scan-results)
- [2. Risk Scoring — CVSS v2.0 Analysis](#2-risk-scoring--cvss-v20-analysis)
  - [2.1 Finding V-01: SMTP Server Non-standard Port Detection](#21-finding-v-01-smtp-server-non-standard-port-detection)
  - [2.2 Finding V-02: SSL Certificate Cannot Be Trusted](#22-finding-v-02-ssl-certificate-cannot-be-trusted)
- [3. Risk Evaluation Against Risk Appetite](#3-risk-evaluation-against-risk-appetite)
- [4. Risk Heat Map](#4-risk-heat-map)
- [5. Risk Treatment Recommendations](#5-risk-treatment-recommendations)
- [6. SpiderFoot — Supplementary OSINT](#6-spiderfoot--supplementary-osint)
- [Appendix — Risk Register](#appendix--risk-register)
- [Disclaimer](#disclaimer)

---

## Overview

This report presents a structured risk assessment derived from a Nessus vulnerability scan conducted against `www.halisans.com`. The methodology follows a sequential process: risk identification from scan output, CVSS-based scoring, risk evaluation against appetite thresholds, heat map positioning, and treatment selection.

The goal is to translate technical vulnerability findings into business-relevant risk statements that support remediation planning and management decision-making.

---

## Methodology

| Stage | Purpose | Outcome |
|---|---|---|
| Risk Identification | Review Nessus findings and classify by severity and exposure | Initial risk register |
| Risk Scoring | Rate exploitability and impact using CVSS v2.0 | Comparable risk scores |
| Risk Evaluation | Compare scores to organizational risk appetite | Priority decisions |
| Risk Matrix Plotting | Position findings on a heat map | Visual prioritization |
| Risk Treatment | Select appropriate response per finding | Remediation plan |

**Scoring Formula:**  
`Risk Score = Exploitability Rating + Impact Rating`  
(Low = 1, Medium = 2, High = 3 → Score range: 2–6)

| Score | Risk Rating |
|---|---|
| 2 | Low |
| 3–4 | Medium |
| 5–6 | High |

---

## 1. Risk Identification — Nessus Scan Results

A Nessus Essentials vulnerability scan was executed against `www.halisans.com`. The scan returned **38 vulnerabilities** across the following severity distribution:

| Severity | Count |
|---|---|
| Medium | 1 |
| Info | 37 |

![Nessus Vulnerability List](screenshots/101-Nessus_vuln.png)

**Host Details confirmed by Nessus:**

| Field | Value |
|---|---|
| IP | `66.29.153.49` |
| DNS | `www.halisans.com` |
| OS | AIX 5.3 |
| Auth | N/A |

**Notable families identified:** Backdoors, General, DNS, FTP, Service Detection, Misc.

The two actionable findings identified beyond informational level are detailed in the sections below.

---

## 2. Risk Scoring — CVSS v2.0 Analysis

Each vulnerability was scored using the CVSS v2.0 calculator. The scores below reflect the Base Score, Impact Subscore, and Exploitability Subscore for each finding.

---

### 2.1 Finding V-01: SMTP Server Non-standard Port Detection

**Nessus Plugin:** `#18391` | **Family:** Backdoors | **Severity:** Medium  
**Affected Port:** `26/tcp` (SMTP on non-standard port)

![CVSS v2.0 Score — V-01](screenshots/001-Vulnerability_Calc_cvss2_0.png)

| CVSS v2.0 Metric | Value |
|---|---|
| Base Score | **5.0** |
| Impact Subscore | 2.9 |
| Exploitability Subscore | 10.0 |
| Temporal Score | N/A |
| Environmental Score | N/A |
| Overall CVSS Score | **5.0** |

**Description:**  
An SMTP server was detected running on a non-standard port (`26/tcp`). This configuration is flagged as a potential backdoor that could be used by attackers to relay spam or maintain covert command-and-control over a targeted machine.

**Nessus Output (Banner):**
```
Banner: 220-premium138.web-hosting.com ESMTP Exim 4.99.1 #2
220 We do not authorize the use of this system to transport unsolicited,
220 and/or bulk e-mail.
```

**Solution:** Review and clean the SMTP server configuration. Confirm whether port 26 is intentional and restrict access if not required.

**Risk Statement:**  
*Because an SMTP server is running on a non-standard port on `www.halisans.com`, there is a risk that an attacker could abuse this service to send unsolicited bulk email or use it as a covert communication channel, potentially leading to reputational damage and blacklisting of the mail infrastructure.*

---

### 2.2 Finding V-02: SSL Certificate Cannot Be Trusted

**Nessus Plugin:** `#51192` | **Family:** General | **Severity:** Medium  
**Affected Ports:** `443/tcp`, `2080/tcp`, `2078/tcp`, `2091/tcp` (www)

![CVSS v2.0 Score — V-02](screenshots/002-vuln_Calc_cvss2_0.png)

| CVSS v2.0 Metric | Value |
|---|---|
| Base Score | **6.4** |
| Impact Subscore | 4.9 |
| Exploitability Subscore | 10.0 |
| CVSS v3.0 Base Score | 6.5 |
| Overall CVSS Score | **6.4** |

**Description:**  
The server's X.509 certificate cannot be trusted. Nessus identified that the certificate chain sent by the host has **expired**, with the `Not After` date recorded as `Sep 16 21:59:59 2025 GMT`. This creates a broken chain of trust, making it easier for attackers to conduct man-in-the-middle attacks against users of the web service.

**Nessus Output:**
```
Subject   : CN=halisans.com
Not After : Sep 16 21:59:59 2025 GMT
```

**Affected Hosts:** `www.halisans.com` on ports 2080, 443, 2078, 2091

**Solution:** Renew and install a valid SSL/TLS certificate from a trusted Certificate Authority. Ensure the full certificate chain is correctly configured on the server.

**Risk Statement:**  
*Because the SSL certificate for `www.halisans.com` has expired and cannot be verified against a trusted CA, there is a risk that users may be exposed to man-in-the-middle attacks and that browsers will display trust warnings, leading to loss of user confidence and potential interception of sensitive data.*

![Nessus SSL Certificate Detail](screenshots/102-Nessus_SSL_Cert.png)

---

## 3. Risk Evaluation Against Risk Appetite

Each finding is evaluated against a standard risk appetite model:

| Risk Rating | Appetite Position | Required Action |
|---|---|---|
| Low (Score 2) | Within appetite | Accept, monitor, or address during routine hardening |
| Medium (Score 3–4) | Conditionally tolerable | Remediate within agreed timeline; track to closure |
| High (Score 5–6) | Above appetite | Escalate and treat immediately with clear ownership |

| Ref | Finding | CVSS Score | Risk Score | Appetite Position |
|---|---|---|---|---|
| V-01 | SMTP Non-standard Port | 5.0 | High (5) | ⚠️ Above appetite — treat immediately |
| V-02 | SSL Certificate Cannot Be Trusted | 6.4 | High (6) | ⚠️ Above appetite — treat immediately |

Both findings exceed the tolerable threshold and require priority remediation.

---

## 4. Risk Heat Map

Findings are positioned on the risk matrix using Probability (exploitability) versus Impact axes:

|  | **Low Impact** | **Medium Impact** | **High Impact** |
|---|---|---|---|
| **High Probability** | Medium | **High** | **High** |
| **Medium Probability** | Low | Medium | **High** |
| **Low Probability** | Low | Low | Medium |

| Ref | Finding | Probability | Impact | Matrix Position |
|---|---|---|---|---|
| V-01 | SMTP Non-standard Port | High (Exploitability: 10.0) | Low–Medium | **High** |
| V-02 | SSL Certificate Cannot Be Trusted | High (Exploitability: 10.0) | Medium | **High** |

Both findings plot in the **High** zone of the heat map, confirming immediate remediation priority.

---

## 5. Risk Treatment Recommendations

| Treatment | Description | When to Apply |
|---|---|---|
| **Mitigate** | Apply security controls or corrective actions | Patching, hardening, access restriction |
| **Accept** | Formally acknowledge within-appetite risk | Low findings with monitoring in place |
| **Transfer** | Shift impact to another party | Cyber insurance, managed security services |
| **Avoid** | Eliminate the condition creating the risk | Decommission unnecessary vulnerable services |

| Ref | Finding | Recommended Treatment | Action |
|---|---|---|---|
| V-01 | SMTP Non-standard Port Detection | **Mitigate** | Audit SMTP configuration; disable port 26 if not operationally required; restrict to authorized mail relays only |
| V-02 | SSL Certificate Cannot Be Trusted | **Mitigate** | Immediately renew the expired SSL/TLS certificate; ensure full chain installation and configure auto-renewal |

---

## 6. SpiderFoot — Supplementary OSINT

SpiderFoot was run in parallel to provide passive OSINT context for the target IP. The scan confirmed the following data types for the target:

![SpiderFoot Browse Results](screenshots/7-fscan_browse.png)

| Data Type | Unique Elements | Total Elements |
|---|---|---|
| IP Address | 1 | 1 |
| Open TCP Port | 6 | 6 |
| Open TCP Port Banner | 2 | 2 |
| Raw Data from RIRs/APIs | 1 | 1 |

> SpiderFoot independently confirmed 6 open TCP ports and captured 2 service banners, corroborating the Nessus port scan results and confirming external visibility of the target's network surface.

---

## Appendix — Risk Register

| Ref | Vulnerability / Asset | Severity | Exploitability | Impact | Score | Matrix Position | Treatment |
|---|---|---|---|---|---|---|---|
| V-01 | SMTP Non-standard Port / `www.halisans.com:26` | Medium | High | Medium | 5 — High | High / High | Mitigate immediately |
| V-02 | SSL Certificate Cannot Be Trusted / `www.halisans.com:443,2080,2078,2091` | Medium | High | Medium | 6 — High | High / Medium | Mitigate immediately |

---

## Disclaimer

> This assessment was conducted in an authorized lab/academic environment. All scanning activities were performed against systems within the defined and approved scope using Nessus Essentials. No exploitation, denial-of-service, or post-exploitation activity was conducted. This report is intended for educational and professional development purposes only.

