# Nessus-Based Vulnerability Risk Assessment — halisans.com

**Domain:** `www.halisans.com` &nbsp;|&nbsp; **IP:** `66.29.153.49` &nbsp;|&nbsp; **OS Fingerprint:** AIX 5.3  
**Tool:** Tenable Nessus Essentials v10.11.3 &nbsp;|&nbsp; **Policy:** Basic Network Scan &nbsp;|&nbsp; **Severity Base:** CVSS v3.0  
**Platform:** Kali Linux &nbsp;|&nbsp; **Classification:** Authorized Academic Security Assessment &nbsp;|&nbsp; **Date:** March 2026

---

> This report translates Nessus scan output into a structured, governance-ready risk assessment following a five-stage methodology: identification → scoring → evaluation → heat map positioning → treatment. All findings are scored using CVSS v2.0 and evaluated against a defined risk appetite threshold.

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Assessment Overview](#assessment-overview)
- [1. Risk Identification — Nessus Scan Results](#1-risk-identification--nessus-scan-results)
- [2. Risk Scoring Methodology](#2-risk-scoring-methodology)
- [3. Validated Findings](#3-validated-findings)
  - [V-01 — SMTP Server Non-standard Port Detection](#v-01--smtp-server-non-standard-port-detection)
  - [V-02 — SSL Certificate Cannot Be Trusted](#v-02--ssl-certificate-cannot-be-trusted)
- [4. Risk Evaluation Against Risk Appetite](#4-risk-evaluation-against-risk-appetite)
- [5. Risk Heat Map](#5-risk-heat-map)
- [6. Risk Treatment Recommendations](#6-risk-treatment-recommendations)
- [Appendix — Risk Register](#appendix--risk-register)
- [Screenshot Index](#screenshot-index)
- [Disclaimer](#disclaimer)

---

## Executive Summary

This assessment presents a structured risk analysis derived from a Nessus Essentials vulnerability scan conducted against `www.halisans.com`. The scan returned **38 findings** across one actionable severity tier (Medium) and 37 informational items. Two vulnerabilities were escalated for formal risk scoring and treatment planning based on their exploitability profile and potential business impact.

Both escalated findings — an SMTP service operating on a non-standard port and an expired SSL/TLS certificate — score in the **High** tier under the analyst-defined risk scoring model and plot in the high-priority zone of the risk heat map. Neither falls within the organization's assumed risk appetite. Immediate remediation is recommended.

The assessment follows a five-stage process aligned with standard risk management practice: identification, scoring, evaluation, matrix positioning, and treatment selection.

---

## Assessment Overview

| Field | Detail |
|---|---|
| Prepared For | Hypertechai |
| Prepared By | Olayemi |
| Assessment Basis | Nessus Essentials vulnerability scan output and analyst-led CVSS v2.0 risk scoring |
| Target Host | `www.halisans.com` — `66.29.153.49` |
| OS (Nessus Fingerprint) | AIX 5.3 |
| Scan Policy | Basic Network Scan |
| Severity Base | CVSS v3.0 (Nessus) / CVSS v2.0 (analyst scoring) |
| Scanner | Local Scanner — Nessus Essentials v10.11.3 |
| Total Vulnerabilities Found | 38 (1 Medium, 37 Informational) |
| Findings Escalated for Scoring | 2 |
| Auth Status | Unauthenticated |

### Methodology at a Glance

| Stage | Purpose | Output |
|---|---|---|
| Risk Identification | Classify Nessus findings by severity and exposure context | Initial finding inventory |
| Risk Scoring | Apply CVSS v2.0 exploitability and impact ratings | Comparable risk scores per finding |
| Risk Evaluation | Benchmark scores against organizational risk appetite | Accept / Escalate decisions |
| Risk Matrix Plotting | Position findings on a probability × impact heat map | Visual prioritization |
| Risk Treatment | Assign a treatment option to each escalated finding | Remediation plan with ownership |

---

## 1. Risk Identification — Nessus Scan Results

The Nessus scan was executed against `www.halisans.com` using a Basic Network Scan policy. The scan returned 38 total vulnerability records. Risk identification began by classifying findings according to Nessus severity and evaluating each for potential business relevance beyond the technical CVSS rating alone.

![Nessus Vulnerability List — 38 Findings](screenshots/101-Nessus_vuln.png)

**Scan Severity Distribution:**

| Severity | Count | Action |
|---|---|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 1 | Escalated for scoring |
| Low | 0 | — |
| Informational | 37 | Logged; not escalated |

**Host Context:**

| Attribute | Value |
|---|---|
| IP Address | `66.29.153.49` |
| Hostname | `www.halisans.com` |
| OS (Nessus) | AIX 5.3 |
| Scan Start | Today at 10:55 AM |
| Authentication | N/A (unauthenticated scan) |

**Families detected:** Backdoors, General, DNS, FTP, Service Detection, Misc.

> **Analyst Note:** Nessus severity ratings indicate technical seriousness but do not independently reflect organizational risk. Both escalated findings were re-evaluated through CVSS v2.0 scoring to produce business-contextualised risk ratings. Informational findings were reviewed and determined to fall within acceptable thresholds for this assessment scope.

---

## 2. Risk Scoring Methodology

Each escalated finding was scored across two dimensions — **Exploitability** and **Impact** — using a three-point scale. The composite score determines the risk rating and drives heat map placement and treatment selection.

**Scoring Scale:**

| Factor | Low (1) | Medium (2) | High (3) |
|---|---|---|---|
| Exploitability | Difficult to exploit; requires rare conditions or significant attacker capability | Exploitable with moderate effort or partial access | Straightforward; publicly documented or readily weaponizable |
| Impact | Minor operational effect or limited business consequence | Noticeable service, integrity, or confidentiality impact | Major disruption, data exposure, or compromise of critical assets |

**Formula:** `Risk Score = Exploitability Rating + Impact Rating`

| Composite Score | Risk Rating |
|---|---|
| 2 | Low |
| 3 – 4 | Medium |
| 5 – 6 | High |

CVSS v2.0 was used as the scoring framework, with calculator outputs recorded as evidence for each finding.

---

## 3. Validated Findings

### V-01 — SMTP Server Non-standard Port Detection

**Nessus Plugin:** `#18391` &nbsp;|&nbsp; **Family:** Backdoors &nbsp;|&nbsp; **Severity:** Medium  
**Affected Host:** `www.halisans.com` &nbsp;|&nbsp; **Affected Port:** `26/tcp` (SMTP on non-standard port)  
**CVSS v2.0 Vector:** `CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N`

![CVSS v2.0 Score — V-01 (Score: 5.0)](screenshots/001-Vulnerability_Calc_cvss2_0.png)

**CVSS v2.0 Score Breakdown:**

| Metric | Value |
|---|---|
| Base Score | **5.0** |
| Impact Subscore | 2.9 |
| Exploitability Subscore | 10.0 |
| Temporal Score | N/A |
| Environmental Score | N/A |
| **Overall CVSS Score** | **5.0 — Medium** |

**Technical Description:**  
An SMTP server is operating on port `26/tcp`, which is not a standard SMTP port. Nessus classifies this under the Backdoors family, flagging the configuration as a potential covert channel that could be used by an attacker to relay spam, bypass email filtering, or maintain persistent unauthorized access to a target system.

**Nessus Plugin Output:**
```
Banner : 220-premium138.web-hosting.com ESMTP Exim 4.99.1 #2 Tue, 24 Mar 2026 11:58:30 -0400
         220-We do not authorize the use of this system to transport unsolicited,
         220 and/or bulk e-mail.
Affected Port: 26/tcp — www.halisans.com
```

**Risk Statement:**  
*Because an SMTP service is running on a non-standard port (`26/tcp`) on `www.halisans.com`, there is a risk that an attacker could exploit this configuration to relay unsolicited email or use the channel for covert command-and-control communication, potentially resulting in IP blacklisting, reputational damage to the mail infrastructure, and loss of email deliverability.*

**Recommended Solution:** Audit the SMTP server configuration. If port 26 is not operationally required, disable it immediately. If required, enforce strict access controls and restrict relay permissions to authorized hosts only. Review Exim version for known CVEs.

**Reference:** [http://www.icir.org/vern/papers/backdoor/](http://www.icir.org/vern/papers/backdoor/)

---

### V-02 — SSL Certificate Cannot Be Trusted

**Nessus Plugin:** `#51192` &nbsp;|&nbsp; **Family:** General &nbsp;|&nbsp; **Severity:** Medium  
**Affected Host:** `www.halisans.com` &nbsp;|&nbsp; **Affected Ports:** `443/tcp`, `2080/tcp`, `2078/tcp`, `2091/tcp`  
**CVSS v3.0 Vector:** `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`

![CVSS v2.0 Score — V-02 (Score: 6.4)](screenshots/002-vuln_Calc_cvss2_0.png)

**CVSS Score Breakdown:**

| Metric | Value |
|---|---|
| CVSS v2.0 Base Score | **6.4** |
| Impact Subscore | 4.9 |
| Exploitability Subscore | 10.0 |
| CVSS v3.0 Base Score | **6.5** |
| **Overall CVSS Score** | **6.4 (v2.0) / 6.5 (v3.0) — Medium** |

**Technical Description:**  
The X.509 SSL/TLS certificate presented by `www.halisans.com` cannot be trusted. Nessus identified that the certificate chain **has expired**, with the `Not After` validity date recorded as `Sep 16 21:59:59 2025 GMT`. An expired certificate breaks the chain of trust between the server and connecting clients, removing a critical authentication control and significantly increasing the viability of man-in-the-middle (MitM) attacks against web application users.

**Nessus Plugin Output:**
```
The following certificate was part of the certificate chain
sent by the remote host, but it has expired:

|-Subject  : CN=halisans.com
|-Not After : Sep 16 21:59:59 2025 GMT

Affected Ports / Hosts:
  2080 / tcp / www  →  www.halisans.com
   443 / tcp / www  →  www.halisans.com
  2078 / tcp / www  →  www.halisans.com
  2091 / tcp / www  →  www.halisans.com
```

![Nessus SSL Certificate Detail — Plugin #51192](screenshots/102-Nessus_SSL_Cert.png)

**Risk Statement:**  
*Because the SSL/TLS certificate for `www.halisans.com` has expired and is no longer validated by a trusted Certificate Authority, there is a risk that users connecting over HTTPS on ports 443, 2080, 2078, and 2091 are exposed to man-in-the-middle interception of session data, credentials, and sensitive communications. Browser trust warnings will additionally erode end-user confidence and may cause service abandonment.*

**Recommended Solution:** Immediately renew the SSL/TLS certificate from a trusted Certificate Authority. Ensure the complete certificate chain — including intermediate certificates — is correctly installed on the server. Implement automated certificate renewal (e.g., via Let's Encrypt / ACME protocol) to prevent future expiry-related lapses.

**References:**  
- [https://www.itu.int/rec/T-REC-X.509/en](https://www.itu.int/rec/T-REC-X.509/en)  
- [https://en.wikipedia.org/wiki/X.509](https://en.wikipedia.org/wiki/X.509)

---

## 4. Risk Evaluation Against Risk Appetite

Risk evaluation benchmarks each finding's composite score against the assumed organizational risk appetite. The model below reflects standard practice: Low findings are within appetite, Medium findings are conditionally tolerable pending a remediation commitment, and High findings exceed appetite and require immediate escalation.

**Risk Appetite Model:**

| Risk Rating | Appetite Position | Required Action |
|---|---|---|
| Low (Score 2) | Within appetite | Accept or address during routine hardening cycles |
| Medium (Score 3–4) | Conditionally tolerable | Remediate within an agreed timeline; track to verified closure |
| High (Score 5–6) | Above appetite | Escalate immediately; assign ownership and enforce a remediation deadline |

**Evaluation Summary:**

| Ref | Finding | CVSS Score | Composite Score | Risk Rating | Appetite Position |
|---|---|---|---|---|---|
| V-01 | SMTP Non-standard Port Detection | 5.0 (v2.0) | 5 — High | 🔴 High | Above appetite — escalate immediately |
| V-02 | SSL Certificate Cannot Be Trusted | 6.4 (v2.0) / 6.5 (v3.0) | 6 — High | 🔴 High | Above appetite — escalate immediately |

Both findings exceed the tolerable risk threshold. Neither should be deferred to a routine patching cycle without documented risk acceptance from a senior stakeholder.

---

## 5. Risk Heat Map

Findings are positioned on a 3×3 probability × impact risk matrix. Probability is informed by the CVSS Exploitability Subscore and the public availability of exploit techniques. Impact reflects the assessed business consequence of successful exploitation.

**Risk Matrix:**

| | **Low Impact** | **Medium Impact** | **High Impact** |
|---|---|---|---|
| **High Probability** | 🟡 Medium | 🔴 **High** | 🔴 **High** |
| **Medium Probability** | 🟢 Low | 🟡 Medium | 🔴 **High** |
| **Low Probability** | 🟢 Low | 🟢 Low | 🟡 Medium |

**Finding Placement:**

| Ref | Finding | Probability Basis | Impact Basis | Matrix Cell |
|---|---|---|---|---|
| V-01 | SMTP Non-standard Port | High — Exploitability Subscore: 10.0; no authentication required | Medium — integrity and reputational impact via mail relay abuse | 🔴 **High** |
| V-02 | SSL Certificate Cannot Be Trusted | High — Exploitability Subscore: 10.0; network-adjacent, no auth | Medium — confidentiality and integrity risk via MitM; user trust erosion | 🔴 **High** |

Both findings occupy the **High** cell (High Probability × Medium Impact), confirming immediate remediation priority.

---

## 6. Risk Treatment Recommendations

**Treatment Options Reference:**

| Option | Description | Typical Application |
|---|---|---|
| **Mitigate** | Apply security controls or corrective actions to reduce the risk | Patching, configuration hardening, certificate renewal, port restriction |
| **Accept** | Formally acknowledge the risk when within appetite, with documented rationale | Low findings with compensating controls and active monitoring |
| **Transfer** | Shift impact to a third party | Cyber insurance, managed security services, contractual allocation |
| **Avoid** | Eliminate the activity or condition generating the risk | Decommission unsupported services; disable unnecessary protocols |

**Treatment Assignments:**

| Ref | Finding | Treatment | Recommended Action | Priority |
|---|---|---|---|---|
| V-01 | SMTP Non-standard Port Detection | **Mitigate / Avoid** | Audit the SMTP configuration on port 26. If not operationally required, disable the listener. If required, restrict relay to authorized hosts and enforce SMTP AUTH. Review Exim 4.99.1 for known vulnerabilities. | Immediate |
| V-02 | SSL Certificate Cannot Be Trusted | **Mitigate** | Renew the expired SSL/TLS certificate immediately across all affected ports (443, 2080, 2078, 2091). Verify the full certificate chain is correctly installed. Implement automated renewal via ACME/Let's Encrypt to prevent recurrence. | Immediate |

> **Analyst Recommendation:** Both findings should be assigned a named owner with a remediation deadline not to exceed 14 days from the date of this report. Closure should be verified through a rescan or independent validation rather than assumed from a change ticket alone.

---

## Appendix — Risk Register

| Ref | Vulnerability | Nessus Plugin | Severity | Affected Service | Exploitability | Impact | Score | Rating | Matrix | Treatment |
|---|---|---|---|---|---|---|---|---|---|---|
| V-01 | SMTP Non-standard Port Detection | #18391 | Medium | `26/tcp` — SMTP | High (3) | Medium (2) | 5 | 🔴 High | High Prob × Med Impact | Mitigate / Avoid |
| V-02 | SSL Certificate Cannot Be Trusted | #51192 | Medium | `443, 2080, 2078, 2091/tcp` — HTTPS | High (3) | Medium (2) | 6 | 🔴 High | High Prob × Med Impact | Mitigate |

---

## Screenshot Index

| File | Contents | Used In |
|---|---|---|
| `101-Nessus_vuln.png` | Nessus vulnerability list — 38 findings for www.halisans.com | Section 1 |
| `001-Vulnerability_Calc_cvss2_0.png` | CVSS v2.0 calculator — V-01 score: 5.0 | Section 3 / V-01 |
| `002-vuln_Calc_cvss2_0.png` | CVSS v2.0 calculator — V-02 score: 6.4 | Section 3 / V-02 |
| `102-Nessus_SSL_Cert.png` | Nessus Plugin #51192 detail — expired certificate output | Section 3 / V-02 |

**Screenshots excluded from this report (administrative / pre-scan / duplicate):**

| File | Reason Excluded |
|---|---|
| `12-Nessus_essentials_welcome.png` / `_-_Copy` | Empty "My Scans" folder — no findings present |
| `12-Nessus_vuln_scan.png` / `_-_Copy` | Scan listed but not yet executed (Last Scanned: N/A) |
| `12-Nessus_vuln_scanning.png` / `_-_Copy` | Scan in progress — no results available |
| `12-Nessus_Vuln_Scan_result.png` / `_-_Copy` | Duplicate of `101-Nessus_vuln.png` |
| `102-Nessus_ssl_cert_.png` | Duplicate of `102-Nessus_SSL_Cert.png` |

---

## Disclaimer

This assessment was conducted in an authorized academic and laboratory environment. All scanning and analysis activities were performed against systems within the explicitly defined and approved assessment scope using Tenable Nessus Essentials. No exploitation, privilege escalation, denial-of-service, or post-exploitation activity was conducted or attempted. This report is produced solely for educational and professional development purposes and does not constitute a formal penetration test or a complete enterprise security audit.

---

**Repository:** `nessus-risk-assessment-halisans`  
**GitHub Description:** `Nessus Essentials vulnerability scan and CVSS v2.0 risk assessment of www.halisans.com — covering risk identification, scoring, heat map analysis, and treatment recommendations.`  
**Topics:** `nessus` `vulnerability-assessment` `cvss` `risk-assessment` `tenable` `kali-linux` `cybersecurity` `ethical-hacking` `infosec` `penetration-testing`

