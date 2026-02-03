# Policy-as-Code Analyzer

A Python-based Policy-as-Code security analysis tool that evaluates IAM style JSON policies for over-permissive access patterns and generates compliance-ready reports mapped to major security and regulatory frameworks.

This project demonstrates how security analysts and engineers can automate access reviews, enforce least privilege, and support audit and compliance requirements across regulated industries.

--- 

## What This Tool Does

The Policy-as-Code Analyzer:

- Parses IAM policy JSON files
- Identifies over-permissive access patterns, including:
  - Wildcard actions (`*`)
  - Wildcard resources (`Resource: *`)
  - Full service access (e.g., `ec2:*`)
- Assigns risk serverity based on access scope
- Generates a **CSV compliance report** suitable for audits and security reviews
-Maps findings to multiple industry frameworks:
   - **NIST SP 800-53**
   - **CIS Critical Secuirty Controls**
   -**HIPAA Security Rule**
   -**HITRUST CSF**

---

## Applicable Industries

This project is intentionally designed to be industry-agnostic and applicable to environments that require strong access controll, auditability, and compliance oversight, including:

- **Healthcare** (HIPAA, HITRUST, EPIC environments)
- **Finance and FinTech** (least privilege, access governance)
-**Education** (FERPA-aligned access control principles)
-**Government and Public Sector**
- **Cloud and SaaS Organizations**
- **Any regulated or audit-driven environment**

---

## Project Structure 

```text
policy-as-code-analyzer/
├─ scripts/
│  ├─ policy_parser.py        # Core policy analysis engine
│  └─ compliance_report.py    # Compliance & audit report generator
├─ sample_policies/
│  ├─ admin_policy.json
│  ├─ read_only_policy.json
│  └─ risky_policy.json
├─ reports/
│  └─ compliance_report.csv   # Generated output
└─ README.md

---

## How It Works

### 1. Policy Analysis

The analyzer normalizes IAM policy statements and evaluates them for:
- Excessive permissions
- Broad resource access
- Privilege escalation risk

### 2. Risk Identification

Each finding is categorized by:
- Issue Type
- Severity level
- Contextual policy details

### 3. Compliance Mapping

Findings are mapped to relevant controls across multiple frameworks to support:
- Security assessments
- Internal audits
- External compliance reviews

---

## How to Run the Project

### Prerequisites
- Python 3.10+
- PowerShell or terminal access

### Run the Policy Analyzer
py scripts\policy_parser.py

### Generate the Compliance Report 
py scripts\compliance_report.py

The generated CSV report will be saved to:
reports/compliance_report.csv

---

## Example Findings 

| policy_file           | issue               | severity | details                                                                    | nist_control              | cis_control                       | hipaa_control                                         | hitrust_control                    |
| --------------------- | ------------------- | -------- | -------------------------------------------------------------------------- | ------------------------- | --------------------------------- | ----------------------------------------------------- | ---------------------------------- |
| admin_policy.json     | Wildcard Action     | High     | "Effect=Allow, Actions=['*'], Resources=['*']"                             | AC-3 (Access Enforcement) | CIS 1.4 - Least Privilege         | Unmapped                                              | 01.b - Access Control Procedures   |
| admin_policy.json     | Wildcard Resource   | High     | "Effect=Allow, Actions=['*'], Resources=['*']"                             | AC-6 (Least Privilege)    | CIS 1.3 - Resource Access Control | 164.312(a)(1) - Access Control                        | 01.c - Least Privilege             |
| read_only_policy.json | Wildcard Resource   | High     | "Effect=Allow, Actions=['s3:GetObject', 's3:ListBucket'], Resources=['*']" | AC-6 (Least Privilege)    | CIS 1.3 - Resource Access Control | 164.312(a)(1) - Access Control                        | 01.c - Least Privilege             |
| risky_policy.json     | Wildcard Resource   | High     | "Effect=Allow, Actions=['ec2:*'], Resources=['*']"                         | AC-6 (Least Privilege)    | CIS 1.3 - Resource Access Control | 164.312(a)(1) - Access Control                        | 01.c - Least Privilege             |
| risky_policy.json     | Full Service Access | Medium   | "Effect=Allow, Action=ec2:*, Resources=['*']"                              | AC-6 (Least Privilege)    | CIS 1.4 - Privilege Restriction   | 164.308(a)(3)(ii)(B) - Workforce Access Authorization | 01.d - Privileged Access Management |

---

## Why This Project Matters

This project demonstrates:
- Practical Policy-as-Code implementation
- Cloud IAM security analysis
- Least privilege enforcement
- Compliance-aware security engineering
- Automation of audit-ready artifacts

It reflects real-world security tasks performed by:
-Cyber Security Analysts
-Cloud Security Analysts
-GRC and Compliance-focused security teams

---

## Future Enhancements

Planned improvements include:
- Risk scoring and prioritization
- Additional framework mappings (SOX, PCI DSS, FERPA)
- JSON schema validation and error handling
- Support for additional policy formats
- Visualization and dashboarding

---

Author

TiOnkaCyberSec
Cybersecurity | IAM | Cloud Security | Compliance Automation | ISC2 CC | Google Cybersecurity Certificate

---

Disclaimer 

This project is for educational and demonstration purposes and does not replace formal security assessments or audits.