# 🔍 VulnHunter Lab

**VulnHunter Lab** is an intentionally vulnerable web application and CI/CD security testbed designed to demonstrate, detect, and remediate vulnerabilities aligned with the **OWASP Top 10**. It integrates **DevSecOps pipelines**, secure coding, tool evaluation,
and security automation workflows.

---

## 📌 Purpose

- Demonstrate OWASP Top 10 vulnerabilities through vulnerable-by-design routes
- Train developers on secure coding and vulnerability remediation
- Evaluate and integrate SAST, DAST, SCA, IaC, and secrets scanning tools
- Enable AppSec teams to test and tune security scanners in CI/CD pipelines
- Provide metrics and dashboards for security posture and maturity tracking

---

## 🧰 Tech Stack

- **Framework**: Flask (Python)
- **Containerization**: Docker, Docker Compose
- **CI/CD**: GitHub Actions
- **Security Tools**:
  - **SAST**: Semgrep
  - **DAST**: OWASP ZAP (headless)
  - **SCA**: Trivy (for OS and Python deps)
  - **Secrets Scanning**: Gitleaks
  - **IaC Scanning**: Checkov
- **Monitoring (WIP)**: Prometheus + Grafana

---

## 🔐 OWASP Top 10 Coverage (2021)

| ID         | Vulnerability                    | 
|------------|----------------------------------|
| A01:2021   | Broken Access Control            | 
| A02:2021   | Cryptographic Failures           | 
| A03:2021   | Injection (SQL, Command)         | 
| A04:2021   | Insecure Design                  | 
| A05:2021   | Security Misconfiguration        | 
| A06:2021   | Vulnerable & Outdated Components | 
| A07:2021   | Identification & Authentication  | 
| A08:2021   | Software & Data Integrity Failures | 
| A09:2021   | Security Logging & Monitoring    | 
| A10:2021   | SSRF                              | 
