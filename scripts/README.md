# SecOps - Security Operations Scripts

Comprehensive security operations tools for vulnerability scanning, compliance checking, incident response, and threat intelligence. Based on authoritative frameworks from OWASP, NIST, CIS, and MITRE.

## 📋 Table of Contents

- [Overview](#overview)
- [Scripts](#scripts)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Documentation](#detailed-documentation)
- [Compliance Frameworks](#compliance-frameworks)
- [References](#references)

---

## 🎯 Overview

This collection includes enterprise-grade security operations scripts for:

- **Vulnerability Scanning** - SAST, DAST, SCA, and Infrastructure security scanning
- **Compliance Checking** - Automated compliance for NIST CSF, CIS Controls, PCI-DSS, HIPAA
- **Incident Response** - Automated IR workflows based on CIS Control 17
- **Threat Intelligence** - IOC scanning, MITRE ATT&CK integration, STIX/TAXII feeds

All scripts generate detailed reports and follow industry best practices from OWASP, NIST, CIS, and MITRE.

---

## 📁 Scripts

### 1. vulnerability-scanner.py

Comprehensive vulnerability scanner implementing OWASP and NIST best practices for security testing.

**Capabilities:**
- **SAST** (Static Application Security Testing) using Bandit for Python code
- **SCA** (Software Composition Analysis) using Safety for dependency vulnerabilities
- **IaC Security** using Checkov for Terraform, Kubernetes, Docker configurations
- **Network Scanning** using Nmap for port and service discovery
- **Secrets Detection** for hardcoded credentials and API keys

**Based on:**
- OWASP Web Security Testing Guide (WSTG)
- OWASP Vulnerability Scanning Tools
- NIST CSF Detect (DE.CM)

**Usage:**
```bash
# Scan Python code for security vulnerabilities
python vulnerability-scanner.py --code-path /path/to/code --scan-code

# Scan dependencies for known vulnerabilities
python vulnerability-scanner.py --requirements requirements.txt --scan-dependencies

# Scan infrastructure as code
python vulnerability-scanner.py --iac-path /path/to/terraform --scan-iac

# Run all applicable scans
python vulnerability-scanner.py --code-path /path/to/code --all

# Network port scan
python vulnerability-scanner.py --network-target 192.168.1.100 --scan-network
```

**Output:**
- HTML report with vulnerability findings by severity
- JSON report for programmatic access
- Individual scan results from each tool

---

### 2. compliance-framework-checker.py

Automated compliance checking for multiple security frameworks and standards.

**Supported Frameworks:**
- **NIST Cybersecurity Framework 2.0** - Identify, Protect, Detect, Respond, Recover
- **CIS Critical Security Controls v8** - 18 critical security controls
- **PCI-DSS v4.0** - Payment Card Industry Data Security Standard
- **HIPAA** (planned) - Healthcare data protection requirements

**Controls Checked:**
- Asset inventory and management
- Access control and authentication
- Data encryption (at rest and in transit)
- Network security controls
- Audit logging and monitoring
- Incident response capabilities
- Disaster recovery planning

**Usage:**
```bash
# Check NIST Cybersecurity Framework compliance
python compliance-framework-checker.py --framework NIST

# Check CIS Controls compliance
python compliance-framework-checker.py --framework CIS

# Check PCI-DSS compliance
python compliance-framework-checker.py --framework PCI-DSS

# Check all frameworks
python compliance-framework-checker.py --framework ALL
```

**Output:**
- Compliance rate percentage
- Pass/Fail status for each control
- Recommendations for non-compliant controls
- HTML and JSON reports

---

### 3. incident-responder.py

Automated incident response tool implementing CIS Control 17 and NIST CSF Respond function.

**Incident Response Lifecycle:**
1. **Detection & Analysis** - Collect system information and analyze incident
2. **Containment** - Isolate and contain the threat
3. **Eradication** - Remove malicious artifacts
4. **Recovery** - Restore systems to normal operations
5. **Post-Incident Analysis** - Lessons learned and improvements

**Supported Incident Types:**
- **Malware** - Virus, trojan, ransomware infections
- **Unauthorized Access** - Compromised credentials, privilege escalation
- **Data Breach** - Unauthorized data access or exfiltration
- **DoS/DDoS** - Denial of service attacks

**Based on:**
- CIS Control 17: Incident Response Management
- NIST CSF Respond (RS)
- SANS Incident Handler's Handbook

**Usage:**
```bash
# Respond to malware incident
python incident-responder.py --type malware

# Full incident response lifecycle for unauthorized access
python incident-responder.py --type unauthorized_access --full-response

# Data breach investigation
python incident-responder.py --type data_breach --output-dir /incidents
```

**Output:**
- Unique incident ID for tracking
- Incident timeline with all actions taken
- Evidence collection (logs, process lists, network connections)
- Incident report in JSON format
- Lessons learned document

---

### 4. threat-intelligence-scanner.py

Threat intelligence and Indicator of Compromise (IOC) scanner with MITRE ATT&CK integration.

**Capabilities:**
- **IOC Detection** - Scan files for IP addresses, domains, file hashes, email addresses
- **File Hash Analysis** - Calculate MD5, SHA1, SHA256 for threat intel lookup
- **MITRE ATT&CK Integration** - Map to adversary tactics and techniques
- **STIX/TAXII Feed Generation** - Generate standardized threat intelligence feeds

**IOC Types Detected:**
- IP Addresses (IPv4)
- Domain names
- File hashes (MD5, SHA256)
- Email addresses
- URLs and URIs

**Based on:**
- MITRE ATT&CK Framework
- STIX/TAXII standards (OASIS)
- Common IOC formats

**Usage:**
```bash
# Scan file for IOCs
python threat-intelligence-scanner.py --scan-file suspicious.log

# Calculate file hashes
python threat-intelligence-scanner.py --hash-file malware.exe

# Lookup MITRE ATT&CK technique
python threat-intelligence-scanner.py --mitre-technique T1566

# Generate STIX IOC feed
python threat-intelligence-scanner.py --generate-feed 192.168.1.100 malicious.com abc123...
```

**Output:**
- IOC findings report (JSON)
- File hashes (MD5, SHA1, SHA256)
- MITRE ATT&CK technique details
- STIX-format threat intelligence feed

---

## 🔧 Prerequisites

### Python Environment

```bash
# Navigate to secops directory
cd /Users/jcox/Repos/Default/envs/secops

# Activate Python virtual environment
source bin/activate

# Verify security packages
python -c "import bandit, safety; print('✅ Security packages installed')"
```

### Required Security Packages

The secops environment includes:

**Scanning & Testing:**
- `bandit` - Python code security scanner
- `safety` - Dependency vulnerability checker
- `checkov` - Infrastructure as Code scanner
- `semgrep` - Multi-language static analysis

**Penetration Testing:**
- `scapy` - Packet manipulation
- `python-nmap` - Network scanning

**Threat Intelligence:**
- `yara-python` - Malware identification
- `virustotal-python` - VirusTotal API integration

**Optional System Tools:**
- `nmap` - Network mapper (install via system package manager)
- `trivy` - Container security scanner

### Installation

```bash
# Install core Python packages
pip install bandit safety checkov semgrep

# Install threat intelligence packages
pip install yara-python virustotal-python

# Install penetration testing packages
pip install scapy python-nmap

# Install system tools (example for Ubuntu/Debian)
sudo apt-get install nmap

# For macOS
brew install nmap trivy
```

---

## 🚀 Quick Start

### 1. Vulnerability Assessment

```bash
# Activate environment
source bin/activate

# Run comprehensive vulnerability scan
cd scripts/assessments
python vulnerability-scanner.py --code-path ~/projects/myapp --all

# Review HTML report
open scan_results/security_report_*.html
```

### 2. Compliance Check

```bash
# Check NIST CSF compliance
cd scripts/compliance
python compliance-framework-checker.py --framework NIST

# Check all frameworks
python compliance-framework-checker.py --framework ALL
```

### 3. Incident Response

```bash
# Respond to security incident
cd scripts/incident-response
python incident-responder.py --type malware --full-response

# Review incident report
cat incidents/INC-*/INC-*_report.json
```

### 4. Threat Intelligence

```bash
# Scan for IOCs
cd scripts/monitoring
python threat-intelligence-scanner.py --scan-file /var/log/auth.log

# Calculate file hash and lookup
python threat-intelligence-scanner.py --hash-file suspicious_file.bin
```

---

## 📚 Detailed Documentation

### Vulnerability Scanner Architecture

The vulnerability scanner uses a modular architecture:

```
VulnerabilityScanner
├── SAST (Static Analysis)
│   └── Bandit (Python code)
├── SCA (Composition Analysis)
│   └── Safety (Dependencies)
├── IaC Security
│   └── Checkov (Terraform/K8s)
├── Network Security
│   └── Nmap (Port scanning)
└── Secrets Detection
    └── Pattern matching
```

### Compliance Framework Mapping

| Framework | Controls | Focus Area |
|-----------|----------|------------|
| **NIST CSF** | 6 core functions | Enterprise security framework |
| **CIS Controls** | 18 critical controls | Defensive security measures |
| **PCI-DSS** | 12 requirements | Payment card data protection |
| **HIPAA** | Security Rule | Healthcare data privacy |

### Incident Response Workflow

```
Detection → Analysis → Containment → Eradication → Recovery → Lessons Learned
    ↓           ↓           ↓              ↓            ↓             ↓
Evidence    Triage      Isolate        Remove        Restore     Document
Collection  Incident    Systems        Threat        Services    Improvements
```

### Report Formats

All scripts generate reports in multiple formats:

1. **HTML Reports**
   - Professional formatted output
   - Color-coded severity levels
   - Executive summaries
   - Drill-down details
   - Links to references

2. **JSON Reports**
   - Machine-readable format
   - API integration ready
   - SIEM ingestion compatible
   - Timestamp tracking

3. **Evidence Files**
   - Raw data collection
   - Forensic analysis ready
   - Chain of custody support

---

## 🛡️ Compliance Frameworks

### NIST Cybersecurity Framework 2.0

**Core Functions:**
- **Identify (ID)** - Asset management, risk assessment
- **Protect (PR)** - Access control, data security
- **Detect (DE)** - Continuous monitoring, anomaly detection
- **Respond (RS)** - Incident response, communications
- **Recover (RC)** - Recovery planning, improvements

**Reference:** [https://www.nist.gov/cyberframework](https://www.nist.gov/cyberframework)

### CIS Critical Security Controls v8

**Control Categories:**
- Basic Controls (CIS 1-6) - Foundational security hygiene
- Foundational Controls (CIS 7-16) - Security program basics
- Organizational Controls (CIS 17-18) - Governance and response

**Reference:** [https://www.cisecurity.org/controls](https://www.cisecurity.org/controls)

### PCI-DSS v4.0

**Build and Maintain:**
- Secure network and systems
- Secure applications and processes

**Protect:**
- Account data and cardholder data
- Access to systems and data

**Detect and Respond:**
- Monitor and test networks
- Maintain incident response

**Reference:** [https://www.pcisecuritystandards.org/](https://www.pcisecuritystandards.org/)

### MITRE ATT&CK

**Tactics (What adversaries want to achieve):**
- Initial Access, Execution, Persistence
- Privilege Escalation, Defense Evasion
- Credential Access, Discovery, Lateral Movement
- Collection, Command & Control, Exfiltration, Impact

**Reference:** [https://attack.mitre.org/](https://attack.mitre.org/)

---

## 🔗 References

### Official Standards and Frameworks

**NIST:**
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [NIST SP 800-53 Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST Incident Response Guide (SP 800-61)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)

**OWASP:**
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Vulnerability Scanning Tools](https://owasp.org/www-community/Vulnerability_Scanning_Tools)
- [OWASP ASVS (Application Security Verification Standard)](https://owasp.org/www-project-application-security-verification-standard/)

**CIS:**
- [CIS Critical Security Controls](https://www.cisecurity.org/controls)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [CIS Control 17: Incident Response](https://www.cisecurity.org/controls/incident-response-management)

**MITRE:**
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE CAR (Cyber Analytics Repository)](https://car.mitre.org/)
- [MITRE D3FEND](https://d3fend.mitre.org/)

### Threat Intelligence

**Standards:**
- [STIX/TAXII (OASIS)](https://oasis-open.github.io/cti-documentation/)
- [OpenIOC Format](https://www.fireeye.com/blog/threat-research/2013/10/openioc-basics.html)

**Platforms:**
- [AlienVault OTX](https://otx.alienvault.com/)
- [MISP (Malware Information Sharing Platform)](https://www.misp-project.org/)
- [VirusTotal](https://www.virustotal.com/)

### Tools and Libraries

**Python Security:**
- [Bandit](https://github.com/PyCQA/bandit) - Python security linter
- [Safety](https://github.com/pyupio/safety) - Dependency checker
- [Checkov](https://github.com/bridgecrewio/checkov) - IaC scanner
- [Semgrep](https://github.com/returntocorp/semgrep) - Static analysis

**Network Security:**
- [Nmap](https://nmap.org/) - Network mapper
- [Scapy](https://scapy.net/) - Packet manipulation
- [Wireshark](https://www.wireshark.org/) - Network analyzer

---

## 📊 Example Workflows

### Weekly Security Assessment

```bash
#!/bin/bash
# Weekly security assessment automation

# 1. Vulnerability scan
python vulnerability-scanner.py --code-path /apps/production --all

# 2. Compliance check
python compliance-framework-checker.py --framework ALL

# 3. Threat intelligence update
python threat-intelligence-scanner.py --scan-file /var/log/syslog

# 4. Generate consolidated report
echo "Security assessment complete - $(date)"
```

### Incident Response Playbook

```bash
#!/bin/bash
# Automated incident response for detected malware

INCIDENT_TYPE="malware"

# 1. Initiate incident response
INCIDENT_ID=$(python incident-responder.py --type $INCIDENT_TYPE --full-response | grep "Incident ID" | cut -d: -f2)

# 2. Collect threat intelligence
python threat-intelligence-scanner.py --scan-file /var/log/auth.log

# 3. Run security scan
python vulnerability-scanner.py --code-path /opt/app --all

# 4. Update compliance status
python compliance-framework-checker.py --framework NIST

echo "Incident response complete: $INCIDENT_ID"
```

### Continuous Monitoring

```bash
#!/bin/bash
# Continuous security monitoring (run via cron)

# Every hour: Check for IOCs
python threat-intelligence-scanner.py --scan-file /var/log/messages

# Daily: Vulnerability scan
python vulnerability-scanner.py --scan-dependencies

# Weekly: Full compliance check
python compliance-framework-checker.py --framework ALL
```

---

## ⚠️ Important Notes

1. **Authorized Use Only**: These tools should only be used on systems you own or have explicit permission to test
2. **Production Safety**: Test in non-production environments first
3. **False Positives**: Review all findings - automated scanners can produce false positives
4. **Continuous Updates**: Keep security tools and signatures updated
5. **Privacy**: Handle scan results securely - they may contain sensitive information
6. **Compliance**: Ensure scanning activities comply with organizational policies

---

## 🤝 Contributing

When extending these scripts:

1. Follow Python best practices (PEP 8)
2. Include comprehensive error handling
3. Reference authoritative sources (NIST, OWASP, CIS, MITRE)
4. Generate both human and machine-readable reports
5. Document all assumptions and limitations
6. Test thoroughly before deployment

---

## 📝 License

These scripts are provided for security operations and defensive security purposes. Always obtain proper authorization before conducting security assessments.

---

## 🆘 Support

For issues, questions, or improvements:

1. Review script documentation and help text
2. Check official framework documentation (NIST, OWASP, CIS)
3. Review logs in output directories
4. Ensure all prerequisites are installed
5. Verify permissions and authorization

---

**Last Updated:** 2025-11-30
**Version:** 1.0
**Based on:** OWASP, NIST CSF 2.0, CIS Controls v8, MITRE ATT&CK, PCI-DSS v4.0
