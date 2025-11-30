# SecOps - Security Operations & Engineering Framework

A comprehensive framework for security operations, testing, monitoring, and automation. This repository provides standardized tools, templates, and AI-assisted workflows for building and maintaining secure systems.

## Overview

This framework is designed to help security engineers:
- Automate security testing and vulnerability scanning
- Implement security monitoring and threat detection
- Conduct penetration testing and security assessments
- Maintain compliance with security standards
- Respond to security incidents effectively
- Leverage AI assistance for security operations

## Repository Structure

```
secops/
├── projects/                    # Active security projects
├── templates/                   # Reusable security templates
│   ├── ansible/                # Security automation playbooks
│   ├── terraform/              # Secure infrastructure as code
│   ├── docker/                 # Secure container configs
│   └── scripts/                # Security scripts
├── docs/                       # Documentation
│   ├── architecture/           # Security architecture
│   ├── runbooks/              # Incident response runbooks
│   ├── policies/              # Security policies
│   ├── standards/             # Security standards
│   ├── tutorials/             # How-to guides
│   └── compliance/            # Compliance documentation
├── config/                     # Configuration files
│   ├── scanners/              # Scanner configurations
│   ├── monitoring/            # Monitoring configs
│   └── siem/                  # SIEM configurations
├── ai-context/                 # AI assistant context
│   ├── personas/              # Security expert personas
│   ├── memory-bank/           # Persistent context
│   ├── cot-templates/         # Chain of Thought templates
│   └── few-shot-examples/     # Code examples
├── scripts/                    # Utility scripts
│   ├── scanning/              # Vulnerability scanning
│   ├── monitoring/            # Security monitoring
│   ├── incident-response/     # IR automation
│   └── compliance/            # Compliance checking
├── tools/                      # Security tools
│   ├── vulnerability-scanners/# Scanning tools
│   ├── penetration-testing/   # Pentest tools
│   ├── forensics/             # Forensic tools
│   └── threat-intel/          # Threat intelligence
└── .claude/                    # Claude Code configuration
```

## Getting Started

### Prerequisites

- Python 3.13+ (virtual environment included)
- Git
- Docker (for container security testing)
- Basic understanding of security concepts

### Installation

1. **Activate the Python virtual environment:**
   ```bash
   cd /Users/jcox/Repos/Default/envs/secops
   source bin/activate
   ```

2. **Verify security packages:**
   ```bash
   python -c "import bandit, safety; print('✅ Security packages installed')"
   ```

### Key Security Packages Installed

**Security Scanning & Testing:**
- **Bandit**: Python code security scanner
- **Safety**: Check Python dependencies for vulnerabilities
- **Checkov**: Infrastructure as code scanner
- **Semgrep**: Static analysis for multiple languages

**Penetration Testing:**
- **SQLMap**: SQL injection testing
- **Scapy**: Packet manipulation
- **python-nmap**: Network scanning

**Threat Intelligence:**
- **Shodan**: Internet-connected device search
- **VirusTotal**: Malware scanning API
- **YARA**: Malware identification

**Security Automation:**
- **Ansible**: Security automation
- **Cryptography**: Encryption and security
- **Paramiko**: SSH automation

## Core Concepts

### AI Context System

#### Personas
Located in [ai-context/personas/](ai-context/personas/):
- **Security Engineer**: Defensive security and operations
- **Application Security Engineer**: Secure development and testing
- **Threat Intelligence Analyst**: Threat hunting and analysis

#### Memory Bank
Stores persistent context for security projects, decisions, and lessons learned.

#### Security Workflows
Chain of Thought templates for:
- Security assessments
- Incident response
- Vulnerability management
- Compliance auditing

## Common Security Tasks

### 1. Vulnerability Scanning

**Scan Python Code:**
```bash
# Run Bandit security scanner
bandit -r /path/to/your/code

# Check dependencies for vulnerabilities
safety check --file requirements.txt
```

**Scan Infrastructure as Code:**
```bash
# Scan Terraform configurations
checkov -d /path/to/terraform

# Scan Kubernetes manifests
checkov -d /path/to/k8s
```

### 2. Dependency Vulnerability Check

```python
import safety
import json

# Check for known vulnerabilities
vulnerabilities = safety.check(packages=[])
if vulnerabilities:
    print(json.dumps(vulnerabilities, indent=2))
```

### 3. Network Scanning

```python
import nmap

nm = nmap.PortScanner()
nm.scan('192.168.1.0/24', '22-443')

for host in nm.all_hosts():
    print(f'Host: {host} ({nm[host].hostname()})')
    print(f'State: {nm[host].state()}')

    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        for port in ports:
            print(f'Port: {port} State: {nm[host][proto][port]["state"]}')
```

### 4. Security Automation with Ansible

```yaml
---
- name: Harden Linux Server
  hosts: all
  become: yes

  tasks:
    - name: Update all packages
      apt:
        upgrade: dist
        update_cache: yes

    - name: Configure firewall
      ufw:
        rule: allow
        port: '{{ item }}'
      loop:
        - '22'
        - '443'

    - name: Enable firewall
      ufw:
        state: enabled

    - name: Disable root login
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: 'PermitRootLogin no'
      notify: restart sshd
```

### 5. Container Security Scanning

```bash
# Scan Docker image for vulnerabilities
trivy image nginx:latest

# Scan for secrets in git repository
trufflehog git https://github.com/example/repo
```

## Security Testing Workflows

### Web Application Security Testing

```bash
# 1. Passive scanning
zap-cli quick-scan http://target.com

# 2. Active scanning
zap-cli active-scan http://target.com

# 3. Generate report
zap-cli report -o security-report.html -f html
```

### API Security Testing

```python
import requests

# Test for authentication bypass
response = requests.get('https://api.example.com/admin',
                       headers={'Authorization': 'Bearer invalid'})
assert response.status_code == 401

# Test for SQL injection
payload = "' OR '1'='1"
response = requests.get(f'https://api.example.com/users?id={payload}')
# Analyze response for vulnerabilities
```

## Incident Response

### Automated Incident Response Workflow

```python
#!/usr/bin/env python3
"""
Automated incident response workflow
"""

def detect_threat(log_entry):
    """Detect potential security threat"""
    suspicious_patterns = [
        'failed login',
        'privilege escalation',
        'malware detected',
    ]
    return any(pattern in log_entry.lower() for pattern in suspicious_patterns)

def contain_threat(threat_type):
    """Contain identified threat"""
    if threat_type == 'compromised_account':
        disable_account()
        force_password_reset()
    elif threat_type == 'malware':
        isolate_system()
        initiate_scan()

def investigate(incident_id):
    """Investigate security incident"""
    collect_logs()
    analyze_network_traffic()
    check_file_integrity()
    document_findings()

def remediate(incident_id):
    """Remediate security incident"""
    patch_vulnerability()
    restore_from_backup()
    verify_system_integrity()

def post_incident_review():
    """Conduct post-incident review"""
    document_lessons_learned()
    update_playbooks()
    implement_preventive_controls()
```

## Compliance & Auditing

### PCI-DSS Compliance Check

```bash
# Check for unencrypted data
grep -r "card.*number" /var/log/

# Verify encryption is enabled
openssl s_client -connect api.example.com:443 -tls1_2

# Check password policy
cat /etc/login.defs | grep PASS
```

### SOC 2 Controls Automation

```python
# Automated access review
def review_user_access():
    """Review user access permissions"""
    users = get_all_users()
    for user in users:
        if user.last_login > 90_days_ago():
            flag_for_review(user)
        if user.has_admin_access() and not user.requires_admin():
            escalate_to_security_team(user)
```

## Threat Intelligence

### IOC Collection and Analysis

```python
import virustotal_python

# Check file hash against VirusTotal
vt = virustotal_python.Virustotal(api_key='YOUR_API_KEY')
response = vt.request('file/report', params={'resource': file_hash})

if response['positives'] > 0:
    print(f"Malicious file detected: {response['positives']}/{response['total']}")
```

### Threat Hunting with YARA

```python
import yara

# Load YARA rules
rules = yara.compile(filepath='/path/to/rules.yar')

# Scan file
matches = rules.match('/path/to/suspicious/file')
for match in matches:
    print(f"Rule matched: {match.rule}")
    print(f"Strings: {match.strings}")
```

## Security Monitoring

### SIEM Integration Example

```python
import json
import requests

def send_to_siem(event):
    """Send security event to SIEM"""
    siem_endpoint = "https://siem.example.com/api/events"

    event_data = {
        "timestamp": event.timestamp,
        "severity": event.severity,
        "source": event.source,
        "message": event.message,
        "tags": event.tags
    }

    response = requests.post(
        siem_endpoint,
        json=event_data,
        headers={"Authorization": f"Bearer {SIEM_API_KEY}"}
    )

    return response.status_code == 200
```

## Best Practices

### Security Operations
- Defense in Depth
- Assume Breach Mentality
- Continuous Monitoring
- Automated Response
- Regular Security Assessments
- Incident Response Preparedness

### Application Security
- Secure SDLC
- Shift Left Security
- Automated Security Testing
- Dependency Management
- Secrets Management
- Security Code Review

### Infrastructure Security
- Least Privilege Access
- Network Segmentation
- Encryption Everywhere
- Patch Management
- Configuration Management
- Audit Logging

## Security Tools Matrix

| Category | Tools | Purpose |
|----------|-------|---------|
| SAST | Bandit, Semgrep, SonarQube | Static code analysis |
| DAST | OWASP ZAP, Burp Suite | Dynamic testing |
| SCA | Safety, Snyk, Dependency-Check | Dependency scanning |
| Container | Trivy, Clair, Anchore | Container security |
| Network | Nmap, Masscan, Wireshark | Network analysis |
| Forensics | Volatility, Autopsy | Digital forensics |
| Threat Intel | MISP, ThreatConnect | Threat intelligence |

## Compliance Frameworks

- **PCI-DSS**: Payment card security
- **HIPAA**: Healthcare data protection
- **GDPR**: Privacy regulations
- **SOC 2**: Security controls
- **ISO 27001**: Information security management
- **NIST CSF**: Cybersecurity framework
- **CIS Controls**: Security best practices

## Resources

### Internal Documentation
- [Security Policies](docs/policies/)
- [Security Standards](docs/standards/)
- [Incident Response Runbooks](docs/runbooks/)
- [Compliance Documentation](docs/compliance/)

### External Resources
- [OWASP](https://owasp.org/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)
- [SANS Institute](https://www.sans.org/)

## License

This framework is provided for security engineering and operations work.

## Acknowledgments

Built with Claude Code for efficient AI-assisted security operations.
