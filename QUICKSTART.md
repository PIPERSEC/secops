# SecOps Framework - Quick Start Guide

## What You Have

Complete security operations framework with:
- Security scanning tools (Bandit, Safety, Checkov)
- Penetration testing libraries
- Threat intelligence integration
- Security automation capabilities
- AI-powered security assistance

## Quick Start

### 1. Activate Environment
```bash
cd /Users/jcox/Repos/Default/envs/secops
source bin/activate
```

### 2. Verify Installation
```bash
python -c "import bandit, safety; print('✅ Security tools ready!')"
```

### 3. Run Your First Security Scan
```bash
# Scan Python code
bandit -r /path/to/code

# Check dependencies
safety check
```

## Common Security Tasks

### Vulnerability Scanning
```bash
# Infrastructure scanning
checkov -d /path/to/terraform

# Code scanning
bandit -r /path/to/python/code
```

### Threat Intelligence
```python
# Check file hash
import virustotal_python
vt = virustotal_python.Virustotal(api_key='YOUR_KEY')
response = vt.request('file/report', params={'resource': file_hash})
```

### Security Automation
```yaml
# Ansible security playbook
- name: Harden server
  hosts: all
  tasks:
    - name: Update packages
      apt:
        upgrade: dist
```

## Security Best Practices

✅ **Never commit secrets**
✅ **Test in isolated environments**
✅ **Follow responsible disclosure**
✅ **Document security findings**
✅ **Maintain audit trails**

## Resources

- README: [README.md](README.md)
- AI Context: [ai-context/](ai-context/)
- Documentation: [docs/](docs/)

**Repository**: https://github.com/PIPERSEC/secops
