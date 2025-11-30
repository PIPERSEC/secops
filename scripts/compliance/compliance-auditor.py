#!/usr/bin/env python3
"""
Compliance Auditor
Automated compliance checking for common security frameworks.
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path

class ComplianceAuditor:
    """Audit systems for compliance with security frameworks."""

    def __init__(self, framework='pci-dss'):
        self.framework = framework
        self.results = {
            'framework': framework,
            'audit_date': datetime.now().isoformat(),
            'controls': []
        }

    def audit_pci_dss(self, target_path='.'):
        """Audit for PCI-DSS compliance."""
        print(f"\n🔍 Auditing for PCI-DSS compliance...")

        controls = [
            self.check_encryption_at_rest(),
            self.check_encryption_in_transit(),
            self.check_access_controls(),
            self.check_logging_monitoring(),
            self.check_vulnerability_scanning(),
            self.check_secure_coding(),
        ]

        self.results['controls'] = controls

    def check_encryption_at_rest(self):
        """Check if data at rest is encrypted."""
        control = {
            'id': 'PCI-DSS 3.4',
            'name': 'Encryption of Cardholder Data at Rest',
            'status': 'unknown',
            'findings': []
        }

        # Check for database encryption settings
        # This is a simplified check - in production, you'd query actual DB configs
        print("  Checking encryption at rest...")

        # Look for encryption configuration in code
        py_files = list(Path('.').rglob('*.py'))
        has_encryption = False

        for py_file in py_files:
            try:
                content = py_file.read_text()
                if any(keyword in content.lower() for keyword in ['encrypt', 'aes', 'cryptography']):
                    has_encryption = True
                    break
            except:
                pass

        if has_encryption:
            control['status'] = 'pass'
            control['findings'].append("Encryption libraries detected in codebase")
        else:
            control['status'] = 'fail'
            control['findings'].append("No encryption implementation found")

        return control

    def check_encryption_in_transit(self):
        """Check if data in transit is encrypted."""
        control = {
            'id': 'PCI-DSS 4.1',
            'name': 'Encryption of Cardholder Data in Transit',
            'status': 'unknown',
            'findings': []
        }

        print("  Checking encryption in transit...")

        # Look for TLS/SSL configuration
        config_files = list(Path('.').rglob('*.conf')) + list(Path('.').rglob('*.yaml'))
        has_tls = False

        for config_file in config_files:
            try:
                content = config_file.read_text()
                if any(keyword in content.lower() for keyword in ['tls', 'ssl', 'https']):
                    has_tls = True
                    break
            except:
                pass

        if has_tls:
            control['status'] = 'pass'
            control['findings'].append("TLS/SSL configuration found")
        else:
            control['status'] = 'warning'
            control['findings'].append("TLS/SSL configuration not detected")

        return control

    def check_access_controls(self):
        """Check access control implementation."""
        control = {
            'id': 'PCI-DSS 7.1',
            'name': 'Access Control Implementation',
            'status': 'unknown',
            'findings': []
        }

        print("  Checking access controls...")

        # Look for authentication/authorization code
        py_files = list(Path('.').rglob('*.py'))
        has_auth = False

        keywords = ['authenticate', 'authorize', 'permission', 'rbac', 'login']

        for py_file in py_files:
            try:
                content = py_file.read_text().lower()
                if any(keyword in content for keyword in keywords):
                    has_auth = True
                    control['findings'].append(f"Authentication logic found in {py_file.name}")
                    break
            except:
                pass

        control['status'] = 'pass' if has_auth else 'warning'

        if not has_auth:
            control['findings'].append("No obvious authentication/authorization logic found")

        return control

    def check_logging_monitoring(self):
        """Check logging and monitoring."""
        control = {
            'id': 'PCI-DSS 10.1',
            'name': 'Logging and Monitoring',
            'status': 'unknown',
            'findings': []
        }

        print("  Checking logging and monitoring...")

        # Look for logging configuration
        py_files = list(Path('.').rglob('*.py'))
        has_logging = False

        for py_file in py_files:
            try:
                content = py_file.read_text()
                if 'import logging' in content or 'logger' in content.lower():
                    has_logging = True
                    break
            except:
                pass

        if has_logging:
            control['status'] = 'pass'
            control['findings'].append("Logging implementation found")
        else:
            control['status'] = 'warning'
            control['findings'].append("No logging implementation detected")

        return control

    def check_vulnerability_scanning(self):
        """Check if vulnerability scanning is performed."""
        control = {
            'id': 'PCI-DSS 11.2',
            'name': 'Vulnerability Scanning',
            'status': 'unknown',
            'findings': []
        }

        print("  Checking vulnerability scanning...")

        # Check for security scanning tools/configs
        has_scanning = False

        # Look for CI/CD configs with security scanning
        ci_files = list(Path('.').glob('.github/workflows/*.yml')) + \
                   list(Path('.').glob('.gitlab-ci.yml')) + \
                   list(Path('.').glob('Jenkinsfile'))

        for ci_file in ci_files:
            try:
                content = ci_file.read_text()
                if any(tool in content.lower() for tool in ['bandit', 'safety', 'snyk', 'trivy']):
                    has_scanning = True
                    control['findings'].append(f"Security scanning configured in {ci_file.name}")
                    break
            except:
                pass

        control['status'] = 'pass' if has_scanning else 'warning'

        if not has_scanning:
            control['findings'].append("No automated vulnerability scanning detected in CI/CD")

        return control

    def check_secure_coding(self):
        """Check secure coding practices."""
        control = {
            'id': 'PCI-DSS 6.5',
            'name': 'Secure Coding Practices',
            'status': 'unknown',
            'findings': []
        }

        print("  Checking secure coding practices...")

        # Run bandit if available
        try:
            result = subprocess.run(
                ['bandit', '-r', '.', '-ll', '-f', 'json'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.stdout:
                data = json.loads(result.stdout)
                issues = data.get('results', [])

                if len(issues) == 0:
                    control['status'] = 'pass'
                    control['findings'].append("No high/medium security issues found by Bandit")
                else:
                    control['status'] = 'fail'
                    control['findings'].append(f"Found {len(issues)} security issues in code")

        except:
            control['status'] = 'warning'
            control['findings'].append("Could not run automated code security scan")

        return control

    def generate_report(self):
        """Generate compliance report."""
        print("\n" + "="*80)
        print(f"{self.framework.upper()} Compliance Audit Report")
        print("="*80)

        passed = sum(1 for c in self.results['controls'] if c['status'] == 'pass')
        failed = sum(1 for c in self.results['controls'] if c['status'] == 'fail')
        warnings = sum(1 for c in self.results['controls'] if c['status'] == 'warning')
        total = len(self.results['controls'])

        print(f"\nControls Checked: {total}")
        print(f"  ✅ Passed: {passed}")
        print(f"  ❌ Failed: {failed}")
        print(f"  ⚠️  Warnings: {warnings}")

        print(f"\nCompliance Score: {(passed/total*100):.1f}%")

        # Detail each control
        print("\nControl Details:")
        print("-"*80)

        for control in self.results['controls']:
            status_icon = {
                'pass': '✅',
                'fail': '❌',
                'warning': '⚠️',
                'unknown': '❓'
            }.get(control['status'], '❓')

            print(f"\n{status_icon} {control['id']}: {control['name']}")
            for finding in control['findings']:
                print(f"   - {finding}")

        print("\n" + "="*80)

    def export_json(self, filename='compliance-report.json'):
        """Export compliance report to JSON."""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n📄 Compliance report saved to {filename}")


def main():
    """Main execution."""
    import argparse

    parser = argparse.ArgumentParser(description='Compliance auditor')
    parser.add_argument('--framework', default='pci-dss',
                       choices=['pci-dss', 'hipaa', 'soc2'],
                       help='Compliance framework to audit against')
    parser.add_argument('--export', help='Export report to JSON file')

    args = parser.parse_args()

    print("Compliance Auditor")
    print("="*80)

    auditor = ComplianceAuditor(framework=args.framework)

    if args.framework == 'pci-dss':
        auditor.audit_pci_dss()

    auditor.generate_report()

    if args.export:
        auditor.export_json(args.export)


if __name__ == '__main__':
    main()
