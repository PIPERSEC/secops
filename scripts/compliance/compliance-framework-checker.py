#!/usr/bin/env python3
"""
Security Compliance Framework Checker

Automated compliance checking for PCI-DSS, SOC 2, HIPAA, NIST CSF, and CIS Controls.

Author: Security Operations Team
Version: 1.0
References:
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- CIS Controls: https://www.cisecurity.org/controls
- PCI-DSS: https://www.pcisecuritystandards.org/
- HIPAA Security Rule: https://www.hhs.gov/hipaa/
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List
import os
import platform

class ComplianceChecker:
    """Multi-framework compliance checker"""

    def __init__(self, framework: str, output_dir: str = "compliance_results"):
        self.framework = framework.upper()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {
            'framework': self.framework,
            'timestamp': datetime.now().isoformat(),
            'system_info': {
                'os': platform.system(),
                'os_version': platform.release(),
                'hostname': platform.node()
            },
            'controls': [],
            'summary': {
                'total_controls': 0,
                'compliant': 0,
                'non_compliant': 0,
                'not_applicable': 0
            }
        }

    def check_nist_csf(self) -> Dict:
        """
        Check NIST Cybersecurity Framework controls

        NIST CSF Functions: Identify, Protect, Detect, Respond, Recover
        """
        print(f"\n[*] Checking NIST Cybersecurity Framework 2.0 Controls")

        controls = [
            {
                'id': 'ID.AM-1',
                'function': 'Identify',
                'category': 'Asset Management',
                'control': 'Physical devices and systems are inventoried',
                'check': self._check_asset_inventory
            },
            {
                'id': 'PR.AC-1',
                'function': 'Protect',
                'category': 'Access Control',
                'control': 'Identities and credentials are issued, managed, and revoked',
                'check': self._check_access_control
            },
            {
                'id': 'PR.DS-1',
                'function': 'Protect',
                'category': 'Data Security',
                'control': 'Data-at-rest is protected',
                'check': self._check_encryption_at_rest
            },
            {
                'id': 'DE.CM-1',
                'function': 'Detect',
                'category': 'Continuous Monitoring',
                'control': 'Networks and network services are monitored',
                'check': self._check_network_monitoring
            },
            {
                'id': 'RS.AN-1',
                'function': 'Respond',
                'category': 'Analysis',
                'control': 'Notifications are investigated',
                'check': self._check_incident_response
            },
            {
                'id': 'RC.RP-1',
                'function': 'Recover',
                'category': 'Recovery Planning',
                'control': 'Recovery plan is executed during or after an event',
                'check': self._check_recovery_plan
            }
        ]

        for control in controls:
            result = control['check']()
            self.add_control_result(
                control_id=control['id'],
                control_name=control['control'],
                category=control['category'],
                status=result['status'],
                details=result.get('details', ''),
                reference=f"NIST CSF {control['function']}"
            )

        return {'framework': 'NIST CSF', 'controls_checked': len(controls)}

    def check_cis_controls(self) -> Dict:
        """
        Check CIS Critical Security Controls v8

        Reference: https://www.cisecurity.org/controls
        """
        print(f"\n[*] Checking CIS Critical Security Controls v8")

        controls = [
            {
                'id': 'CIS-1',
                'control': 'Inventory and Control of Enterprise Assets',
                'check': self._check_asset_inventory
            },
            {
                'id': 'CIS-3',
                'control': 'Data Protection',
                'check': self._check_data_protection
            },
            {
                'id': 'CIS-6',
                'control': 'Access Control Management',
                'check': self._check_access_control
            },
            {
                'id': 'CIS-8',
                'control': 'Audit Log Management',
                'check': self._check_audit_logging
            },
            {
                'id': 'CIS-17',
                'control': 'Incident Response Management',
                'check': self._check_incident_response
            }
        ]

        for control in controls:
            result = control['check']()
            self.add_control_result(
                control_id=control['id'],
                control_name=control['control'],
                category='CIS Controls',
                status=result['status'],
                details=result.get('details', ''),
                reference='https://www.cisecurity.org/controls'
            )

        return {'framework': 'CIS Controls', 'controls_checked': len(controls)}

    def check_pci_dss(self) -> Dict:
        """
        Check PCI-DSS v4.0 requirements

        Reference: https://www.pcisecuritystandards.org/
        """
        print(f"\n[*] Checking PCI-DSS v4.0 Requirements")

        requirements = [
            {
                'id': 'PCI-1',
                'requirement': 'Install and maintain network security controls',
                'check': self._check_firewall_config
            },
            {
                'id': 'PCI-2',
                'requirement': 'Apply secure configurations to all system components',
                'check': self._check_secure_config
            },
            {
                'id': 'PCI-3',
                'requirement': 'Protect stored account data',
                'check': self._check_encryption_at_rest
            },
            {
                'id': 'PCI-8',
                'requirement': 'Identify users and authenticate access',
                'check': self._check_access_control
            },
            {
                'id': 'PCI-10',
                'requirement': 'Log and monitor all access',
                'check': self._check_audit_logging
            }
        ]

        for req in requirements:
            result = req['check']()
            self.add_control_result(
                control_id=req['id'],
                control_name=req['requirement'],
                category='PCI-DSS',
                status=result['status'],
                details=result.get('details', ''),
                reference='https://www.pcisecuritystandards.org/'
            )

        return {'framework': 'PCI-DSS', 'requirements_checked': len(requirements)}

    def check_soc2(self) -> Dict:
        """
        Check SOC 2 Trust Service Criteria

        Reference: https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report
        """
        print(f"\n[*] Checking SOC 2 Trust Service Criteria")

        criteria = [
            {
                'id': 'CC1.1',
                'category': 'Control Environment',
                'criterion': 'Demonstrates commitment to integrity and ethical values',
                'check': self._check_security_policies
            },
            {
                'id': 'CC6.1',
                'category': 'Logical and Physical Access',
                'criterion': 'Restricts logical and physical access',
                'check': self._check_access_control
            },
            {
                'id': 'CC6.6',
                'category': 'Encryption',
                'criterion': 'Protects data in transmission and at rest',
                'check': self._check_encryption_at_rest
            },
            {
                'id': 'CC7.2',
                'category': 'System Monitoring',
                'criterion': 'Monitors system components',
                'check': self._check_network_monitoring
            },
            {
                'id': 'A1.2',
                'category': 'Availability',
                'criterion': 'Environmental protections and recovery infrastructure',
                'check': self._check_recovery_plan
            },
            {
                'id': 'P3.2',
                'category': 'Privacy',
                'criterion': 'Access controls for privacy',
                'check': self._check_access_control
            }
        ]

        for criterion in criteria:
            result = criterion['check']()
            self.add_control_result(
                control_id=criterion['id'],
                control_name=criterion['criterion'],
                category=criterion['category'],
                status=result['status'],
                details=result.get('details', ''),
                reference='SOC 2 Trust Service Criteria'
            )

        return {'framework': 'SOC 2', 'criteria_checked': len(criteria)}

    def check_hipaa(self) -> Dict:
        """
        Check HIPAA Security Rule requirements

        Reference: https://www.hhs.gov/hipaa/for-professionals/security/
        """
        print(f"\n[*] Checking HIPAA Security Rule Requirements")

        safeguards = [
            {
                'id': 'HIPAA-164.308(a)(1)',
                'category': 'Administrative Safeguards',
                'safeguard': 'Security Management Process - Risk Analysis',
                'check': self._check_security_policies
            },
            {
                'id': 'HIPAA-164.308(a)(3)',
                'category': 'Administrative Safeguards',
                'safeguard': 'Workforce Security - Authorization/Supervision',
                'check': self._check_access_control
            },
            {
                'id': 'HIPAA-164.308(a)(6)',
                'category': 'Administrative Safeguards',
                'safeguard': 'Security Incident Procedures',
                'check': self._check_incident_response
            },
            {
                'id': 'HIPAA-164.310(a)(1)',
                'category': 'Physical Safeguards',
                'safeguard': 'Facility Access Controls',
                'check': self._check_physical_security
            },
            {
                'id': 'HIPAA-164.312(a)(1)',
                'category': 'Technical Safeguards',
                'safeguard': 'Access Control - Unique User Identification',
                'check': self._check_access_control
            },
            {
                'id': 'HIPAA-164.312(a)(2)(iv)',
                'category': 'Technical Safeguards',
                'safeguard': 'Encryption and Decryption',
                'check': self._check_encryption_at_rest
            },
            {
                'id': 'HIPAA-164.312(b)',
                'category': 'Technical Safeguards',
                'safeguard': 'Audit Controls',
                'check': self._check_audit_logging
            },
            {
                'id': 'HIPAA-164.312(e)(1)',
                'category': 'Technical Safeguards',
                'safeguard': 'Transmission Security',
                'check': self._check_transmission_security
            }
        ]

        for safeguard in safeguards:
            result = safeguard['check']()
            self.add_control_result(
                control_id=safeguard['id'],
                control_name=safeguard['safeguard'],
                category=safeguard['category'],
                status=result['status'],
                details=result.get('details', ''),
                reference='HIPAA Security Rule'
            )

        return {'framework': 'HIPAA', 'safeguards_checked': len(safeguards)}

    # Control Check Methods
    def _check_asset_inventory(self) -> Dict:
        """Check if asset inventory exists"""
        # Check for common asset inventory tools/files
        inventory_locations = [
            '/etc/ansible/inventory',
            'assets.json',
            'inventory.yml'
        ]

        for location in inventory_locations:
            if Path(location).exists():
                return {
                    'status': 'COMPLIANT',
                    'details': f'Asset inventory found at {location}'
                }

        return {
            'status': 'NON_COMPLIANT',
            'details': 'No asset inventory system detected'
        }

    def _check_access_control(self) -> Dict:
        """Check access control configuration"""
        if platform.system() == 'Linux':
            try:
                result = subprocess.run(['cat', '/etc/pam.d/common-auth'],
                                      capture_output=True, text=True)
                if 'pam_unix' in result.stdout:
                    return {
                        'status': 'COMPLIANT',
                        'details': 'PAM authentication configured'
                    }
            except:
                pass

        return {
            'status': 'NOT_APPLICABLE',
            'details': 'Manual review required'
        }

    def _check_encryption_at_rest(self) -> Dict:
        """Check data-at-rest encryption"""
        if platform.system() == 'Linux':
            try:
                result = subprocess.run(['lsblk', '-f'], capture_output=True, text=True)
                if 'crypto_LUKS' in result.stdout:
                    return {
                        'status': 'COMPLIANT',
                        'details': 'LUKS encryption detected'
                    }
            except:
                pass

        return {
            'status': 'NOT_APPLICABLE',
            'details': 'Encryption check not applicable for this platform'
        }

    def _check_network_monitoring(self) -> Dict:
        """Check network monitoring tools"""
        monitoring_tools = ['tcpdump', 'wireshark', 'snort']

        for tool in monitoring_tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True)
                if result.returncode == 0:
                    return {
                        'status': 'COMPLIANT',
                        'details': f'Network monitoring tool found: {tool}'
                    }
            except:
                continue

        return {
            'status': 'NON_COMPLIANT',
            'details': 'No network monitoring tools detected'
        }

    def _check_incident_response(self) -> Dict:
        """Check incident response plan"""
        ir_docs = ['incident-response.md', 'IR-plan.pdf', 'runbooks/incident-response']

        for doc in ir_docs:
            if Path(doc).exists():
                return {
                    'status': 'COMPLIANT',
                    'details': f'Incident response documentation found: {doc}'
                }

        return {
            'status': 'NON_COMPLIANT',
            'details': 'No incident response plan detected'
        }

    def _check_recovery_plan(self) -> Dict:
        """Check disaster recovery plan"""
        dr_docs = ['disaster-recovery.md', 'DR-plan.pdf', 'backup-policy.md']

        for doc in dr_docs:
            if Path(doc).exists():
                return {
                    'status': 'COMPLIANT',
                    'details': f'Recovery plan found: {doc}'
                }

        return {
            'status': 'NON_COMPLIANT',
            'details': 'No disaster recovery plan detected'
        }

    def _check_data_protection(self) -> Dict:
        """Check data protection measures"""
        return self._check_encryption_at_rest()

    def _check_audit_logging(self) -> Dict:
        """Check audit logging configuration"""
        if platform.system() == 'Linux':
            try:
                result = subprocess.run(['systemctl', 'is-active', 'auditd'],
                                      capture_output=True, text=True)
                if 'active' in result.stdout:
                    return {
                        'status': 'COMPLIANT',
                        'details': 'Audit daemon (auditd) is active'
                    }
            except:
                pass

        return {
            'status': 'NOT_APPLICABLE',
            'details': 'Manual review of logging required'
        }

    def _check_firewall_config(self) -> Dict:
        """Check firewall configuration"""
        if platform.system() == 'Linux':
            try:
                result = subprocess.run(['systemctl', 'is-active', 'firewalld'],
                                      capture_output=True, text=True)
                if 'active' in result.stdout:
                    return {
                        'status': 'COMPLIANT',
                        'details': 'Firewall (firewalld) is active'
                    }

                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                if 'active' in result.stdout.lower():
                    return {
                        'status': 'COMPLIANT',
                        'details': 'Firewall (ufw) is active'
                    }
            except:
                pass

        return {
            'status': 'NON_COMPLIANT',
            'details': 'No active firewall detected'
        }

    def _check_secure_config(self) -> Dict:
        """Check secure system configuration"""
        return {
            'status': 'NOT_APPLICABLE',
            'details': 'Requires manual configuration review'
        }

    def _check_security_policies(self) -> Dict:
        """Check for security policy documentation"""
        policy_docs = ['security-policy.md', 'security-policy.pdf', 'policies/security.md']

        for doc in policy_docs:
            if Path(doc).exists():
                return {
                    'status': 'COMPLIANT',
                    'details': f'Security policy documentation found: {doc}'
                }

        return {
            'status': 'NON_COMPLIANT',
            'details': 'No security policy documentation found'
        }

    def _check_physical_security(self) -> Dict:
        """Check physical security controls"""
        return {
            'status': 'NOT_APPLICABLE',
            'details': 'Physical security requires on-site inspection'
        }

    def _check_transmission_security(self) -> Dict:
        """Check data transmission security"""
        # Check for SSL/TLS configuration
        try:
            result = subprocess.run(['openssl', 'version'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return {
                    'status': 'COMPLIANT',
                    'details': f'OpenSSL installed: {result.stdout.strip()}'
                }
        except:
            pass

        return {
            'status': 'NOT_APPLICABLE',
            'details': 'Manual review of transmission security required'
        }

    def add_control_result(self, control_id: str, control_name: str,
                          category: str, status: str, details: str, reference: str):
        """Add control check result"""
        self.results['controls'].append({
            'id': control_id,
            'name': control_name,
            'category': category,
            'status': status,
            'details': details,
            'reference': reference,
            'timestamp': datetime.now().isoformat()
        })

        self.results['summary']['total_controls'] += 1
        if status == 'COMPLIANT':
            self.results['summary']['compliant'] += 1
        elif status == 'NON_COMPLIANT':
            self.results['summary']['non_compliant'] += 1
        else:
            self.results['summary']['not_applicable'] += 1

        # Print status
        status_symbol = '✓' if status == 'COMPLIANT' else '✗' if status == 'NON_COMPLIANT' else '○'
        print(f"    [{status_symbol}] {control_id}: {control_name} - {status}")

    def generate_report(self) -> str:
        """Generate compliance report"""
        print(f"\n[*] Generating Compliance Report")

        # Generate JSON report
        json_path = self.output_dir / f"{self.framework}_compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2)

        # Generate HTML report
        html_report = self._generate_html_report()
        html_path = self.output_dir / f"{self.framework}_compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(html_path, 'w') as f:
            f.write(html_report)

        print(f"    ✓ JSON Report: {json_path}")
        print(f"    ✓ HTML Report: {html_path}")

        return str(html_path)

    def _generate_html_report(self) -> str:
        """Generate HTML compliance report"""
        summary = self.results['summary']
        compliance_rate = (summary['compliant'] / summary['total_controls'] * 100) if summary['total_controls'] > 0 else 0

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{self.framework} Compliance Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #1565c0 0%, #0d47a1 100%); color: white; padding: 30px; border-radius: 5px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .summary-number {{ font-size: 2.5em; font-weight: bold; }}
        .compliant {{ color: #2e7d32; }}
        .non-compliant {{ color: #c62828; }}
        .controls {{ background: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .control {{ border-left: 4px solid #ccc; padding: 15px; margin: 10px 0; background: #f9f9f9; }}
        .control.compliant {{ border-color: #2e7d32; background: #e8f5e9; }}
        .control.non-compliant {{ border-color: #c62828; background: #ffebee; }}
        .status-badge {{ padding: 5px 12px; border-radius: 3px; font-weight: bold; display: inline-block; }}
        .status-COMPLIANT {{ background: #2e7d32; color: white; }}
        .status-NON_COMPLIANT {{ background: #c62828; color: white; }}
        .status-NOT_APPLICABLE {{ background: #757575; color: white; }}
        .footer {{ text-align: center; color: #666; margin: 30px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📋 {self.framework} Compliance Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>System: {self.results['system_info']['hostname']} ({self.results['system_info']['os']})</p>
    </div>

    <div class="summary">
        <div class="summary-card">
            <div class="summary-number">{compliance_rate:.1f}%</div>
            <div>Compliance Rate</div>
        </div>
        <div class="summary-card">
            <div class="summary-number compliant">{summary['compliant']}</div>
            <div>Compliant</div>
        </div>
        <div class="summary-card">
            <div class="summary-number non-compliant">{summary['non_compliant']}</div>
            <div>Non-Compliant</div>
        </div>
        <div class="summary-card">
            <div class="summary-number">{summary['not_applicable']}</div>
            <div>Not Applicable</div>
        </div>
    </div>

    <div class="controls">
        <h2>Control Assessment Results</h2>
"""

        for control in self.results['controls']:
            status_class = control['status'].lower().replace('_', '-')
            html += f"""
        <div class="control {status_class}">
            <span class="status-badge status-{control['status']}">{control['status']}</span>
            <h3>{control['id']}: {control['name']}</h3>
            <p><strong>Category:</strong> {control['category']}</p>
            <p><strong>Details:</strong> {control['details']}</p>
            <p><strong>Reference:</strong> {control['reference']}</p>
        </div>
"""

        html += """
    </div>
    <div class="footer">
        <p><strong>Compliance Framework Checker v1.0</strong></p>
        <p>
            <a href="https://www.nist.gov/cyberframework" target="_blank">NIST CSF</a> |
            <a href="https://www.cisecurity.org/controls" target="_blank">CIS Controls</a> |
            <a href="https://www.pcisecuritystandards.org/" target="_blank">PCI-DSS</a>
        </p>
    </div>
</body>
</html>
"""
        return html

    def print_summary(self):
        """Print compliance summary"""
        summary = self.results['summary']
        compliance_rate = (summary['compliant'] / summary['total_controls'] * 100) if summary['total_controls'] > 0 else 0

        print(f"\n{'='*70}")
        print(f"{self.framework} Compliance Assessment Summary")
        print(f"{'='*70}\n")
        print(f"Total Controls Checked: {summary['total_controls']}")
        print(f"Compliance Rate: {compliance_rate:.1f}%\n")
        print(f"✓ Compliant:      {summary['compliant']}")
        print(f"✗ Non-Compliant:  {summary['non_compliant']}")
        print(f"○ Not Applicable: {summary['not_applicable']}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Security Compliance Framework Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--framework', required=True,
                       choices=['NIST', 'CIS', 'PCI-DSS', 'SOC2', 'HIPAA', 'ALL'],
                       help='Compliance framework to check')
    parser.add_argument('--output-dir', default='compliance_results',
                       help='Output directory for reports')

    args = parser.parse_args()

    frameworks = ['NIST', 'CIS', 'PCI-DSS', 'SOC2', 'HIPAA'] if args.framework == 'ALL' else [args.framework]

    for framework in frameworks:
        checker = ComplianceChecker(framework, args.output_dir)

        print(f"\n{'='*70}")
        print(f"Starting {framework} Compliance Assessment")
        print(f"{'='*70}")

        if framework == 'NIST':
            checker.check_nist_csf()
        elif framework == 'CIS':
            checker.check_cis_controls()
        elif framework == 'PCI-DSS':
            checker.check_pci_dss()
        elif framework == 'SOC2':
            checker.check_soc2()
        elif framework == 'HIPAA':
            checker.check_hipaa()

        report_path = checker.generate_report()
        checker.print_summary()

        print(f"\nFull report: {report_path}\n")


if __name__ == '__main__':
    main()
