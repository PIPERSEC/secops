#!/usr/bin/env python3
"""
Comprehensive Security Scanner
Runs multiple security scans across code, dependencies, and infrastructure.
"""

import subprocess
import json
import sys
from pathlib import Path
from datetime import datetime

class SecurityScanner:
    """Comprehensive security scanning."""

    def __init__(self, target_path='.'):
        self.target_path = Path(target_path)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'target': str(self.target_path),
            'scans': {}
        }

    def scan_python_code(self):
        """Scan Python code with Bandit."""
        print("\n🔍 Scanning Python code with Bandit...")

        python_files = list(self.target_path.rglob('*.py'))
        if not python_files:
            print("  ⚠️  No Python files found")
            self.results['scans']['bandit'] = {'status': 'skipped'}
            return

        try:
            result = subprocess.run(
                ['bandit', '-r', str(self.target_path), '-f', 'json'],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                print("  ✅ No security issues found")
                self.results['scans']['bandit'] = {
                    'status': 'pass',
                    'issues': 0
                }
            else:
                data = json.loads(result.stdout) if result.stdout else {}
                issues = data.get('results', [])

                # Count by severity
                high = sum(1 for i in issues if i.get('issue_severity') == 'HIGH')
                medium = sum(1 for i in issues if i.get('issue_severity') == 'MEDIUM')
                low = sum(1 for i in issues if i.get('issue_severity') == 'LOW')

                print(f"  ❌ Found {len(issues)} issues:")
                print(f"     High: {high}, Medium: {medium}, Low: {low}")

                self.results['scans']['bandit'] = {
                    'status': 'fail',
                    'total_issues': len(issues),
                    'high': high,
                    'medium': medium,
                    'low': low,
                    'details': issues[:5]  # Store first 5 for report
                }

        except FileNotFoundError:
            print("  ⚠️  Bandit not installed")
            self.results['scans']['bandit'] = {'status': 'error', 'message': 'Tool not found'}
        except Exception as e:
            print(f"  ❌ Error: {e}")
            self.results['scans']['bandit'] = {'status': 'error', 'message': str(e)}

    def scan_dependencies(self):
        """Scan Python dependencies with Safety."""
        print("\n🔍 Scanning dependencies with Safety...")

        requirements_files = list(self.target_path.rglob('requirements*.txt'))
        if not requirements_files:
            print("  ⚠️  No requirements.txt found")
            self.results['scans']['safety'] = {'status': 'skipped'}
            return

        try:
            for req_file in requirements_files:
                result = subprocess.run(
                    ['safety', 'check', '--file', str(req_file), '--json'],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    print(f"  ✅ No vulnerabilities in {req_file.name}")
                    self.results['scans']['safety'] = {
                        'status': 'pass',
                        'vulnerabilities': 0
                    }
                else:
                    try:
                        vulns = json.loads(result.stdout)
                        print(f"  ❌ Found {len(vulns)} vulnerabilities in {req_file.name}")

                        for vuln in vulns[:3]:  # Show first 3
                            print(f"     - {vuln[0]}: {vuln[2]}")

                        self.results['scans']['safety'] = {
                            'status': 'fail',
                            'vulnerabilities': len(vulns),
                            'details': vulns
                        }
                    except:
                        print(f"  ❌ Vulnerabilities found (see details)")

        except FileNotFoundError:
            print("  ⚠️  Safety not installed")
            self.results['scans']['safety'] = {'status': 'error', 'message': 'Tool not found'}
        except Exception as e:
            print(f"  ❌ Error: {e}")
            self.results['scans']['safety'] = {'status': 'error', 'message': str(e)}

    def scan_infrastructure_code(self):
        """Scan infrastructure code with Checkov."""
        print("\n🔍 Scanning infrastructure with Checkov...")

        # Look for IaC files
        tf_files = list(self.target_path.rglob('*.tf'))
        k8s_files = list(self.target_path.rglob('*deployment*.yaml'))

        if not tf_files and not k8s_files:
            print("  ⚠️  No infrastructure code found")
            self.results['scans']['checkov'] = {'status': 'skipped'}
            return

        try:
            result = subprocess.run(
                ['checkov', '-d', str(self.target_path), '--quiet', '--compact', '-o', 'json'],
                capture_output=True,
                text=True
            )

            if result.stdout:
                data = json.loads(result.stdout)
                summary = data.get('summary', {})

                passed = summary.get('passed', 0)
                failed = summary.get('failed', 0)
                skipped = summary.get('skipped', 0)

                if failed > 0:
                    print(f"  ❌ Found {failed} failed checks")
                    print(f"     Passed: {passed}, Failed: {failed}, Skipped: {skipped}")
                    self.results['scans']['checkov'] = {
                        'status': 'fail',
                        'passed': passed,
                        'failed': failed,
                        'skipped': skipped
                    }
                else:
                    print(f"  ✅ All checks passed ({passed})")
                    self.results['scans']['checkov'] = {
                        'status': 'pass',
                        'passed': passed
                    }

        except FileNotFoundError:
            print("  ⚠️  Checkov not installed")
            self.results['scans']['checkov'] = {'status': 'error', 'message': 'Tool not found'}
        except Exception as e:
            print(f"  ⚠️  Could not parse results: {e}")
            self.results['scans']['checkov'] = {'status': 'error', 'message': str(e)}

    def scan_secrets(self):
        """Scan for exposed secrets."""
        print("\n🔍 Scanning for exposed secrets...")

        # Simple secret patterns
        patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', 'Password in code'),
            (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'API key in code'),
            (r'secret\s*=\s*["\'][^"\']+["\']', 'Secret in code'),
            (r'BEGIN\s+PRIVATE\s+KEY', 'Private key in code'),
        ]

        issues_found = []

        for py_file in self.target_path.rglob('*.py'):
            try:
                content = py_file.read_text()
                for pattern, description in patterns:
                    import re
                    if re.search(pattern, content, re.IGNORECASE):
                        issues_found.append({
                            'file': str(py_file),
                            'issue': description
                        })
                        print(f"  ⚠️  {py_file.name}: {description}")
            except:
                pass

        if issues_found:
            self.results['scans']['secrets'] = {
                'status': 'warning',
                'issues': len(issues_found),
                'details': issues_found
            }
        else:
            print("  ✅ No obvious secrets found")
            self.results['scans']['secrets'] = {'status': 'pass'}

    def generate_report(self):
        """Generate comprehensive security report."""
        print("\n" + "="*80)
        print("Security Scan Summary")
        print("="*80)

        total_scans = len(self.results['scans'])
        passed = sum(1 for s in self.results['scans'].values() if s.get('status') == 'pass')
        failed = sum(1 for s in self.results['scans'].values() if s.get('status') == 'fail')
        warnings = sum(1 for s in self.results['scans'].values() if s.get('status') == 'warning')
        skipped = sum(1 for s in self.results['scans'].values() if s.get('status') == 'skipped')

        print(f"\nTotal Scans: {total_scans}")
        print(f"  ✅ Passed: {passed}")
        print(f"  ❌ Failed: {failed}")
        print(f"  ⚠️  Warnings: {warnings}")
        print(f"  ⏭️  Skipped: {skipped}")

        # Critical findings
        critical_findings = []
        for scan_name, scan_result in self.results['scans'].items():
            if scan_result.get('status') == 'fail':
                if scan_name == 'bandit' and scan_result.get('high', 0) > 0:
                    critical_findings.append(f"High severity code issues: {scan_result['high']}")
                elif scan_name == 'safety' and scan_result.get('vulnerabilities', 0) > 0:
                    critical_findings.append(f"Vulnerable dependencies: {scan_result['vulnerabilities']}")
                elif scan_name == 'checkov' and scan_result.get('failed', 0) > 0:
                    critical_findings.append(f"Infrastructure security issues: {scan_result['failed']}")

        if critical_findings:
            print("\n❌ Critical Findings:")
            for finding in critical_findings:
                print(f"  - {finding}")

        print("\n" + "="*80)

    def export_json(self, filename='security-scan-results.json'):
        """Export results to JSON."""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n📄 Detailed results saved to {filename}")


def main():
    """Main execution."""
    import argparse

    parser = argparse.ArgumentParser(description='Comprehensive security scanner')
    parser.add_argument('path', nargs='?', default='.', help='Path to scan')
    parser.add_argument('--export', help='Export results to JSON file')

    args = parser.parse_args()

    print("Comprehensive Security Scanner")
    print("="*80)

    scanner = SecurityScanner(target_path=args.path)

    # Run all scans
    scanner.scan_python_code()
    scanner.scan_dependencies()
    scanner.scan_infrastructure_code()
    scanner.scan_secrets()

    # Generate report
    scanner.generate_report()

    # Export if requested
    if args.export:
        scanner.export_json(args.export)

    # Exit code based on failures
    failed_scans = sum(1 for s in scanner.results['scans'].values() if s.get('status') == 'fail')
    sys.exit(1 if failed_scans > 0 else 0)


if __name__ == '__main__':
    main()
