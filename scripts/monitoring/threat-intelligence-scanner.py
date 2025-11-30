#!/usr/bin/env python3
"""
Threat Intelligence and IOC Scanner

Scans for Indicators of Compromise (IOCs) and integrates with threat intelligence feeds.

Author: Security Operations Team
Version: 1.0
References:
- MITRE ATT&CK: https://attack.mitre.org/
- STIX/TAXII: https://oasis-open.github.io/cti-documentation/
- AlienVault OTX: https://otx.alienvault.com/
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List
import re

class ThreatIntelligenceScanner:
    """IOC scanner and threat intelligence tool"""

    def __init__(self, output_dir: str = "threat_intel"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

        # Common IOC patterns
        self.ioc_patterns = {
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }

    def scan_file_for_iocs(self, file_path: str) -> Dict:
        """Scan file for indicators of compromise"""
        print(f"\n[*] Scanning {file_path} for IOCs...")

        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()

            iocs_found = {}
            for ioc_type, pattern in self.ioc_patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    unique_matches = list(set(matches))
                    iocs_found[ioc_type] = unique_matches
                    print(f"    Found {len(unique_matches)} {ioc_type} indicators")

                    for ioc in unique_matches:
                        self.add_finding(
                            ioc_type=ioc_type,
                            ioc_value=ioc,
                            source=file_path,
                            severity='INFO'
                        )

            return {'file': file_path, 'iocs': iocs_found}

        except Exception as e:
            print(f"    Error scanning file: {e}")
            return {'file': file_path, 'error': str(e)}

    def calculate_file_hashes(self, file_path: str) -> Dict:
        """Calculate file hashes for threat intelligence lookup"""
        print(f"\n[*] Calculating file hashes for {file_path}...")

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()

            hashes = {
                'md5': hashlib.md5(file_data).hexdigest(),
                'sha1': hashlib.sha1(file_data).hexdigest(),
                'sha256': hashlib.sha256(file_data).hexdigest()
            }

            print(f"    MD5:    {hashes['md5']}")
            print(f"    SHA1:   {hashes['sha1']}")
            print(f"    SHA256: {hashes['sha256']}")

            return hashes

        except Exception as e:
            print(f"    Error calculating hashes: {e}")
            return {}

    def check_mitre_attack(self, technique_id: str) -> Dict:
        """
        Reference MITRE ATT&CK technique
        In production, this would query the MITRE ATT&CK API
        """
        print(f"\n[*] MITRE ATT&CK Technique: {technique_id}")

        # Example MITRE ATT&CK techniques (would be from API in production)
        techniques = {
            'T1566': {'name': 'Phishing', 'tactic': 'Initial Access'},
            'T1078': {'name': 'Valid Accounts', 'tactic': 'Persistence'},
            'T1003': {'name': 'OS Credential Dumping', 'tactic': 'Credential Access'},
            'T1071': {'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
            'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact'}
        }

        if technique_id in techniques:
            tech = techniques[technique_id]
            print(f"    Technique: {tech['name']}")
            print(f"    Tactic: {tech['tactic']}")
            print(f"    Reference: https://attack.mitre.org/techniques/{technique_id}/")
            return tech
        else:
            print(f"    Technique not found in database")
            return {}

    def generate_ioc_feed(self, ioc_list: List[str]) -> str:
        """Generate STIX-format IOC feed"""
        print(f"\n[*] Generating IOC feed...")

        feed = {
            'type': 'bundle',
            'id': f'bundle--{datetime.now().strftime("%Y%m%d-%H%M%S")}',
            'objects': []
        }

        for ioc in ioc_list:
            ioc_type = self._detect_ioc_type(ioc)
            indicator = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f'indicator--{hashlib.md5(ioc.encode()).hexdigest()}',
                'created': datetime.now().isoformat(),
                'modified': datetime.now().isoformat(),
                'name': f'{ioc_type}: {ioc}',
                'pattern': f"[{ioc_type}:value = '{ioc}']",
                'pattern_type': 'stix',
                'valid_from': datetime.now().isoformat()
            }
            feed['objects'].append(indicator)

        feed_path = self.output_dir / f'ioc_feed_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(feed_path, 'w') as f:
            json.dump(feed, f, indent=2)

        print(f"    ✓ IOC feed generated: {feed_path}")
        return str(feed_path)

    def add_finding(self, ioc_type: str, ioc_value: str, source: str, severity: str):
        """Add IOC finding"""
        self.findings.append({
            'type': ioc_type,
            'value': ioc_value,
            'source': source,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        })

    def _detect_ioc_type(self, ioc: str) -> str:
        """Detect IOC type from value"""
        for ioc_type, pattern in self.ioc_patterns.items():
            if re.match(pattern, ioc):
                return ioc_type
        return 'unknown'

    def generate_report(self) -> str:
        """Generate threat intelligence report"""
        print(f"\n[*] Generating Threat Intelligence Report")

        report = {
            'timestamp': datetime.now().isoformat(),
            'total_iocs': len(self.findings),
            'iocs_by_type': {},
            'findings': self.findings
        }

        # Count by type
        for finding in self.findings:
            ioc_type = finding['type']
            report['iocs_by_type'][ioc_type] = report['iocs_by_type'].get(ioc_type, 0) + 1

        # Save report
        report_path = self.output_dir / f'threat_intel_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"    ✓ Report saved: {report_path}")
        print(f"\n    Total IOCs Found: {report['total_iocs']}")
        for ioc_type, count in report['iocs_by_type'].items():
            print(f"      {ioc_type}: {count}")

        return str(report_path)


def main():
    parser = argparse.ArgumentParser(
        description='Threat Intelligence and IOC Scanner'
    )

    parser.add_argument('--scan-file', help='File to scan for IOCs')
    parser.add_argument('--hash-file', help='Calculate file hashes')
    parser.add_argument('--mitre-technique', help='Lookup MITRE ATT&CK technique')
    parser.add_argument('--generate-feed', nargs='+', help='Generate IOC feed from list')
    parser.add_argument('--output-dir', default='threat_intel', help='Output directory')

    args = parser.parse_args()

    scanner = ThreatIntelligenceScanner(args.output_dir)

    print("""
╔═══════════════════════════════════════════════════════════════════╗
║   Threat Intelligence and IOC Scanner                            ║
║   MITRE ATT&CK | STIX/TAXII Integration                          ║
╚═══════════════════════════════════════════════════════════════════╝
    """)

    if args.scan_file:
        scanner.scan_file_for_iocs(args.scan_file)

    if args.hash_file:
        scanner.calculate_file_hashes(args.hash_file)

    if args.mitre_technique:
        scanner.check_mitre_attack(args.mitre_technique)

    if args.generate_feed:
        scanner.generate_ioc_feed(args.generate_feed)

    if args.scan_file or args.generate_feed:
        scanner.generate_report()

    print(f"\n✓ Operations complete\n")


if __name__ == '__main__':
    main()
