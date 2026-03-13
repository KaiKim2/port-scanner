import nmap
import requests
import json
import csv
import argparse
import sys
from datetime import datetime
import pandas as pd

print(r" _   _      _   ____                  _            ")
print(r"| \ | | ___| |_/ ___| _ __   ___  ___| |_ ___ _ __  ")
print(r"|  \| |/ _ \ __\___ \| '_ \ / _ \/ __| __/ _ \ '__| ")
print(r"| |\  |  __/ |_ ___) | |_) |  __/ (__| ||  __/ |    ")
print(r"|_| \_|\___|\__|____/| .__/ \___|\___|\__\___|_|    ")
print(r"                     |_|                            ")

class AdvScanner:
    def __init__(self, args):
        self.nm = nmap.PortScanner()
        self.target = args.target
        self.output = args.output
        self.fast = args.fast
        self.vulners_script = "vulners"

    def discover_hosts(self):
        """Fast host discovery using ping/syn scan."""
        print(f"[+] Discovering hosts on {self.target}")
        if self.fast:
            self.nm.scan(hosts=self.target, arguments='-sn -T4 --min-parallelism 256')
        else:
            self.nm.scan(hosts=self.target, arguments='-sn')
        hosts = [h for h in self.nm.all_hosts() if self.nm[h].state() == 'up']
        print(f"[+] Found {len(hosts)} live hosts")
        return hosts

    def scan_ports_vulns(self, host):
        """Advanced port scan with NSE vulnerability scripts."""
        print(f"[+] Scanning {host} for ports and vulns")
        args = '-sV -sC --script="vuln,vulners" -T4 -O --script-args vulners.showall'
        if self.fast:
            args += ' --top-ports 1000 -Pn'
        self.nm.scan(host, arguments=args)
        return self.nm[host]

    def fetch_cve_details(self, cves):
        """Fetch recent CVE details from NVD API (simplified, rate-limited)."""
        details = {}
        for cve in cves[:5]:
            try:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    if 'vulnerabilities' in data and data['vulnerabilities']:
                        vuln = data['vulnerabilities'][0]['cve']
                        details[cve] = {
                            'cvss': vuln.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A'),
                            'description': vuln['descriptions'][0]['value'][:200]
                        }
            except:
                pass
        return details

    def generate_reports(self, results):
        """Generate JSON and CSV reports with risk scoring."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        json_file = f"{self.output}_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        df = pd.DataFrame(results['hosts'])
        csv_file = f"{self.output}_{timestamp}.csv"
        df.to_csv(csv_file, index=False)
        
        high_risks = sum(1 for h in results['hosts'] for v in h.get('vulnerabilities', []) if v.get('severity', '').lower() == 'high')
        print(f"[+] Reports saved: {json_file}, {csv_file}")
        print(f"[+] High-risk vulns found: {high_risks}")

    def run(self):
        hosts = self.discover_hosts()
        all_results = {'scan_date': datetime.now().isoformat(), 'target': self.target, 'hosts': []}
        
        for host in hosts:
            host_data = self.scan_ports_vulns(host)
            vulns = []
            for proto in host_data.all_protocols():
                ports = host_data[proto].keys()
                for port in ports:
                    info = host_data[proto][port]
                    scripts = info.get('script', {})
                    if 'vulners' in scripts:
                        cve_list = scripts['vulners'].split(', ')
                        details = self.fetch_cve_details(cve_list)
                        vulns.extend([{'port': port, 'service': info.get('name', 'unknown'), 'cve': cve, **details.get(cve, {})} for cve in cve_list])
            
            all_results['hosts'].append({
                'ip': host,
                'os': host_data.get('osmatch', [{}])[0].get('name', 'unknown') if 'osmatch' in host_data else 'unknown',
                'open_ports': len(host_data.all_protocols()),
                'vulnerabilities': vulns
            })
        
        self.generate_reports(all_results)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Vulnerability Scanner for Pros")
    parser.add_argument("target", help="Target IP/range e.g. 192.168.1.0/24")
    parser.add_argument("-o", "--output", default="advscan", help="Output prefix")
    parser.add_argument("--fast", action="store_true", help="Fast mode: top ports, aggressive timing")
    args = parser.parse_args()
    
    print("Advanced Government-Grade Scanner v1.0")
    print("Install NSE vulners: nmap --script-updatedb")
    scanner = AdvScanner(args)
    scanner.run()
