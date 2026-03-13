#!/usr/bin/env python3

import nmap
import argparse
import requests
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

print(r" _   _      _   ____                  _            ")
print(r"| \ | | ___| |_/ ___| _ __   ___  ___| |_ ___ _ __  ")
print(r"|  \| |/ _ \ __\___ \| '_ \ / _ \/ __| __/ _ \ '__| ")
print(r"| |\  |  __/ |_ ___) | |_) |  __/ (__| ||  __/ |    ")
print(r"|_| \_|\___|\__|____/| .__/ \___|\___|\__\___|_|    ")
print(r"                     |_|                            ")
print(r"                                      ~by CipherWolf")
class VulnScanner:

    def __init__(self, target, output):

        self.target = target
        self.output = output
        self.nm = nmap.PortScanner()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.log_file = f"{output}_{timestamp}.txt"

        # log console
        self.log_console = Console(file=open(self.log_file, "w"), force_terminal=False)

        self.results = []

    def dual_print(self, obj):

        console.print(obj)
        self.log_console.print(obj)

    def discover_hosts(self):

        self.dual_print("[cyan]Discovering hosts...[/cyan]")

        self.nm.scan(hosts=self.target, arguments="-sn")

        hosts = []

        for host in self.nm.all_hosts():

            if self.nm[host].state() == "up":
                hosts.append(host)

        self.dual_print(f"[green]Found {len(hosts)} live hosts[/green]\n")

        return hosts

    def fetch_cve_details(self, cve):

        try:

            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

            r = requests.get(url, timeout=5)

            if r.status_code == 200:

                data = r.json()

                vuln = data["vulnerabilities"][0]["cve"]

                desc = vuln["descriptions"][0]["value"]

                cvss = "N/A"

                metrics = vuln.get("metrics", {})

                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

                return desc[:120], cvss

        except:
            pass

        return "Unknown vulnerability", "N/A"

    def scan_host(self, host):

        self.dual_print(f"[yellow]Scanning {host}...[/yellow]")

        self.nm.scan(host, arguments="-sV -O --script vuln")

        host_data = {
            "ip": host,
            "os": "unknown",
            "services": [],
            "vulns": []
        }

        if "osmatch" in self.nm[host]:

            matches = self.nm[host]["osmatch"]

            if matches:
                host_data["os"] = matches[0]["name"]

        for proto in self.nm[host].all_protocols():

            for port in self.nm[host][proto]:

                service = self.nm[host][proto][port]

                svc = {
                    "port": port,
                    "protocol": proto,
                    "name": service.get("name"),
                    "product": service.get("product"),
                    "version": service.get("version")
                }

                host_data["services"].append(svc)

                scripts = service.get("script", {})

                for output in scripts.values():

                    if "CVE-" in output:

                        for line in output.split("\n"):

                            if "CVE-" in line:

                                cve = line.strip().split()[0]

                                desc, cvss = self.fetch_cve_details(cve)

                                host_data["vulns"].append({
                                    "port": port,
                                    "service": svc["name"],
                                    "cve": cve,
                                    "cvss": cvss,
                                    "desc": desc
                                })

        self.results.append(host_data)

    def show_results(self):

        for host in self.results:

            self.dual_print(Panel(f"Scan Results for {host['ip']}", style="bold blue"))

            self.dual_print(f"[bold]OS Detected:[/bold] {host['os']}\n")

            svc_table = Table(title="Running Services", box=box.ROUNDED)

            svc_table.add_column("Port")
            svc_table.add_column("Protocol")
            svc_table.add_column("Service")
            svc_table.add_column("Product")
            svc_table.add_column("Version")

            for s in host["services"]:

                svc_table.add_row(
                    str(s["port"]),
                    s["protocol"],
                    str(s["name"]),
                    str(s["product"]),
                    str(s["version"])
                )

            self.dual_print(svc_table)

            if host["vulns"]:

                vuln_table = Table(title="Detected Vulnerabilities", box=box.ROUNDED)

                vuln_table.add_column("Port")
                vuln_table.add_column("Service")
                vuln_table.add_column("CVE")
                vuln_table.add_column("CVSS")
                vuln_table.add_column("Description")

                for v in host["vulns"]:

                    vuln_table.add_row(
                        str(v["port"]),
                        str(v["service"]),
                        v["cve"],
                        str(v["cvss"]),
                        v["desc"]
                    )

                self.dual_print(vuln_table)

            else:

                self.dual_print("[green]No known vulnerabilities detected[/green]\n")

    def run(self):

        hosts = self.discover_hosts()

        for h in hosts:
            self.scan_host(h)

        self.show_results()

        self.dual_print(f"\n[green]Scan report saved to:[/green] {self.log_file}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Beautiful Network Vulnerability Scanner")

    parser.add_argument("target")
    parser.add_argument("-o", "--output", default="scan_report")

    args = parser.parse_args()

    console.print(Panel("Network Security Scanner", style="bold green"))

    scanner = VulnScanner(args.target, args.output)

    scanner.run()
