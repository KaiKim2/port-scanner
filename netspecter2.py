#!/usr/bin/env python3

import nmap
import argparse
import requests
import json
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.theme import Theme

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "danger": "bold red",
    "success": "bold green"
})

console = Console(theme=custom_theme)


class AdvancedScanner:

    def __init__(self, target, output, threads, mode, min_cvss):
        self.target = target
        self.output = output
        self.threads = threads
        self.mode = mode
        self.min_cvss = min_cvss

        self.nm = nmap.PortScanner()
        self.results = []

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.log_file = f"{output}_{timestamp}.txt"
        self.json_file = f"{output}_{timestamp}.json"

        self.log_console = Console(
            file=open(self.log_file, "w"),
            force_terminal=True,
            color_system="truecolor",
            theme=custom_theme
        )

    def dual_print(self, obj):
        console.print(obj)
        self.log_console.print(obj)

    def get_scan_args(self):
        if self.mode == "quick":
            return "-T4 -F"
        elif self.mode == "stealth":
            return "-sS -T2"
        elif self.mode == "full":
            return "-sV -O -p- --script vuln"
        return "-sV"

    def discover_hosts(self):
        self.dual_print("[info]Discovering hosts...[/info]")

        self.nm.scan(hosts=self.target, arguments="-sn")

        hosts = [h for h in self.nm.all_hosts() if self.nm[h].state() == "up"]

        self.dual_print(f"[success]Found {len(hosts)} live hosts[/success]\n")
        return hosts


    def grab_banner(self, ip, port):
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            return banner[:100]
        except:
            return ""


    def fetch_cve(self, cve):
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
            r = requests.get(url, timeout=5)

            if r.status_code == 200:
                data = r.json()
                vuln = data["vulnerabilities"][0]["cve"]

                desc = vuln["descriptions"][0]["value"]
                metrics = vuln.get("metrics", {})

                cvss = 0
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

                return desc[:120], float(cvss)

        except:
            pass

        return "Unknown", 0

    def scan_host(self, host):
        args = self.get_scan_args()

        self.dual_print(f"[warning]Scanning {host} ({self.mode})...[/warning]")

        try:
            self.nm.scan(host, arguments=args)
        except Exception as e:
            self.dual_print(f"[danger]Error scanning {host}: {e}[/danger]")
            return

        host_data = {
            "ip": host,
            "os": "unknown",
            "services": [],
            "vulns": []
        }

        if "osmatch" in self.nm[host] and self.nm[host]["osmatch"]:
            host_data["os"] = self.nm[host]["osmatch"][0]["name"]

        seen_cves = set()

        for proto in self.nm[host].all_protocols():
            for port in self.nm[host][proto]:

                service = self.nm[host][proto][port]
                banner = self.grab_banner(host, port)

                svc = {
                    "port": port,
                    "protocol": proto,
                    "name": service.get("name"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "banner": banner
                }

                host_data["services"].append(svc)

                scripts = service.get("script", {})

                for output in scripts.values():
                    if "CVE-" in output:
                        for line in output.split("\n"):
                            if "CVE-" in line:
                                cve = line.strip().split()[0]

                                if cve in seen_cves:
                                    continue

                                seen_cves.add(cve)

                                desc, cvss = self.fetch_cve(cve)

                                if cvss >= self.min_cvss:
                                    host_data["vulns"].append({
                                        "port": port,
                                        "service": svc["name"],
                                        "cve": cve,
                                        "cvss": cvss,
                                        "desc": desc
                                    })

        self.results.append(host_data)

    def run_scans(self, hosts):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_host, h) for h in hosts]
            for _ in as_completed(futures):
                pass

    def analyze_web_target(self, url):
        self.dual_print(f"[info]Analyzing web target: {url}[/info]")

        findings = []

        try:
            r = requests.get(url, timeout=5)

            headers = r.headers

            if "X-Frame-Options" not in headers:
                findings.append("Missing X-Frame-Options (Clickjacking risk)")

            if "Content-Security-Policy" not in headers:
                findings.append("Missing CSP (XSS risk)")

            if "Strict-Transport-Security" not in headers:
                findings.append("Missing HSTS (HTTPS downgrade risk)")

            soup = BeautifulSoup(r.text, "html.parser")
            forms = soup.find_all("form")

            findings.append(f"Forms detected: {len(forms)}")

            for form in forms:
                action = form.get("action")
                method = form.get("method", "get").upper()

                inputs = form.find_all("input")
                names = [i.get("name") for i in inputs if i.get("name")]

                findings.append(f"{method} {action} | Inputs: {names}")

            if "?" in url:
                findings.append("URL contains parameters (potential input vectors)")

        except Exception as e:
            findings.append(f"Error analyzing site: {e}")

        for f in findings:
            self.dual_print(f"[warning]{f}[/warning]")

    def show_results(self):

        for host in self.results:

            self.dual_print(Panel(f"Results: {host['ip']}", style="bold blue"))
            self.dual_print(f"[bold]OS:[/bold] {host['os']}\n")

            svc_table = Table(title="Services", box=box.ROUNDED)
            svc_table.add_column("Port")
            svc_table.add_column("Service")
            svc_table.add_column("Product")
            svc_table.add_column("Banner")

            for s in host["services"]:
                svc_table.add_row(
                    str(s["port"]),
                    str(s["name"]),
                    str(s["product"]),
                    s["banner"]
                )

            self.dual_print(svc_table)

            if host["vulns"]:
                vuln_table = Table(title="Vulnerabilities", box=box.ROUNDED)
                vuln_table.add_column("Port")
                vuln_table.add_column("CVE")
                vuln_table.add_column("CVSS")
                vuln_table.add_column("Description")

                for v in host["vulns"]:
                    vuln_table.add_row(
                        str(v["port"]),
                        v["cve"],
                        str(v["cvss"]),
                        v["desc"]
                    )

                self.dual_print(vuln_table)
            else:
                self.dual_print("[success]No high-severity vulnerabilities[/success]\n")

    def save_json(self):
        with open(self.json_file, "w") as f:
            json.dump(self.results, f, indent=4)

        self.dual_print(f"\n[success]JSON saved:[/success] {self.json_file}")

    def run(self):

        if self.target.startswith("http"):
            self.analyze_web_target(self.target)
            return

        hosts = self.discover_hosts()
        self.run_scans(hosts)
        self.show_results()
        self.save_json()

        self.dual_print(f"\n[success]Log saved:[/success] {self.log_file}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="⚡ Advanced Security Scanner")

    parser.add_argument("target", help="IP / range OR URL")
    parser.add_argument("-o", "--output", default="scan_report")
    parser.add_argument("-t", "--threads", type=int, default=5)
    parser.add_argument("-m", "--mode", choices=["quick", "full", "stealth"], default="full")
    parser.add_argument("--min-cvss", type=float, default=5.0)

    args = parser.parse_args()

    console.print(Panel("⚡ Advanced Network + Web Scanner", style="bold green"))

    scanner = AdvancedScanner(
        args.target,
        args.output,
        args.threads,
        args.mode,
        args.min_cvss
    )

    scanner.run()
