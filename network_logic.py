# Yonith Tool NMAP

import subprocess
import re
import socket

def extract_scan_data(output, target):
    # Target Identification
    try:
        rdns = socket.gethostbyaddr(target)[0]
    except (socket.herror, socket.gaierror):
        domain_match = re.search(r"Nmap scan report for ([a-zA-Z0-9.-]+) \(", output)
        rdns = domain_match.group(1) if domain_match else "No domain found"

    web_match = re.search(r"commonName=([a-zA-Z0-9.-]*)", output)
    website = web_match.group(1) if web_match else "Unknown Website"

    ip_match = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", output)
    if not ip_match:
        ip_match = re.search(r"Nmap scan report for (\d{1,3}(?:\.\d{1,3}){3})", output)
    ip_address = ip_match.group(1) if ip_match else target

    # Ports & Services
    port_pattern = r"(\d+)\/(\w+)\s+open\s+(\S+)\s*(.*)"
    port_matches = re.findall(port_pattern, output)
    ports = [{"port": f"{p[0]}/{p[1]}", "service": p[2], "version": p[3].strip()} for p in port_matches]

    # SSL Details
    ssl_details = []
    cert_blocks = re.findall(r"ssl-cert:.*?\n((?:\|_?.*\n)+)", output)
    for block in cert_blocks:
        subject = re.search(r"Subject: (.*)", block)
        issuer = re.search(r"Issuer: (.*)", block)
        ssl_details.append({
            "subject": subject.group(1) if subject else "N/A",
            "issuer": issuer.group(1) if issuer else "N/A"
        })

    # CVEs and CVSS Scores 
    cve_cvss_pattern = r"(CVE-\d{4}-\d{4,7})\s+(\d+\.\d)"
    found_vulns = re.findall(cve_cvss_pattern, output)
    
    unique_vulns = list(set(found_vulns))
    sorted_vulns = sorted(unique_vulns, key=lambda x: float(x[1]), reverse=True)

    cve_list = []
    for cve_id, score in sorted_vulns:
        s = float(score)
        if s >= 9.0: sev = "CRITICAL"
        elif s >= 7.0: sev = "HIGH"
        elif s >= 4.0: sev = "MEDIUM"
        else: sev = "LOW"
        
        cve_list.append(f"{cve_id} ({score} {sev})")

    return {
        "target": target,
        "ip": ip_address,
        "rdns": rdns,
        "website": website,
        "ports": ports,
        "cves": cve_list,
        "ssl": ssl_details
    }


def run_network_scan(target: str):
    # Updated command to include vulners script for CVSS scores
    cmd = [
        "nmap", "-sV", "-Pn", "--script", "vulners,ssl-cert",
        "--min-rate", "5000", target
    ]
    
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=400)
        return extract_scan_data(process.stdout, target)
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(run_network_scan(sys.argv[1]))
    else:
        print("Please provide a target argument.")