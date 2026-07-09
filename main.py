from fastapi import FastAPI, Request, Query
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import socket
import re
import subprocess
import platform
import network_logic
import subdomain_logic
import email_logic
import search_logic
import initial_logic
import webhub_logic
import webanalysis_logic

app = FastAPI()
templates = Jinja2Templates(directory="templates")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def serve_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/ping")
async def check_ping_endpoint(target: str):
    # Resolve IP if needed
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        try:
            target = socket.gethostbyaddr(target)[0]
        except:
            pass
    
    is_alive = ping_host(target)
    return {"alive": is_alive, "target": target}

@app.get("/scan")
async def master_scan(target: str, type: str):
    # Sanitize target globally
    target = target.replace("https://", "").replace("http://", "").split("/")[0]
    scan_type = type.lower()

    # IP RESOLUTION
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        try:
            resolved_domain = socket.gethostbyaddr(target)[0]
            print(f"[*] Resolved IP {target} to {resolved_domain}")
            target = resolved_domain
        except Exception as e:
            print(f"[-] Could not resolve IP {target}: {e}")
            pass
    
    # Check connectvity (Ping) for specific scans
    ping_required_types = ["initial", "network", "website", "webanalysis", "web analysis", "sub domain", "subdomain", "all"]
    should_ping = any(x in scan_type for x in ping_required_types)
    
    if should_ping:
        if not ping_host(target):
            return {"error": "Host not Reachable"}
    
    # Initial Identification (Tool: Whois, GeoIPLookup, TheHarvester) (file name: initial_logic.py)
    if "initial" in scan_type:
        return initial_logic.run_initial_scan(target)
    # Network Scan (Tool: NMAP) (file name: network_logic.py)
    elif "network" in scan_type:
        return network_logic.run_network_scan(target)
    # Web Analysis & Security (Tool: Nikto) (file name: webanalysis_logic.py)
    elif "website" in scan_type or "webanalysis" in scan_type or "web analysis" in scan_type:
        return webanalysis_logic.run_webanalysis_scan(target)
    # Subdomain Enumeration (Tool: Amass) (file name: subdomain_logic.py)
    elif "sub domain" in scan_type or "subdomain" in scan_type:
        return subdomain_logic.run_subdomain_scan(target)
    # Web Hub Scan (Tool: Waybackmachine Wappalyzer) (file name: webhub_logic.py)
    elif "web hub" in scan_type or "webhub" in scan_type:
        return webhub_logic.run_webhub_scan(target)
    # Search Engine Scan (Tool: GoogleDork) (file name: search_logic.py)
    elif "search" in scan_type:
        return search_logic.run_search_engine_scan(target)
    # User Email & Discovery (Tool: TheHarvester) (file name: email_logic.py)
    elif "email" in scan_type:
        return email_logic.run_email_user_scan(target)
    # All Scans 
    elif "all" in scan_type:
        # Run lightweight/passive scans first to avoid blocking or timeouts
        results = {}
        # 1. Initial Identification (Whois, IP, Geo)
        results.update(initial_logic.run_initial_scan(target))
        # 2. Subdomain Enumeration (Passive, critical for scope)
        results.update(subdomain_logic.run_subdomain_scan(target))
        # 3. Web Hub (Wayback, Tech Stack)
        results.update(webhub_logic.run_webhub_scan(target))
        # 4. Search Engine Discovery
        results.update(search_logic.run_search_engine_scan(target))
        # 5. Email/User Discovery
        results.update(email_logic.run_email_user_scan(target))
        # 6. Network Scan (Nmap - Slower)
        results.update(network_logic.run_network_scan(target))
        # 7. Web Analysis (Nikto - Slowest)
        results.update(webanalysis_logic.run_webanalysis_scan(target))
        
        return results
    return {"error": f"Invalid Scan Type: {type}"}


def ping_host(target):
    """
    Pings the target to check if it is active.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', target]
    
    print(f"[*] Pinging {target}...")
    try:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(f"[+] {target} is reachable.")
        return True
    except subprocess.CalledProcessError:
        print(f"[-] {target} is NOT reachable")
        return False


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)