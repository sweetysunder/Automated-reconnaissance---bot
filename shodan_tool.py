import shodan
import os
import socket
import re
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv('SHODAN_API_KEY')

def get_shodan_data(target):
    if not API_KEY or API_KEY == "YOUR_SHODAN_API_KEY_HERE":
        print("Error: SHODAN_API_KEY is not set or is still the placeholder.")
        return {"hsts": "Error: API Key Missing", "shodan_data": "N/A"}

    try:
        api = shodan.Shodan(API_KEY)
        
        # Domain Resolution Logic
        target_ip = target
        
        # Remove protocol if present
        if target_ip.startswith("http://"):
            target_ip = target_ip[7:]
        elif target_ip.startswith("https://"):
            target_ip = target_ip[8:]
        
        # Remove trailing slash
        target_ip = target_ip.rstrip('/')

        # Try to resolve if it doesn't look like an IP
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target_ip):
            try:
                # Only print if running as main, or maybe logging? keeping simple for now
                # print(f"[+] Resolving domain: {target_ip}...")
                resolved_ip = socket.gethostbyname(target_ip)
                # print(f"[+] Resolved to: {resolved_ip}")
                target_ip = resolved_ip
            except socket.gaierror:
                print(f"[-] Error: Could not resolve domain '{target_ip}'.")
                return {"hsts": f"Error: DNS Resolution Failed for {target_ip}", "shodan_data": "N/A"}

        # print(f"\n[+] Checking HSTS Presence for: {target_ip}...")
        host = api.host(target_ip)
        
        found_hsts = False
        hsts_details = []

        # Iterate through all open ports/services found on the host
        for item in host.get('data', []):
            port = item.get('port')
            transport = item.get('transport')
            
            # Check if HTTP/HTTPS info is available in the banner
            if 'http' in item:
                headers = item['http'].get('headers', {})
                hsts_header = headers.get('Strict-Transport-Security')
                
                if hsts_header:
                    found_hsts = True
                    hsts_details.append(f"Port {port}/{transport}: Enabled ({hsts_header})")
                else:
                    pass 
            elif transport == 'tcp' and (port == 80 or port == 443 or port == 8080):
                 pass

        if found_hsts:
            return {"hsts": "Enabled", "hsts_details": hsts_details, "shodan_data": host.get('org', 'Unknown Organization')}
        else:
             return {"hsts": "Not Present", "shodan_data": host.get('org', 'Unknown Organization')}
    
    except shodan.APIError as e:
        print(f"\nError: {e}")
        return {"hsts": f"Error: {e}", "shodan_data": "N/A"}
    except Exception as e:
        print(f"Error: {e}")
        return {"hsts": f"Error: {str(e)}", "shodan_data": "N/A"}

if __name__ == "__main__":
    if not API_KEY or API_KEY == "YOUR_SHODAN_API_KEY_HERE":
        print("Error: SHODAN_API_KEY is not set or is still the placeholder.")
        print("Please edit .env and set your valid Shodan API key.")
        exit(1)

    api = shodan.Shodan(API_KEY)
    
    try:
        # Check plan information first
        info = api.info()
        print(f"[+] API Key Valid. Plan: {info.get('plan', 'Unknown')}")
        print(f"[+] Query credits: {info.get('query_credits', 'Unknown')}")
        print(f"[+] Scan credits:  {info.get('scan_credits', 'Unknown')}\n")

        user_input = input("Enter Target IP or Domain: ").strip()
        
        if not user_input:
            print("[-] No input provided. Exiting.")
            exit()
            
        result = get_shodan_data(user_input)
        print(result)

    except shodan.APIError as e:
        print(f"\nError: {e}")