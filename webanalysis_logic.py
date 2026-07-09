# Hemanandh Tool NIKTO

import subprocess
import re
from urllib.parse import urlparse

# ================= CONFIG =================
NIKTO_PATH = r"C:\Users\yonit\OneDrive\Desktop\Project\Integration\9\nikto-master\program\nikto.pl"

def run_webanalysis_scan(raw_target):
    if raw_target.startswith(("http://", "https://")):
        parsed = urlparse(raw_target)
        target = parsed.hostname
    else:
        target = raw_target

    if not target:
        return {"error": "Invalid target"}

    # ================= RUN NIKTO =================
    cmd = [
        "perl",
        NIKTO_PATH,
        "-h", target,
        "-ssl",
        "-Tuning", "x",
        "-C", "all"
    ]

    print(f"[*] Running Nikto command: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="ignore"
        )
        output = result.stdout
        
    except Exception as e:
        return {"error": str(e)}

    regex_map = {
        # SSL / TLS Information
        "SLL Cipher": r"^\s*Ciphers:\s+(.+)",
        "SLL Issuer": r"^\s*Issuer:\s+(.+)",
        "HTTP/3 (QUIC)": r"alt-svc.*HTTP/3",

        # Server & Headers
        "Web Server": r"^\s*\+\s*Server:\s+(.+)",
        "Uncommon Header": r"Uncommon header\(s\)\s+'([^']+)'\s+found,\s+with\s+contents:\s+(.+)",
        "Missing Security Headers": r"Suggested security header missing:\s+(.+)",
        "HSTS Missing": r"Strict-Transport-Security HTTP header is not defined",
        "X Content Type Option": r"X-Content-Type-Options header is not set",

        # Vulnerability and Findings
        "Generic Finding": r"^\s*\+\s+([^:]+):\s*(.+)",

        # Errors
        "SSL Handshake": r"handshake failure",
        "Error Limit Reached": r"ERROR: Error limit",
        "Socket Error": r"already connected socket",
        "Nikto Plugin Error": r"nikto.*\.pm line \d+",
    }

    parsed_data = {}

    for title, pattern in regex_map.items():
        matches = re.findall(pattern, output, re.MULTILINE | re.IGNORECASE)
        if matches:
            parsed_data[title] = matches

    # Map parsed data to frontend keys
    def format_list(keys):
        items = []
        for key in keys:
            if key in parsed_data:
                # Join multiple matches with HTML line break for display
                # Tuple matches (captured groups) are joined by pipe first
                val_list = []
                for match in parsed_data[key][:50]:
                    # Create a nice block for each finding
                    item_text = " | ".join(match) if isinstance(match, tuple) else match
                    val_list.append(f'<div class="mb-2 pb-1 border-bottom border-secondary border-opacity-25">{item_text}</div>')
                
                if len(parsed_data[key]) > 50:
                    val_list.append(f'<div class="text-muted fst-italic">...and {len(parsed_data[key]) - 50} more</div>')
                
                val = "".join(val_list)
            else:
                val = "---"
            items.append({"label": key, "value": val})
        return items

    # Specific mapping logic akin to how frontend expects it
    final_data = {
        "ssl_info": format_list(["SLL Cipher", "SLL Issuer", "HTTP/3 (QUIC)"]),
        "header_info": format_list(["Web Server", "Uncommon Header", "Missing Security Headers", "HSTS Missing", "X Content Type Option"]),
        "findings": format_list(["Generic Finding"]),
        "errors": format_list(["SSL Handshake", "Error Limit Reached", "Socket Error", "Nikto Plugin Error"])
    }

    # Remove None values to allow frontend fallbacks
    final_data = {k: v for k, v in final_data.items() if v is not None}

    return {"website_analysis": final_data}

if __name__ == "__main__":
    # ================= TARGET INPUT =================
    raw_target_input = input("Enter IP / domain / URL: ").strip()
    
    print("\n========== NIKTO OUTPUT ==========\n")
    results = run_webanalysis_scan(raw_target_input)
    
    if "error" in results:
        print(f"Error: {results['error']}")
    else:
        for title, matches in results.items():
            print(f"{title}:")
            for match in matches:
                if isinstance(match, tuple):
                    print(" | ".join(match))
                else:
                    print(match)
            print()
