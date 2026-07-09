import requests
import re
import sys
import json
from urllib.parse import urlparse

# --- SENSITIVE PATTERNS ---
# Focused on finding endpoints that typically hold credentials, configs, or admin panels.
SENSITIVE_REGEX = r'.*(admin|api|v1|v2|config|env|secret|login|auth|dashboard|internal|private|backup|sql|db|git|jenkins|jira).*'



def get_wayback_data(domain):
    """
    Queries the Wayback Machine for all URLs associated with the domain
    and returns a structured dictionary with sensitive findings.
    """
    # Clean domain if passed with schema
    domain = domain.replace("http://", "").replace("https://", "").split('/')[0]

    # Using wildcard (*.) to include subdomains as well
    cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original"

    session = requests.Session()
    retries = requests.adapters.Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retries))

    urls = []
    try:
        response = session.get(cdx_url, timeout=60)
        response.raise_for_status()
        data = response.json()

        if len(data) > 1:
            urls = [item[0] for item in data[1:]]
    except Exception as e:
        pass 

    # Filter for sensitive endpoints
    pattern = re.compile(SENSITIVE_REGEX, re.IGNORECASE)
    sensitive_list = sorted(list({u for u in urls if pattern.match(u)}))

    # Return raw list for frontend to handle, limited to top 500
    return {
        "web_hub": {
            "sensitive": sensitive_list[:500] if sensitive_list else []
        }
    }

def main():
    # Accept input from command line (for automation) or manual prompt
    target = sys.argv[1] if len(sys.argv) > 1 else input("Enter Domain: ").strip()
    
    data = get_wayback_data(target)
    print(json.dumps(data, indent=4))


if __name__ == "__main__":
    main()