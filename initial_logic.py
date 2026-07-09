# Connects to 4 files (whois.py, geoiplookup.py, theharvester.py, shodan_tool.py) with the logic of the initial scan

import whois
import geoiplookup
import theharvester
import shodan_tool

def run_initial_scan(target):
    
    result = {}

    # Whois Scan (whois.py)
    whois_data = whois.get_whois_details(target)
    if whois_data:
        result.update(whois_data)

    # GeoIP Scan (geoiplookup.py)
    geo_data = geoiplookup.get_geo_info(target)
    if geo_data:
        result["country"] = geo_data.get("Country")
        result["city"] = geo_data.get("City")

    # Shodan Scan (shodan_tool.py)
    shodan_data = shodan_tool.get_shodan_data(target)
    if shodan_data:
        result.update(shodan_data)
    else:
        result["hsts"] = "Not Scanned"
    
    # TheHarvester Scan (theharvester.py)
    theharvester_data = theharvester.get_theharvester_data(target)
    if theharvester_data:
        result.update(theharvester_data)
        
    return {"initial_id": result}