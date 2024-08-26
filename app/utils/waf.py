from wafw00f.main import WAFW00F

def check_waf(url):
    # Create a WAFW00F object
    waf = WAFW00F(target=url)
    
    # Run the scan
    waf_name = waf.identwaf()

    # Return WAF name or None if no WAF is detected
    return waf_name if waf_name else None
