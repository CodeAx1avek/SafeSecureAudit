import requests
from wafw00f.main import WAFW00F
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ssl

# Function to create a session with retry logic
def create_session():
    session = requests.Session()
    retry = Retry(
        total=3,  # Retry 3 times
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],  # Retry on certain errors
        method_whitelist=["HEAD", "GET", "POST"]  # Retry only specific HTTP methods
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def check_waf(url):
    # Create a session for handling retries and SSL issues
    session = create_session()

    # Create a WAFW00F object
    waf = WAFW00F(target=url)

    try:
        # Run the scan (this will use the internal session handling of WAFW00F)
        waf_name = waf.identwaf()  # No session argument needed here
        return waf_name if waf_name else None

    except requests.exceptions.SSLError as e:
        # Handle SSL error
        return f"SSL/TLS Error: {e}"

    except Exception as e:
        # Catch all other exceptions
        return f"Error: {e}"

