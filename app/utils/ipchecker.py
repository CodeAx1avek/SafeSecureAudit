import requests
import html


def sanitize_html(text: str) -> str:
    """Escape special HTML characters to prevent injection issues."""
    return html.escape(text, quote=False)


def extract_between(source: str, start: str, end: str) -> str:
    """Extracts text between two substrings safely."""
    try:
        return source.split(start)[1].split(end)[0]
    except IndexError:
        return "n/a"


def fetch_ip_details(ip: str) -> dict:
    """Fetches IP fraud details from Scamalytics and returns a dictionary."""
    url = f"https://scamalytics.com/ip/{ip}"
    response = requests.get(url)

    if response.status_code != 200:
        return {"error": "Unable to fetch details. Please check the IP and try again."}

    return {
        "score": extract_between(response.text, '"score":"', '",'),
        "risk": extract_between(response.text, '"risk":"', '"'),
        "hostname": extract_between(response.text, "<th>Hostname</th>\n                <td>", "</td>"),
        "asn": extract_between(response.text, "<th>ASN</th>\n                <td>", "</td>"),
        "isp": extract_between(response.text, 'https://scamalytics.com/ip/isp/', '">'),
        "organization": extract_between(response.text, "<th>Organization Name</th>\n                <td>", "</td>"),
        "connection": extract_between(response.text, "<th>Connection type</th>\n                <td>", "</td>"),
        "country": extract_between(response.text, "<th>Country Name</th>\n                <td>", "</td>"),
        "state": extract_between(response.text, "<th>State / Province</th>\n                <td>", "</td>"),
        "city": extract_between(response.text, "<th>City</th>\n                <td>", "</td>"),
        "postal": extract_between(response.text, "<th>Postal Code</th>\n                <td>", "</td>"),
        "latitude": extract_between(response.text, "<th>Latitude</th>\n                <td>", "</td>"),
        "longitude": extract_between(response.text, "<th>Longitude</th>\n                <td>", "</td>"),
        "vpn": extract_between(response.text, '<th>Anonymizing VPN</th>\n                <td><div class="risk ', '">'),
        "tor": extract_between(response.text, '<th>Tor Exit Node</th>\n                <td><div class="risk ', '">'),
        "public_proxy": extract_between(response.text, '<th>Public Proxy</th>\n                <td><div class="risk ', '">'),
        "web_proxy": extract_between(response.text, '<th>Web Proxy</th>\n                <td><div class="risk ', '">'),
        "search_engine_bot": extract_between(response.text, '<th>Search Engine Robot</th>\n                <td><div class="risk ', '">'),
        "domain_name": extract_between(response.text, '<td colspan="2" class="colspan">', "</td>"),
    }
