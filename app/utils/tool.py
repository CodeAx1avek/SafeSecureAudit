import dns.resolver
import requests
import re
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

def dns_record_lookup(domain_name, record_type):
    try:
        answers = dns.resolver.resolve(domain_name, record_type)
        result = [r.to_text() for r in answers]
        return result
    except dns.resolver.NoAnswer:
        return ["No {} record found for {}".format(record_type, domain_name)]
    except dns.resolver.NXDOMAIN:
        return ["Domain {} does not exist".format(domain_name)]
    except dns.resolver.Timeout:
        return ["Timeout occurred while performing DNS lookup"]
    except dns.exception.DNSException as e:
        return ["DNS lookup error: {}".format(str(e))]

def dnslookup(domain_name):
    url = f"https://api.hackertarget.com/dnslookup/?q={domain_name}"
    response = requests.get(url)
    if response.status_code == 200:
        output = {}
        lines = response.text.split('\n')
        for line in lines:
            if line.strip():
                if ':' in line:
                    record_type, value = line.split(':', 1)
                    record_type = record_type.strip()
                    value = value.strip()
                    if record_type in output:
                        output[record_type].append(value)
                    else:
                        output[record_type] = [value]
                else:
                    output['Unknown'] = [line.strip()]
        return output
    else:
        return None



def reverse_dns(domain_name):
    url = f"https://api.hackertarget.com/reversedns/?q={domain_name}"
    response = requests.get(url)
    
    if response.status_code == 200:
        results = response.text.splitlines()
        return results
    else:
        return None
def ipgeotool(domain_name):
    url = f"https://api.hackertarget.com/ipgeo/?q={domain_name}"
    response = requests.get(url)
    
    if response.status_code == 200:
        results = response.text.splitlines()
        return results
    else:
        return None
    
def page_extract(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a', href=True)]

        if not links:
            return [], "No links found on the page."

        return links, None
    
    except RequestException as e:
        return [], f"An error occurred: {str(e)}"


def extract_emails(url):
    try:
        # Send HTTP request to the URL with a timeout and headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        response = requests.get(f"http://{url}", headers=headers, timeout=10)
        response.raise_for_status()

        # Get the HTML content of the page
        html_content = response.text

        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')

        # Extract text from key sections only (like body, footer, etc.)
        page_text = soup.find('body').get_text() if soup.find('body') else soup.get_text()

        # Regular expression pattern for extracting emails
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

        # Find all email addresses in the page text
        emails = re.findall(email_pattern, page_text)

        # Remove duplicates by converting the list to a set
        unique_emails = set(emails)

        return list(unique_emails)

    except requests.exceptions.RequestException as e:
        # Handle error and return an empty list if the request fails
        return []

def fetch_all_in_one_data(domain_name):
    url = f"https://netlas-all-in-one-host.p.rapidapi.com/host/{domain_name}/"
    querystring = {"source_type": "include", "fields[0]": "*"}
    headers = {
        "X-RapidAPI-Key": "9814b3a6d1msh41b9e25311f05bap13521ejsn9147e8e70ae1",
        "X-RapidAPI-Host": "netlas-all-in-one-host.p.rapidapi.com"
    }
    response = requests.get(url, headers=headers, params=querystring)
    if response.status_code == 200:
        return response.json()
    
    else:
        print("erorrrr")
    