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


import logging

logger = logging.getLogger(__name__)

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
        logger.error(f"An error occurred: {str(e)}")
        return [], f"An error occurred: {str(e)}"



def extract_emails(url):
    try:
        response = requests.get(url)
        response.raise_for_status() 
        if response.status_code == 200:
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text)
            return emails
        else:
            print("Failed to fetch the webpage. Status code:", response.status_code)
            return []
    except requests.RequestException as e:
        print("Error occurred during HTTP request:", e)
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
    