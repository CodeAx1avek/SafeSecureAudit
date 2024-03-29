import requests

url = "https://netdetective.p.rapidapi.com/query"

querystring = {"ipaddress":"172.66.41.24"}

headers = {
	"X-RapidAPI-Key": "9814b3a6d1msh41b9e25311f05bap13521ejsn9147e8e70ae1",
	"X-RapidAPI-Host": "netdetective.p.rapidapi.com"
}

response = requests.get(url, headers=headers, params=querystring)

print(response.json())


# <!-- ----------------------------------------------------------------------------------------- -->


# <!-- import requests

# url = "https://ip-iq.p.rapidapi.com/ip"

# querystring = {"ip":"185.246.188.140"}

# headers = {
# 	"X-RapidAPI-Key": "9814b3a6d1msh41b9e25311f05bap13521ejsn9147e8e70ae1",
# 	"X-RapidAPI-Host": "ip-iq.p.rapidapi.com"
# }

# response = requests.get(url, headers=headers, params=querystring)

# print(response.json()) -->


# <!-- Easily turn IPs into detailed country+network info and True/False for if they’re datacenters, proxies/tor/vpn, malicious, or have recently been found on important blacklists (and if so, how many). The JSON object also returns network/cidr the IP is under, and the network’s name and ASN.

# The IP IQ API was created because existing IP APIs are slow, expensive, only focus on one thing, or use data and lists several years out of date. We recompile the datasets twice a day and are constantly trawling lists and the latest network data so your website or software can have instant access to high confidence origin traffic information.

# The basic geolocation feature is powered by IP2Location (98% country-level confidence) and further enriched with useful info like the country’s various codes (UN M49, ISO 3166-1 alpha-2 and 3, UN/LOCODE), ISO 4217 currency code, assigned domain ccTLD, E164 telephone calling code, EU and EEA membership status, various VAT rates if applicable, as well as arrays of the country’s official and spoken languages in ISO 639 format.

# Additional IP info returned in the JSON object:

#     True/False: if the IP is a Bogon address
#     True/False: if the IP belongs to an entity on the current list of OFAC sanctions (data from orpa . princeton . edu)
#     True/False: if the IP belongs to an entity on the current list of State Sponsors of Terrorism (data from state . gov)

# Note that user errors (invalid IP, etc) result in a 400 HTTP code with the error explained in the field “detail”.
# Show less -->