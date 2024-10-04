from django.shortcuts import render,redirect
from .utils import portscanners
from .utils.tool import dns_record_lookup,dnslookup,reverse_dns,ipgeotool,page_extract,extract_emails,fetch_all_in_one_data
from .utils.ssl_checker import ssl_check
from .utils.waf import check_waf
from .utils.subdomain_enum import enumerate_and_check_subdomains
from .models import Scan
from .utils.tool import page_extract
from .utils.phone_info_tool import gather_phone_info
import requests,json
from django.contrib.auth import authenticate, login, logout 
from .forms import SignUpForm,LoginForm
from django.contrib.auth.decorators import login_required

def save_scan(user, domain_name, tool_used):
    if user.is_authenticated:
        Scan.objects.create(user=user, domain_name=domain_name, tool_used=tool_used)

def index(request):
    tool = request.GET.get('tool', '')
    if request.method == 'POST':
        domain_name = request.POST.get('websiteUrl')
        if not domain_name:
            return render(request, 'index.html', {'message': 'Please enter a valid domain name.'})
        domain_name = sanitize_domain(domain_name)  # Ensure the domain is sanitized

        # Create a record for each tool
        if tool == "allinone":
            domain_data = fetch_all_in_one_data(domain_name)
            # Save the scan
            save_scan(request.user, domain_name, tool)
            return render(request, 'tools/allinone.html', {'domain_data': domain_data, "tool": tool, "domain_name": domain_name})
        
        elif tool == 'dnsresolvertool':
            record_types = ["A", "MX", "TXT", "NS"]
            dns_results = {record_type: dns_record_lookup(domain_name, record_type) for record_type in record_types}
            save_scan(request.user, domain_name, tool)
            context = {'tool': tool, 'dns_results': dns_results}
            return render(request, 'tools/dnsresolvertool.html', context)

        elif tool == "dnslookuptool":
            dns_results = dnslookup(domain_name)
            save_scan(request.user, domain_name, tool)
            return render(request, 'tools/dnslookuptool.html', {'tool': tool, 'domain_name': domain_name, 'dns_results': dns_results})

        elif tool == "reversednstool":
            reverse_dns_results = reverse_dns(domain_name)
            save_scan(request.user, domain_name, tool)
            return render(request, 'tools/reversednstool.html', {'tool': tool, 'domain_name': domain_name, 'reverse_dns_results': reverse_dns_results})

        elif tool == "ipgeotool":
            ipgeotool_results = ipgeotool(domain_name)
            save_scan(request.user, domain_name, tool)
            return render(request, 'tools/ipgeotool.html', {'tool': tool, 'domain_name': domain_name, 'ipgeotool_results': ipgeotool_results})
        
        elif tool == "page_extract":
            if not domain_name.startswith(('http://', 'https://')):
                domain_name = "https://" + domain_name
            page_extract_results, error_message = page_extract(domain_name)
            save_scan(request.user, domain_name, tool)
            context = {
                'tool': tool,
                'domain_name': domain_name,
                'page_extract_results': page_extract_results,
                'error_message': error_message
            }
            return render(request, 'tools/page_extract.html', context)
        
        elif tool == "dork":
            google_dorks = generate_dorks(domain_name)
            save_scan(request.user, domain_name, tool)
            return render(request, "tools/dork.html", {'google_dorks': google_dorks, 'domain_name': domain_name})

        elif tool == 'portscanner':
            open_ports = portscanners.scan_port(domain_name)
            save_scan(request.user, domain_name, tool)
            context = {'open_ports': open_ports, 'tool': tool, 'domain_name': domain_name}
            return render(request, 'tools/portscanner.html', context)

        elif tool == 'waf':
            if not domain_name.startswith(('http://', 'https://')):
                domain_name = "https://" + domain_name
            waf_name = check_waf(domain_name)
            save_scan(request.user, domain_name, tool)
            context = {'tool': tool, 'waf_name': waf_name, 'domain_name': domain_name}
            return render(request, 'tools/waf.html', context)
        
        elif tool == "ssl_checker_tool":
            domain_name = domain_name.lstrip('http://').lstrip('https://')
            ssl_results = ssl_check(domain_name) 
            save_scan(request.user, domain_name, tool)
            return render(request, 'tools/ssl_checker.html', {
            'tool': tool,
            'domain_name': domain_name,
            'ssl_results': ssl_results,
        })

        elif tool == "subdomain_enum_tool":
            found_subdomains = enumerate_and_check_subdomains(domain_name)
            save_scan(request.user, domain_name, tool)
            return render(request, 'tools/subdomain_enum.html', {
                'tool': tool,
                'domain_name': domain_name,
                'found_subdomains': found_subdomains,
                'scan_done': True, 
            })
        
        elif tool == "phoneinfo":
            phone_info_results = gather_phone_info(domain_name)
            save_scan(request.user, domain_name, tool)
            return render(request, 'tools/phoneinfo.html', {'tool': tool, 'domain_name': domain_name, 'phone_info_results': phone_info_results})

        elif tool == "extract_emails":
            extract_emails_results = "we are working on it"
            save_scan(request.user, domain_name, tool)
            return render(request, 'tools/extract_emails.html', {'tool': tool, 'domain_name': domain_name, 'extract_emails_results': extract_emails_results})

        elif tool == "breachdata":
            url = "https://credential-verification.p.rapidapi.com/restpeopleMOB/MA/MaWcf.svc/Makshouf"
            payload = {
                "Service_Flag": "",
                "Criterias": [
                    {"Field": "page", "Value": "1"},
                    {"Field": "SEARCH_KEY", "Value": domain_name}
                ]
            }
            headers = {
                "content-type": "application/json",
                "X-RapidAPI-Key": "9814b3a6d1msh41b9e25311f05bap13521ejsn9147e8e70ae1", 
                "X-RapidAPI-Host": "credential-verification.p.rapidapi.com"
            }
            response = requests.post(url, json=payload, headers=headers)
            result = response.json()
            message = ""

            summary = []
            if 'Count' in result and result['Count'] > 0:
                message = result['Message']
                breaches = json.loads(result['Result'])  # Parsing the JSON string
                for breach in breaches:
                    summary.append({
                        'breach_name': breach.get('BREACH_NAME', ''),
                        'breach_summary': breach.get('BREACH_SUMMARY', '')
                    })

            save_scan(request.user, domain_name, tool)
            return render(request, 'tools/breachdata.html', {"message": message, "tool": tool, 'domain_name': domain_name, 'summary': summary})

        else:
            return render(request, 'index.html', {'error_message': 'Please select a tool from the sidebar.'})
        
        
    if request.method == 'GET':
        if tool == "allinone":
             return render(request, 'tools/allinone.html')
        elif tool == "dork":
            return render(request, 'tools/dork.html')
        elif tool == 'dnsresolvertool':
            return render(request, 'tools/dnsresolvertool.html')

        elif tool == "dnslookuptool":
            return render(request, 'tools/dnslookuptool.html')
        
        elif tool == "reversednstool":
            return render(request, 'tools/reversednstool.html')
        
        elif tool  == "ipgeotool":
            return render(request, 'tools/ipgeotool.html')
        
        elif tool == "page_extract":
            return render(request, 'tools/page_extract.html')

        elif tool == 'portscanner':
            return render(request, 'tools/portscanner.html')
        
        elif tool == 'waf':
            return render(request, 'tools/waf.html')
        
        elif tool == "phoneinfo":
            return render(request, 'tools/phoneinfo.html')
        
        elif tool == "extract_emails":
            return render(request, 'tools/extract_emails.html')
        
        elif tool == "ssl_checker_tool":
            return render(request, 'tools/ssl_checker.html')
    
        elif tool == 'subdomain_enum_tool':
            return render(request, 'tools/subdomain_enum.html')

        elif tool == "breachdata":
            return render(request, 'tools/breachdata.html')
        else:
            if request.user.is_authenticated:
                return redirect('dashboard') 
            return render(request, 'index.html', {'error_message': 'Please select provided tool on sidebar.'})

def learning(request):
    if request.method == 'GET':
            return render(request,template_name="learning.html")
        
def Allaboutbugbounty(request):
    if request.method == 'GET':
            return render(request,template_name="vuln10.html")

    
def termsandcondition(request):
    return render(request,template_name="termsandcondition.html")

def bughuntingmethodology(request):
    return render(request,template_name="bughuntingmethodology.html")

def huntchecklist(request):
    return render(request,template_name="huntchecklist.html")


# views.py
@login_required
def dashboard(request):
    recent_scans = Scan.objects.filter(user=request.user).order_by('-timestamp')[:5]
    return render(request, 'dashboard.html', {'recent_scans': recent_scans})


def user_signup(request):
    if request.user.is_authenticated: 
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
            return redirect('dashboard') 
    else:
        form = SignUpForm()

    return render(request, 'signup.html', {'form': form})

def user_login(request):
    if request.user.is_authenticated: 
        return redirect('dashboard')  
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                return redirect('dashboard')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

def profile(request):
    return render(request,template_name="profile.html")
def user_logout(request):
    logout(request)
    return redirect('login')


def sanitize_domain(domain_name):
    if domain_name.startswith(('http://', 'https://')):
        domain_name = domain_name.split('//')[1]
    if domain_name.startswith('www.'):
        domain_name = domain_name[4:]
    return domain_name

def generate_dorks(domain_name):
    """Generates a list of advanced Google Dork queries for recon on a target domain."""
    dorks = [
        f'site:{domain_name} inurl:admin',  # Admin panels
        f'site:{domain_name} intitle:"index of"',  # Directory listings
        f'site:{domain_name} ext:php',  # PHP pages (commonly vulnerable)
        f'site:{domain_name} ext:sql | ext:db | ext:bak',  # Database files
        f'site:{domain_name} "login" | "signin"',  # Login pages
        f'site:{domain_name} "forgot password" | "reset password"',  # Password reset pages
        f'site:{domain_name} "config.php" | "wp-config.php"',  # Configuration files (PHP)
        f'site:{domain_name} "password" filetype:txt | filetype:log',  # Passwords in text/log files
        f'site:{domain_name} filetype:log',  # Log files (might contain sensitive data)
        f'site:{domain_name} filetype:sql | filetype:db | filetype:sql.gz',  # Exposed database dumps
        f'site:{domain_name} inurl:/wp-admin/',  # WordPress admin login
        f'site:{domain_name} inurl:dashboard',  # Admin dashboards
        f'site:{domain_name} inurl:ftp',  # Exposed FTP services
        f'site:{domain_name} ext:xml | ext:json "api"',  # API keys or sensitive data in XML/JSON
        f'site:{domain_name} ext:env',  # Environment configuration files (.env)
        f'site:{domain_name} "intitle:login" "admin"',  # Admin login portals
        f'site:{domain_name} intext:"credentials" | intext:"username" | intext:"password"',  # Credential leaks
        f'site:{domain_name} filetype:pdf | filetype:xls | filetype:doc | filetype:csv "confidential"',  # Exposed documents
        f'site:{domain_name} "htaccess" | "robots.txt" | "sitemap.xml"',  # Access control files
        f'site:{domain_name} inurl:"/cgi-bin/"',  # Common CGI vulnerabilities
        f'site:{domain_name} "Powered by WordPress" | "Joomla" | "Drupal"',  # Identify CMS for exploitation
        f'site:{domain_name} "phpinfo" "version"',  # PHP info pages (leak server info)
        f'site:{domain_name} inurl:"shell" | intitle:"shell" filetype:php',  # Possible backdoors or web shells
        f'site:{domain_name} "Apache Status" | "nginx status"',  # Exposed server status pages
        f'site:{domain_name} filetype:bak | filetype:old | filetype:backup',  # Backup files
    ]
    return dorks
