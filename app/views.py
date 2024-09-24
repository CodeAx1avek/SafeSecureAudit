from django.shortcuts import render,redirect
import uuid
from .utils import ortscanner
from .utils.tool import dns_record_lookup,dnslookup,reverse_dns,ipgeotool,page_extract,extract_emails,fetch_all_in_one_data
from .utils.waf import check_waf
from .utils.tool import page_extract
from .utils.phone_info_tool import gather_phone_info
import requests,json
from django.contrib.auth import authenticate, login, logout 
from .forms import SignUpForm,LoginForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpResponse



def initialize_guest_credits(request):
    if not request.user.is_authenticated:
        user_id = request.COOKIES.get('guest_user_id')
        if not user_id:
            user_id = str(uuid.uuid4())  # Generate a new unique identifier
            response = HttpResponse()
            response.set_cookie('guest_user_id', user_id)  # Set the cookie
            request.session['credits'] = 10  # Assign credits
            return response  # Return the response to set the cookie
        else:
            # Optionally, check credits in the session or handle reinitialization logic
            if 'credits' not in request.session:
                request.session['credits'] = 10  # Reassign if needed
def index(request):
    response = initialize_guest_credits(request)

    tool = request.GET.get('tool', '')
    if request.method == 'POST':
        domain_name = request.POST.get('websiteUrl')
        if not request.user.is_authenticated:
            credits = request.session.get('credits', 0)
            if credits < 3:
                return render(request, 'no_credits.html', {'message': 'You have no credits left. Please log in to continue using the tools.'})
            request.session['credits'] -= 3
            request.session.modified = True
        if tool == "allinone":
            if domain_name.startswith(('http://', 'https://')):
                domain_name = domain_name.split('//')[1] 
            if domain_name.startswith('www.'):
                domain_name = domain_name[4:]
            domain_data = fetch_all_in_one_data(domain_name)
            return render(request, 'tools/allinone.html', {'domain_data': domain_data,"tool":tool,"domain_name":domain_name})
        
        elif tool == 'dnsresolvertool':
            if domain_name.startswith(('http://', 'https://')):
                domain_name = domain_name.split('//')[1] 
            if domain_name.startswith('www.'):
                domain_name = domain_name[4:]
            record_types = ["A", "MX", "TXT", "NS"]
            dns_results = {}
            for record_type in record_types:
                dns_results[record_type] = dns_record_lookup(domain_name, record_type)
            context = {'tool': tool, 'dns_results': dns_results}
            return render(request, 'tools/dnsresolvertool.html', context)
        
        elif tool == "dnslookuptool":
            dns_results = dnslookup(domain_name)
            return render(request, 'tools/dnslookuptool.html', {'tool':tool,'domain_name': domain_name, 'dns_results': dns_results})
        
        elif tool == "reversednstool":
            reverse_dns_results = reverse_dns(domain_name)
            return render(request, 'tools/reversednstool.html', {'tool': tool, 'domain_name': domain_name, 'reverse_dns_results': reverse_dns_results})
        
        elif tool  == "ipgeotool":
            if domain_name.startswith(('http://', 'https://')):
                domain_name = domain_name.split('//')[1] 
            if domain_name.startswith('www.'):
                domain_name = domain_name[4:]
            ipgeotool_results = ipgeotool(domain_name)
            return render(request, 'tools/ipgeotool.html', {'tool': tool, 'domain_name': domain_name, 'ipgeotool_results': ipgeotool_results})
      
        elif tool == "page_extract":
            page_extract_results = []
            error_message = None
            page_extract_results, error_message = page_extract(domain_name)
            context = {
                'tool': tool,
                'domain_name': domain_name,
                'page_extract_results': page_extract_results,
                'error_message': error_message
                 }
            return render(request, 'tools/page_extract.html', context)

        elif tool == 'portscanner':
            if domain_name.startswith(('http://', 'https://')):
                domain_name = domain_name.split('//')[1]
            if domain_name.startswith('www.'):
                domain_name = domain_name[4:]
            if domain_name.endswith('/'):
                domain_name = domain_name[:-1] 

            open_ports = ortscanner.port_scan(domain_name)
            context = {'open_ports': open_ports, 'tool': tool, 'domain_name': domain_name}
            return render(request, 'tools/portscanner.html', context)
        
        elif tool == 'waf':
            if not domain_name.startswith(('http://', 'https://')):
                domain_name = "https://" + domain_name
            waf_name = check_waf(domain_name)
            context = {'tool': tool, 'waf_name': waf_name, 'domain_name': domain_name}
            return render(request, 'tools/waf.html', context)
        
        elif tool == "phoneinfo":
            phone_info_results = gather_phone_info(domain_name)
            return render(request, 'tools/phoneinfo.html', {'tool': tool, 'domain_name': domain_name, 'phone_info_results': phone_info_results})
        
        elif tool == "extract_emails":
            extract_emails_results = extract_emails(domain_name)
            return render(request, 'tools/extract_emails.html', {'tool': tool, 'domain_name': domain_name,'extract_emails_results':extract_emails_results})
        
        elif tool == "breachdata":
            url = "https://credential-verification.p.rapidapi.com/restpeopleMOB/MA/MaWcf.svc/Makshouf"
            payload = {
                "Service_Flag": "",
                "Criterias": [
                    {
                "Field": "page",
                "Value": "1"
                    },
                    {
                "Field": "SEARCH_KEY",
                "Value": domain_name
                    }
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
                    summary.append({'breach_name': breach.get('BREACH_NAME', ''),
                            'breach_summary': breach.get('BREACH_SUMMARY', '')})

            return render(request, 'tools/breachdata.html', {"message": message, "tool": tool, 'domain_name': domain_name, 'summary': summary})
        else:
            return render(request, 'index.html', {'error_message': 'Please select provided tool on sidebar.'})
        
    if request.method == 'GET':
        if tool == "allinone":
             return render(request, 'tools/allinone.html')
        
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


@login_required
def dashboard(request):
    data = {
        'user_count': User.objects.count(), 
        'recent_signups': User.objects.order_by('-date_joined')[:5], 
    }
    return render(request, 'dashboard.html', data)


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