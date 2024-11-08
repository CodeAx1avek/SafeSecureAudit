from django.http import HttpResponseForbidden
from .models import BlockedIP
from .util import get_client_ip 

class BlockIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = get_client_ip(request)  # Get the real IP address

        # Check if the IP address is in the blocked list
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Access Denied: Your IP address has been blocked.")

        return self.get_response(request)
