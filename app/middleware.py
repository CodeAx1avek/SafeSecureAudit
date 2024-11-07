from django.http import HttpResponseForbidden
from .models import BlockedIP

class BlockIPMiddleware:
    """
    Middleware to block requests from IPs listed in the BlockedIP model.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = request.META.get('REMOTE_ADDR')

        # Check if the IP address is in the blocked list
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Access Denied: Your IP address has been blocked.")

        return self.get_response(request)
