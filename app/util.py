def get_client_ip(request):
    # Try to get the client's real IP from the 'X-Forwarded-For' header
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]  # Get the first IP in the list
    else:
        ip = request.META.get('REMOTE_ADDR')  # Fallback to REMOTE_ADDR if no proxy
    return ip
