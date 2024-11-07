import socket

def scan_port(domain, ports=None):
    open_ports = {}
    
    # Default ports to scan if none are provided
    if ports is None:
        ports = [
            443, 80, 21, 22, 8080, 23, 25, 53, 110, 123, 143, 
            465, 587, 993, 995, 3306, 3389, 
            8443, 389, 137, 138, 139, 445
        ]
    
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return {'error': f"Failed to resolve domain: {domain}"}
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = sock.connect_ex((ip, port))  # 0 means port is open
            if result == 0:
                open_ports[port] = 'Open'
            sock.close()
        except Exception as e:
            # Do nothing for closed ports
            continue
    
    return {'open_ports': open_ports}
