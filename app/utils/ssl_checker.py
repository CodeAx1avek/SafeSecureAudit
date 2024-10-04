# ssl_checker.py
import ssl
import socket
from datetime import datetime

def ssl_check(hostname, port=443):
    try:
        # Create an SSL context
        context = ssl.create_default_context()
        # Establish a connection to the server
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Get certificate details
                cert_info = {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'notBefore': cert['notBefore'],
                    'notAfter': cert['notAfter'],
                    'version': cert['version'],
                    'fingerprint': ssl.DER_cert_to_PEM_cert(ssock.getpeercert(binary_form=True)).strip(),
                }

                # Check certificate validity
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                current_time = datetime.utcnow()

                # Certificate validity check
                is_valid = not_after > current_time and not_before < current_time

                return {
                    'is_valid': is_valid,
                    'validity_period': {
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                    },
                    'certificate_info': cert_info
                }

    except ssl.SSLError as ssl_err:
        return {'error': f'SSL error: {ssl_err}'}
    except socket.gaierror as addr_err:
        return {'error': f'Address error: {addr_err}'}
    except Exception as e:
        return {'error': f'An unexpected error occurred: {str(e)}'}
