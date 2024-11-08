import dns.resolver
from concurrent.futures import ThreadPoolExecutor

def enumerate_and_check_subdomains(domain):
    subdomain_list = [
        'www', 'mail', 'ftp', 'test', 'dev', 'api', 'blog', 'shop', 'secure',
        'smtp', 'pop', 'imap', 'webmail', 'admin', 'dashboard', 'vpn', 
        'support', 'portal', 'uploads', 'test1', 'test2', 'm', 'static', 
        'intranet', 'docs', 'forum', 'news', 'images', 'video', 'store',
        'app', 'cdn', 'search', 'git', 'gitlab', 'jenkins', 'ci',
        'beta', 'local', 'devops', 'remote', 'files', 'service',
        'api1', 'api2', 'api3', 'testapi', 'mail1', 'mail2',
        'blog1', 'blog2', 'account', 'shop1', 'testshop', 'checkout',
        'monitor', 'metrics', 'metrics1', 'static1', 'static2',
        'files1', 'files2', 'admin1', 'admin2', 'support1', 'support2',
        'portal1', 'portal2', 'help', 'contact', 'feedback',
        'devportal', 'wiki', 'kb', 'knowledgebase', 'reports',
        'uploads1', 'uploads2', 'assets', 'staticfiles', 'cdn1',
        'cdn2', 'download', 'downloads', 'sandbox', 'api-docs',
        'api-test', 'dev1', 'dev2', 'api-gateway', 'api-v1', 'api-v2',
        'testbed', 'platform', 'service1', 'service2', 'events',
        'status', 'status1', 'status2', 'sandbox1', 'qa',
        'demo', 'demo1', 'demo2', 'events1', 'events2',
        'static-assets', 'temp', 'temp1', 'temp2', 'backup',
        'testing', 'analytics', 'cloud', 'cloud1', 'cloud2',
        'registry', 'registry1', 'registry2', 'repo', 'repo1',
        'repo2', 'v1', 'v2', 'v3', 'legacy', 'legacy1', 'legacy2',
        'dev-env', 'production', 'prod', 'staging', 'stage',
        'live', 'live1', 'live2', 'beta1', 'beta2',
        'shop-test', 'test-site', 'preview', 'preview1', 'test-env',
        'api-v3', 'docs1', 'docs2'
    ]
    found_subdomains = []
    
    def check_subdomain(subdomain):
        full_domain = f"{subdomain}.{domain}"
        try:
            # Attempt to resolve the subdomain
            dns.resolver.resolve(full_domain, 'A')
            return full_domain, True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return full_domain, False
        except Exception as e:
            print(f"Error resolving {full_domain}: {e}")
            return full_domain, False

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(check_subdomain, subdomain_list)
        for full_domain, exists in results:
            if exists:
                found_subdomains.append(full_domain)

    return found_subdomains
