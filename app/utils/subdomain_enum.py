import dns.resolver
from concurrent.futures import ThreadPoolExecutor

def enumerate_and_check_subdomains(domain):
    subdomain_list = [
    'api-v4', 'api-v5', 'api-v6', 'v4', 'v5', 'v6', 'microservices', 'microservice', 
    'container', 'container1', 'container2', 'kubernetes', 'k8s', 'k8s1', 'k8s2', 
    'data-api', 'db-api', 'db-server', 'db-prod', 'db-staging', 'db-backup', 'sql-db', 
    'no-sql', 'graph-db', 'redis', 'mongo', 'postgres', 'mysql', 'dev-server', 'test-db', 
    'infrastructure', 'infra', 'infra1', 'infra2', 'maintenance1', 'maintenance2', 'sso',
    'saml', 'oidc', 'openid', 'gateway', 'loadbalancer', 'balance', 'cdn-api', 'cloud-api', 
    'cloudfront1', 'cloudfront2', 'edge-service', 'load-balancer', 'global-edge', 'cloud-edge',
    'webhooks1', 'webhooks2', 'internal-api', 'admin-api', 'api-server', 'auth-api', 'oauth',
    'auth0', 'identity', 'sso-service', 'identity-provider', 'auth-service', 'oauth2', 'jwt', 
    'tfa', '2fa', 'firewall1', 'firewall2', 'proxy', 'vpn-service', 'nexus', 'artifactory', 
    'docker-registry', 'helm-repo', 'bitbucket', 'gitlab-ci', 'circleci', 'jenkins-ci', 
    'bitbucket-pipelines', 'ci-pipeline', 'ci-test', 'ci-release', 'automation', 'autoscale', 
    'trigger', 'dev-portal', 'api-portal', 'api-docs1', 'api-docs2', 'apidocs', 'devops1', 
    'devops2', 'release1', 'release2', 'release-candidate', 'patches1', 'patches2', 'rollback1', 
    'rollback2', 'prod-backup', 'prod-restore', 'backup-api', 'restore', 'datastore', 'replica1',
    'replica2', 'replica-db', 'data-backup', 'db-backups', 'data-recovery', 'databases1', 
    'databases2', 'datamigration', 'data-import', 'data-export', 'staging-api', 'prod-api', 
    'beta-api', 'staging-environment', 'prod-environment', 'api-testbed', 'prod-test', 'qa-environment', 
    'dev-environment', 'api-development', 'demo-environment', 'integration-api', 'integration1', 
    'integration2', 'integrations', 'integrations1', 'integrations2', 'service-discovery', 'orchestrator', 
    'service-mesh', 'databricks', 'notebooks', 'airflow', 'etl-pipeline', 'etl-process', 'datalake', 
    'ai-model', 'ai-inference', 'ml-api', 'ml-service', 'tensorboard', 'ml-model', 'mlflow', 'mlops', 
    'training', 'model-train', 'model-deploy', 'scikit-learn', 'tensorflow', 'keras', 'pytorch', 'model-serving', 
    'data-science', 'ml-team', 'model-repository', 'model-registry', 'predictive', 'forecasting', 
    'model-monitoring', 'experiment', 'experiment1', 'experiment2', 'test-model', 'model-testing',
    'buckets', 'object-storage', 'cdn-backend', 'cdn-config', 'static-backend', 'cdn-caching', 
    'video-streaming', 'video-processing', 'media-server', 'video-api', 'vod', 'live-stream', 
    'video-on-demand', 'streaming-api', 'cdn-video', 'media-storage', 'cdn-delivery', 's3', 'aws-s3', 
    'azure-storage', 'google-cloud', 'cloud-storage', 'blob-storage', 'data-sync', 'data-replication', 
    'data-cluster', 'service-cluster', 'service-discovery1', 'load-balancer1', 'cloud-loadbalancer', 
    'redis-cache', 'object-store', 's3-bucket', 'file-server', 'file-storage', 'uploads-backend', 
    'datadog', 'prometheus', 'grafana', 'alertmanager', 'logs-aggregation', 'logstash', 'elk', 
    'metrics-api', 'metrics-db', 'metrics-aggregator', 'logs-api', 'monitoring-dashboard', 'healthcheck',
    'status-dashboard', 'status-monitor', 'api-monitoring', 'alert-api', 'alert-system', 'log-monitoring', 
    'logs-dashboard', 'real-time-logs', 'metrics-dashboard', 'incident-response', 'alerting-system', 
    'incident-dashboard', 'observability', 'insights-api', 'logging-system', 'datadog-api', 'grafana-api', 
    'cloudwatch', 'aws-metrics', 'monitoring-api', 'vulnerability', 'security-monitoring', 'threat-hunting', 
    'firewall-api', 'incident-response1', 'incident-response2', 'threat-detection', 'attack-simulation', 
    'pentest', 'security-audit', 'attack-response', 'security-dashboard', 'encryption-api', 'dlp',
    'compliance', 'risk-management', 'vulnerability-scan', 'patch-management', 'security-service',
    'risk-api', 'secrets-management', 'identity-access', 'security-test', 'audit-logs', 'audit-trail', 
    'secure-logs', 'backup-logs', 'logs-secure', 'event-log', 'event-logs', 'key-management', 'key-store',
    'identity-sync', 'authentication-api', 'access-control', 'access-policy', 'app-monitoring', 
    'app-performance', 'user-performance', 'user-data', 'data-protection', 'data-security', 'business-continuity', 
    'disaster-recovery', 'data-recovery-service', 'business-api', 'crash-reports', 'error-tracking', 'error-api',
    'feedback-api', 'user-feedback', 'user-reports', 'user-comments', 'reporting-api', 'bugs', 'bug-tracker',
    'bug-reports', 'dev-feedback', 'dev-comments', 'feature-requests', 'task-tracker', 'workplace', 'workflow',
    'workflow-api', 'task-api', 'project-management', 'task-manager', 'task-list', 'project-dashboard', 
    'taskboard', 'user-feedback-api', 'service-feedback', 'incident-reports', 'incident-api'
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
