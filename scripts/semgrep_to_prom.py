import json
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

registry = CollectorRegistry()
g = Gauge('vuln_total', 'Count of vulnerabilities by category',
          ['tool', 'owasp_category', 'severity', 'status'],
          registry=registry)

with open('semgrep.json') as f:
    data = json.load(f)

for finding in data.get('results', []):
    owasp = finding.get('metadata', {}).get('owasp', ["Unlabeled"])[0]
    severity = finding.get('extra', {}).get('severity', "info").lower()
    g.labels(tool='semgrep', owasp_category=owasp, severity=severity, status='open').inc()

push_to_gateway('localhost:9091', job='vulnhunter', registry=registry)
