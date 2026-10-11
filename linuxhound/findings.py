from __future__ import annotations

LABELS = {
    'writable-root-job': ('Writable file named by a root job', 'high', 'Protect the named file and parent directory from unintended writers; review whether it is code or data.'),
    'service-influence': ('Writable service dependency or configuration', 'medium', 'Review file ownership, ACLs, parent replacement rights and service reload permissions.'),
    'sudo': ('Sudo privilege grant to review', 'medium', 'Review the exact command policy, authentication requirement and intended administrator role.'),
    'suid-execute': ('Executable setuid grant to review', 'medium', 'Review whether the application needs setuid and whether its behavior permits unintended privilege.'),
    'capability-execute': ('Executable file capability to review', 'medium', 'Review the capability, program behavior, mount flags, namespaces and process bounding set.'),
    'docker-group': ('Docker group membership to review', 'high', 'Verify whether Docker API access is intended; restrict the socket and administrator membership.'),
    'docker-boundary': ('Privileged container or Docker socket exposure', 'high', 'Review privileged mode, socket binds and the actual user-namespace boundary.'),
}


def findings(report: dict) -> list[dict]:
    analysis = report.get('analysis') or {}
    result = []
    seen = set()
    for path in list(analysis.get('paths') or []) + list(analysis.get('service_paths') or []):
        key = tuple(sorted(step['edge_id'] for step in path.get('steps') or []))
        if key in seen:
            continue
        seen.add(key)
        account = next((node for node in report['nodes'] if node['id'] == path.get('account_id')), None)
        is_admin = path.get('authority') == 'legitimate_administrator' or bool(account and account.get('properties', {}).get('designated_admin'))
        if is_admin and not path.get('verified'):
            continue
        title, priority, recommendation = LABELS.get(path['pattern'], ('Conditional privilege relationship', 'medium', 'Review the recorded prerequisites and intended access policy.'))
        result.append({
            'id': 'finding/' + path['id'].split('/')[-1], 'title': title,
            'priority': priority, 'status': 'externally_verified' if path.get('verified') else 'needs_review',
            'classification': 'verified_vulnerability' if path.get('verified') else 'configuration_exposure',
            'impact': 'verified_vulnerability' if path.get('verified') else 'conditional',
            'summary': path['summary'], 'path_id': path['id'],
            'node_ids': path.get('node_ids') or [],
            'edge_ids': [step['edge_id'] for step in path.get('steps') or []],
            'evidence_ids': path.get('evidence_ids') or [],
            'prerequisites': path.get('prerequisites') or [], 'recommendation': recommendation,
            'coverage_domains': path.get('coverage_domains') or [],
        })
    coverage = report['collection'].get('coverage') or {}
    gaps = [key + '=' + str(value) for key, value in coverage.items() if value != 'complete']
    if gaps:
        result.append({'id': 'finding/coverage', 'title': 'Collection gaps', 'priority': 'info',
            'status': 'incomplete_evidence', 'classification': 'coverage_gap', 'impact': 'unknown',
            'summary': 'Missing coverage is not evidence of safety: ' + ', '.join(gaps),
            'node_ids': ['host/' + report['host']['id'] + '/' + report['host']['id']],
            'edge_ids': [], 'evidence_ids': [], 'prerequisites': [],
            'recommendation': 'Collect the missing domains with authorized access before assessing absence of paths.'})
    return sorted(result, key=lambda finding: ({'high': 0, 'medium': 1, 'info': 2}[finding['priority']], finding['title'], finding['id']))
