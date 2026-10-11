from __future__ import annotations
import copy
import hashlib
import json
import posixpath
import shlex
from linuxhound.access import can_execute, mount_for, suid_honored

SCHEMA = 'linuxhound-techniques-v1'
SOURCE = 'https://gtfobins.org/api.json'
CONTEXTS = ('sudo', 'suid', 'capabilities')
FUNCTIONS = ('shell', 'command', 'file-read', 'file-write', 'library-load', 'privilege-escalation')


def normalize_catalog(document, raw_sha256, retrieved_at):
    executables = document.get('executables')
    if not isinstance(executables, dict) or not executables:
        raise ValueError('expected the current GTFOBins API executables object')
    entries = []
    for name, binary in sorted(executables.items()):
        if not isinstance(name, str) or '/' in name or not isinstance(binary, dict):
            raise ValueError('invalid GTFOBins executable')
        for function, recipes in sorted(binary.get('functions', {}).items()):
            if function not in FUNCTIONS:
                continue
            if not isinstance(recipes, list):
                raise ValueError('invalid GTFOBins technique list')
            for i, recipe in enumerate(recipes):
                if not isinstance(recipe, dict):
                    raise ValueError('invalid GTFOBins recipe')
                for context, detail in (recipe.get('contexts') or {}).items():
                    if context not in CONTEXTS:
                        continue
                    if detail is not None and not isinstance(detail, dict):
                        raise ValueError('invalid GTFOBins context')
                    detail = detail or {}
                    caps = detail.get('list', [])
                    if not isinstance(caps, list) or any(not isinstance(c, str) or not c.lower().startswith('cap_') for c in caps):
                        raise ValueError('invalid GTFOBins capability prerequisites')
                    entries.append({'id': '%s/%s/%s/%s' % (name, function, context, i),
                        'binary': name, 'function': function, 'context': context,
                        'required_capabilities': sorted(c.lower() for c in caps),
                        'shell_dependency': detail.get('shell') if isinstance(detail.get('shell'), bool) else None,
                        'reference': 'https://gtfobins.org/gtfobins/%s/' % name})
    return {'schema': SCHEMA, 'source': SOURCE, 'source_sha256': raw_sha256,
            'retrieved_at': retrieved_at, 'upstream_license': 'GPL-3.0', 'entries': entries}


def _check(name, state, explanation):
    return {'name': name, 'state': state, 'explanation': explanation}


def _decision(name, decision):
    state = {'granted': 'met', 'denied': 'blocked'}.get(decision.state, 'unknown')
    if state == 'met' and decision.assumptions:
        state = 'unknown'
    return _check(name, state, decision.reason)


def match(report, catalog):
    if catalog.get('schema') != SCHEMA or catalog.get('source') != SOURCE:
        raise ValueError('unsupported technique catalog provenance or schema')
    entries = catalog.get('entries')
    if not isinstance(entries, list) or len(entries) > 20000:
        raise ValueError('invalid or oversized technique catalog')
    by_name = {}
    for e in entries:
        if e.get('context') not in CONTEXTS or e.get('function') not in FUNCTIONS or not isinstance(e.get('binary'), str):
            raise ValueError('unsupported technique entry')
        by_name.setdefault(e['binary'], []).append(e)
    nodes = {n['id']: n for n in report.get('nodes', [])}
    accounts = [n for n in nodes.values() if n['type'] == 'account' and n.get('properties', {}).get('uid') != 0]
    files = {f['path']: f for f in report.get('observations', {}).get('files', [])}
    mounts = report.get('observations', {}).get('mounts')
    resources = {n.get('properties', {}).get('path'): n for n in nodes.values() if n['type'] in ('binary', 'file')}
    matches = []
    def emit(actor, path, context, checks, edge_ids=(), resource=None):
        for entry in by_name.get(posixpath.basename(path), []):
            if entry['context'] != context:
                continue
            specific = list(checks)
            if context == 'capabilities':
                required = entry.get('required_capabilities', [])
                observed = files.get(path, {}).get('capabilities')
                state = 'unknown' if not required or not isinstance(observed, list) else ('met' if set(required) <= set(observed) else 'blocked')
                specific.append(_check('required_capabilities', state, 'Required effective capability semantics and namespace scope still need review.'))
                specific.append(_check('capability_effective_flags', 'unknown', 'Collector does not establish file capability effective/permitted flags.'))
            specific.extend([_check('binary_identity_and_version', 'unknown', 'Basename match only; executable identity and version have not been verified.'),
                             _check('technique_behavior', 'unknown', 'Recipe constraints, shell behavior, dependencies and confinement were not executed or proven.')])
            key = [actor['id'], path, entry['id'], list(edge_ids)]
            matches.append({'id': 'technique:' + hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24],
                'account_id': actor['id'], 'resource_id': resource['id'] if resource else None,
                'binary_path': path, 'technique_id': entry['id'], 'function': entry['function'], 'context': context,
                'reference': entry['reference'], 'edge_ids': list(edge_ids), 'prerequisites': specific,
                'status': 'blocked' if any(c['state'] == 'blocked' for c in specific) else 'conditional', 'verified': False})
            if len(matches) > 100000:
                raise ValueError('technique matching exceeds 100,000 candidates; nothing was truncated')
    for edge in report.get('edges', []):
        if edge['type'] != 'SudoAllows':
            continue
        actor, target = nodes[edge['source']], nodes[edge['target']]
        p = edge.get('properties', {})
        commands = p.get('commands', [])
        complex_policy = any(not isinstance(c, str) or c.lstrip().startswith('!') or c.strip() == 'ALL' for c in commands)
        for command in commands:
            if not isinstance(command, str) or command.lstrip().startswith('!'):
                continue
            try:
                tokens = shlex.split(command)
            except ValueError:
                continue
            if not tokens or not tokens[0].startswith('/') or any(x in tokens[0] for x in '*?[]'):
                continue
            path = tokens[0]; info = files.get(path)
            target_uid = target.get('properties', {}).get('uid')
            checks = [_check('root_run_as', 'unknown' if target_uid is None else 'met' if target_uid == 0 else 'blocked', 'Collected sudo run-as UID.'),
                _check('authentication_without_credentials', 'met' if p.get('nopasswd') is True else 'blocked' if p.get('nopasswd') is False else 'unknown', 'Threat model assumes account compromise without a sudo password or cached authentication.'),
                _check('sudo_invocation_arguments', 'unknown' if len(tokens) > 1 or complex_policy else 'met', 'Restricted arguments and policy ordering require exact technique review; unrestricted arguments do not prove technique behavior.'),
                _check('sudo_host_scope', 'unknown' if p.get('host_restricted') is not False else 'met', 'Host qualification must match the observed host.')]
            if info and target_uid is not None:
                checks.append(_decision('privileged_execution', can_execute(files, mounts, target_uid, target.get('properties', {}).get('gids', []), path)))
            else:
                checks.append(_check('privileged_execution', 'unknown', 'Executable or run-as identity was not collected.'))
            emit(actor, path, 'sudo', checks, [edge['id']], resources.get(path))
    for path, resource in resources.items():
        if not path or posixpath.basename(path) not in by_name or path not in files:
            continue
        info = files[path]; mode = info.get('mode'); caps = info.get('capabilities')
        contexts = (['suid'] if type(mode) is int and mode & 0o4000 else []) + (['capabilities'] if caps else [])
        for context in contexts:
            for actor in accounts:
                p = actor['properties']; uid = p.get('uid')
                if uid is None:
                    continue
                checks = [_decision('account_can_execute', can_execute(files, mounts, uid, p.get('gids', []), path))]
                if context == 'suid':
                    checks.extend([_decision('setuid_mount_policy', suid_honored(info, mounts)),
                        _check('setuid_root_owner', 'unknown' if info.get('uid') is None else 'met' if info['uid'] == 0 else 'blocked', 'Root escalation requires root ownership.')])
                    mount = mount_for(mounts, path)
                    if mount and 'flags' in mount and 'nosuid' not in mount['flags']:
                        checks[-2]['state'] = 'met'
                else:
                    mount = mount_for(mounts, path)
                    checks.append(_check('capability_mount_policy', 'unknown' if not mount or 'flags' not in mount else 'blocked' if 'nosuid' in mount['flags'] else 'met', 'nosuid disables file capabilities on the recorded mount.'))
                emit(actor, path, context, checks, resource=resource)
    result = copy.deepcopy(report)
    result['techniques'] = {'schema': SCHEMA, 'catalog_sha256': hashlib.sha256(json.dumps(catalog, sort_keys=True).encode()).hexdigest(),
        'source_sha256': catalog.get('source_sha256'), 'retrieved_at': catalog.get('retrieved_at'),
        'source': SOURCE, 'notice': 'Reference matches are conditional hypotheses, never verified findings. No recipes are stored or executed.', 'matches': matches}
    return result
