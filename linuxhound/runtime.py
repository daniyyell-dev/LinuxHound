from __future__ import annotations

import json
import re
import shutil
import subprocess
from linuxhound.parsers import parse_systemctl_exec
from linuxhound.sanitize import safe_argv

SERVICE_PROPERTIES = ('Id','LoadState','ActiveState','SubState','UnitFileState','User','Group',
    'DynamicUser','MainPID','FragmentPath','DropInPaths','ExecStart','ExecStartPre','ExecStartPost',
    'NoNewPrivileges','ProtectSystem','ProtectHome','PrivateTmp','CapabilityBoundingSet','AmbientCapabilities')
DOCKER_FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},"user":{{json .Config.User}},'
    '"running":{{json .State.Running}},"status":{{json .State.Status}},'
    '"privileged":{{json .HostConfig.Privileged}},"pid_mode":{{json .HostConfig.PidMode}},'
    '"userns_mode":{{json .HostConfig.UsernsMode}},"readonly_rootfs":{{json .HostConfig.ReadonlyRootfs}},'
    '"cap_add":{{json .HostConfig.CapAdd}},"cap_drop":{{json .HostConfig.CapDrop}},'
    '"security_opt":{{json .HostConfig.SecurityOpt}},"mounts":{{json .Mounts}}}')


def _run(args, remaining):
    if remaining() <= 0:
        raise TimeoutError('collection deadline reached')
    result = subprocess.run(args, capture_output=True, text=True,
                            timeout=min(8, remaining()), check=False)
    if result.returncode or len(result.stdout)>2_000_000:
        raise RuntimeError('metadata command unavailable or exceeds bound')
    return result.stdout


def services(remaining, record_error, limit=200):
    binary=shutil.which('systemctl')
    if not binary:
        record_error('systemd','systemctl unavailable','running service inventory is unknown')
        return [], 'unavailable'
    try:
        text=_run([binary,'list-units','--all','--type=service','--no-legend','--plain','--no-pager'],remaining)
        names=[line.split()[0] for line in text.splitlines() if line.split() and line.split()[0].endswith('.service')]
    except (OSError,RuntimeError,TimeoutError,subprocess.TimeoutExpired):
        record_error('systemd','service discovery unavailable','running service inventory is unknown')
        return [],'unavailable'
    coverage='complete'
    if len(names)>limit:
        coverage='partial'
        record_error('systemd','service limit reached','unvisited service state and invocations are unknown')
    records=[]
    for name in names[:limit]:
        try:
            show=_run([binary,'show',name,'--no-pager','--property='+','.join(SERVICE_PROPERTIES)],remaining)
            values=dict(line.split('=',1) for line in show.splitlines() if '=' in line)
            if not values.get('Id') or not values.get('LoadState') or values.get('LoadState') in ('not-found','error'):
                raise RuntimeError('unit unavailable')
        except (OSError,RuntimeError,TimeoutError,subprocess.TimeoutExpired):
            coverage='partial'
            record_error('systemd','could not inspect '+name,'this unit is unresolved, not absent')
            continue
        commands=[]
        for phase in ('ExecStart','ExecStartPre','ExecStartPost'):
            for chunk in re.findall(r'\{[^{}]*\}',values.get(phase,'')):
                argv=safe_argv(parse_systemctl_exec(chunk))
                if not argv:continue
                absolute=[token for token in argv if token.startswith('/')]
                commands.append({'phase':phase,'argv':argv,'absolute_paths':absolute,
                                 'resolution':'absolute' if argv[0].startswith('/') else 'unresolved'})
        absolute=list(dict.fromkeys(path for cmd in commands for path in cmd['absolute_paths']))
        records.append({'name':values.get('Id') or name,'unit_kind':'service',
            'user':values.get('User') or 'root','user_defaulted':False,'runtime_observed':True,
            'dynamic_user':values.get('DynamicUser')=='yes','group':values.get('Group') or None,
            'active_state':values.get('ActiveState','unknown'),'sub_state':values.get('SubState','unknown'),
            'enabled_state':values.get('UnitFileState','unknown'),'main_pid':values.get('MainPID','0'),
            'fragment_path':values.get('FragmentPath',''),
            'drop_in_paths':values.get('DropInPaths','').split(),
            'argv':[token for cmd in commands for token in cmd['argv']],
            'commands':commands,'absolute_paths':absolute,
            'resolution':'absolute' if commands and all(c['resolution']=='absolute' for c in commands) else 'unresolved',
            'sanitized_exec':' | '.join(' '.join(cmd['argv']) for cmd in commands),
            'sandbox':{key:values.get(key,'unknown') for key in ('NoNewPrivileges','ProtectSystem','ProtectHome','PrivateTmp','CapabilityBoundingSet','AmbientCapabilities')}})
    return records,coverage


def containers(remaining, record_error, limit=100):
    binary=shutil.which('docker')
    if not binary:
        record_error('docker','docker CLI unavailable','container relationships are unknown')
        return [],'unavailable'
    try:
        ids=_run([binary,'--host','unix:///var/run/docker.sock','ps','--all','--quiet','--no-trunc'],remaining).split()
    except (OSError,RuntimeError,TimeoutError,subprocess.TimeoutExpired):
        record_error('docker','Docker metadata access unavailable','no container discovery; not a clean Docker result')
        return [],'unavailable'
    records=[];coverage='complete'
    if len(ids)>limit:
        coverage='partial';record_error('docker','container limit reached','unvisited containers remain unknown')
    for identifier in ids[:limit]:
        if not re.fullmatch(r'[a-f0-9]{12,64}',identifier):
            coverage='partial';continue
        try:
            data=json.loads(_run([binary,'--host','unix:///var/run/docker.sock','inspect','--type=container','--format',DOCKER_FORMAT,identifier],remaining))
        except (OSError,ValueError,RuntimeError,TimeoutError,subprocess.TimeoutExpired):
            coverage='partial';record_error('docker','container metadata inspection failed','this container is unresolved');continue
        mounts=[{'source':m.get('Source',''),'destination':m.get('Destination',''),
                 'type':m.get('Type',''),'rw':bool(m.get('RW'))} for m in data.get('mounts') or []]
        records.append({key:data.get(key) for key in ('id','name','user','running','status','privileged','pid_mode','userns_mode','readonly_rootfs','cap_add','cap_drop','security_opt')} |
                       {'mounts':mounts,'binds':[m['source']+':'+m['destination'] for m in mounts if m['type']=='bind'],
                        'identity_boundary':'host_user_namespace' if data.get('userns_mode')=='host' else 'unknown'})
    return records,coverage
