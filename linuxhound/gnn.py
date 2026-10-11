from __future__ import annotations

import copy
import hashlib
import json
import math
from linuxhound.gnn_context import NODE_CONTEXT, EDGE_CONTEXT, context

SCHEMA = 'linuxhound-gnn-v3'
NODE_TYPES = ('account', 'group', 'file', 'binary', 'directory', 'symlink', 'service', 'job', 'container', 'capability', 'host')
RELATIONS = ('MemberOf', 'CanRead', 'CanWrite', 'CanReplace', 'CanExecute', 'CanDelete', 'CanCreate', 'CanTraverse', 'CanList', 'OwnedBy', 'GroupOwnedBy', 'Contains', 'LinksTo', 'RunsAs', 'MayInfluence', 'SudoAllows', 'HasCapability', 'RunsOn', 'BindMounts', 'Configures', 'Invokes', 'other')
CAPABILITIES = ('cap_setuid','cap_setgid','cap_sys_admin','cap_dac_override','cap_dac_read_search','cap_sys_ptrace','cap_net_admin','cap_net_raw','cap_chown','cap_fowner')
COVERAGE = ('users','groups','filesystem','acls','mounts','sudo','systemd','cron','capabilities','docker')
BASE = ('other_type','root_identity','owner_root','group_root','designated_admin','implicit_dac_override','group_count','interactive_shell','disabled_shell','mode_owner_read','mode_owner_write','mode_owner_execute','mode_group_read','mode_group_write','mode_group_execute','mode_other_read','world_writable','mode_other_execute','setuid','setgid','sticky','capability_count','active_service','failed_service','enabled_service','masked_service','runtime_observed','main_pid_present','run_as_root','dynamic_user','no_new_privileges','protect_system','protect_home','private_tmp','privileged_container','container_running','readonly_rootfs','container_user_root','host_pid_namespace','host_user_namespace','private_user_namespace','cap_add_count','cap_drop_all','no_new_privileges_container','docker_socket_bind','host_root_bind','writable_bind_count','bind_count','acl_present','acl_entry_count','mount_readonly','mount_nosuid','mount_noexec','mount_nodev','incoming_degree','outgoing_degree','isolated','incoming_evidence_count','outgoing_evidence_count','coverage_fraction','running_as_root')
FEATURES = NODE_TYPES + BASE + tuple('file_'+c for c in CAPABILITIES) + tuple('coverage_'+c for c in COVERAGE) + tuple('incoming_'+r for r in RELATIONS) + tuple('outgoing_'+r for r in RELATIONS) + NODE_CONTEXT
EDGE_FEATURES = ('observed_permission','conditional','administrator_authority','possibly_unintended','sudo_nopasswd','bind_writable','prerequisite_count','assumption_count','evidence_count') + EDGE_CONTEXT


def fingerprint(report):
    evidence_report = {k:v for k,v in report.items() if k not in ('gnn','gnn_features','techniques')}
    return hashlib.sha256(json.dumps(evidence_report, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def features(report):
    nodes, edges = report.get('nodes', []), report.get('edges', [])
    if len(nodes) > 20000 or len(edges) > 200000:
        raise ValueError('GNN graph exceeds the supported 20,000-node / 200,000-edge limit; no graph was truncated')
    ids = [n['id'] for n in nodes]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate node ID')
    index = {name:i for i,name in enumerate(ids)}
    by_id = {n['id']:n for n in nodes}
    incoming, outgoing = {n:[] for n in ids}, {n:[] for n in ids}
    for edge in edges:
        if edge['source'] not in index or edge['target'] not in index:
            raise ValueError('edge endpoint is missing; GNN graph was not silently changed')
        incoming[edge['target']].append(edge);outgoing[edge['source']].append(edge)
    coverage = report.get('collection', {}).get('coverage', {})
    observations = report.get('observations', {})
    files = {f.get('path'):f for f in observations.get('files',[]) if isinstance(f,dict)}
    mounts = sorted(observations.get('mounts',[]), key=lambda m:len(m.get('path','')), reverse=True)
    node_context, edge_context = context(report,nodes,edges,files,mounts)
    rows, masks = [], []
    def count(value):
        return min(1.0, math.log1p(value)/math.log1p(1000))
    def known(value):
        return value is not None and value != 'unknown'
    for node in nodes:
        p, kind = node.get('properties',{}), node.get('type')
        values = {t:float(kind==t) for t in NODE_TYPES}
        values['other_type'] = float(kind not in NODE_TYPES)
        def put(name, value, observed=True):
            if observed:values[name]=float(value)
        def boolean(name, key):
            v=p.get(key);put(name,v is True, isinstance(v,bool))
        put('root_identity',kind=='account' and p.get('uid')==0,kind!='account' or 'uid' in p)
        put('owner_root',p.get('uid')==0,'uid' in p)
        put('group_root',p.get('gid')==0,'gid' in p)
        for name in ('designated_admin','implicit_dac_override','runtime_observed','dynamic_user'):
            boolean(name,name)
        put('group_count',count(len(p.get('gids',[]))),'gids' in p)
        shell=p.get('shell');put('interactive_shell',bool(shell) and not shell.endswith(('nologin','false')),bool(shell));put('disabled_shell',bool(shell) and shell.endswith(('nologin','false')),bool(shell))
        mode=p.get('mode')
        if type(mode) is int:
            for name,bit in zip(BASE[9:21],(0o400,0o200,0o100,0o040,0o020,0o010,0o004,0o002,0o001,0o4000,0o2000,0o1000)):
                put(name,bool(mode&bit))
        caps=p.get('capabilities')
        if isinstance(caps,list):
            put('capability_count',count(len(caps)))
            for cap in CAPABILITIES:put('file_'+cap,cap in caps)
        for name,key,positive in [('active_service','active_state',('active',)),('failed_service','active_state',('failed',)),('enabled_service','enabled_state',('enabled','enabled-runtime')),('masked_service','enabled_state',('masked','masked-runtime'))]:
            v=p.get(key);put(name,v in positive,known(v))
        pid=p.get('main_pid');put('main_pid_present',str(pid) not in ('0','None',''),known(pid))
        put('run_as_root',any(e['type']=='RunsAs' and by_id[e['target']].get('properties',{}).get('uid')==0 for e in outgoing[node['id']]),any(e['type']=='RunsAs' and 'uid' in by_id[e['target']].get('properties',{}) for e in outgoing[node['id']]))
        sandbox=p.get('sandbox',{})
        for name,key in [('no_new_privileges','NoNewPrivileges'),('private_tmp','PrivateTmp'),('protect_system','ProtectSystem'),('protect_home','ProtectHome')]:
            v=sandbox.get(key);put(name,str(v).lower() in ('true','yes','1','full','strict','read-only','tmpfs','disconnected'),known(v))
        for name,key in [('privileged_container','privileged'),('container_running','running'),('readonly_rootfs','readonly_rootfs')]:boolean(name,key)
        user=p.get('user');put('container_user_root',str(user).split(':')[0] in ('0','root',''),kind=='container' and user is not None)
        for name,key,positive in [('host_pid_namespace','pid_mode','host'),('host_user_namespace','userns_mode','host'),('private_user_namespace','userns_mode','private')]:
            v=p.get(key);put(name,v==positive,kind=='container' and v is not None and (key!='userns_mode' or v in ('host','private')))
        for name,key in [('cap_add_count','cap_add'),('bind_count','binds')]:put(name,count(len(p.get(key,[]))),key in p)
        dropped=p.get('cap_drop');put('cap_drop_all',any(str(v).upper()=='ALL' for v in dropped or []),isinstance(dropped,list))
        opts=p.get('security_opt');put('no_new_privileges_container',any(str(v).lower() in ('no-new-privileges','no-new-privileges:true','no-new-privileges=true') for v in opts or []),isinstance(opts,list))
        binds=p.get('binds');put('docker_socket_bind',any('/docker.sock' in str(v) for v in binds or []),isinstance(binds,list));put('host_root_bind',any(str(v).startswith('/:') for v in binds or []),isinstance(binds,list))
        container_mounts=p.get('mounts');put('writable_bind_count',count(sum(m.get('type')=='bind' and m.get('rw') is True for m in container_mounts or [])),isinstance(container_mounts,list))
        info=files.get(p.get('path'),{});acl=info.get('acl');put('acl_present',bool(acl),coverage.get('acls')=='complete' and bool(info));put('acl_entry_count',count(len(acl)) if isinstance(acl,(dict,list)) else 0,isinstance(acl,(dict,list)))
        path=p.get('path')
        mount=next((m for m in mounts if path and (m.get('path')=='/' or path==m.get('path') or path.startswith(m.get('path','')+'/'))),None)
        for name,flag in [('mount_readonly','ro'),('mount_nosuid','nosuid'),('mount_noexec','noexec'),('mount_nodev','nodev')]:put(name,flag in (mount or {}).get('flags',[]),mount is not None and 'flags' in mount)
        ins,outs=incoming[node['id']],outgoing[node['id']]
        put('incoming_degree',count(len(ins)));put('outgoing_degree',count(len(outs)));put('isolated',not ins and not outs)
        put('incoming_evidence_count',count(sum(len(e.get('evidence_ids',[])) for e in ins)));put('outgoing_evidence_count',count(sum(len(e.get('evidence_ids',[])) for e in outs)))
        for direction,links in [('incoming',ins),('outgoing',outs)]:
            for relation in RELATIONS:put(direction+'_'+relation,count(sum((e.get('type') if e.get('type') in RELATIONS else 'other')==relation for e in links)))
        put('coverage_fraction',sum(v=='complete' for v in coverage.values())/max(1,len(coverage)),bool(coverage))
        for domain in COVERAGE:put('coverage_'+domain,coverage.get(domain)=='complete',domain in coverage)
        v=report.get('collection',{}).get('running_as_root');put('running_as_root',v is True,isinstance(v,bool))
        values.update(node_context[node['id']])
        rows.append([values.get(f,0.0) for f in FEATURES]);masks.append([float(f in values) for f in FEATURES])
    links, edge_rows, edge_masks = [], [], []
    for e in edges:
        relation=e.get('type','other');links.append([index[e['source']],index[e['target']],RELATIONS.index(relation if relation in RELATIONS else 'other')])
        vals={}
        if 'classification' in e:vals.update(observed_permission=float(e['classification']=='observed_permission'),conditional=float(e['classification']=='conditional'))
        if e.get('authority') not in (None,'unknown'):vals.update(administrator_authority=float(e['authority']=='legitimate_administrator'),possibly_unintended=float(e['authority']=='possible_unintended'))
        ep=e.get('properties',{})
        for f,k in [('sudo_nopasswd','nopasswd'),('bind_writable','rw')]:
            if isinstance(ep.get(k),bool):vals[f]=float(ep[k])
        for f,k in [('prerequisite_count','prerequisites'),('assumption_count','assumptions'),('evidence_count','evidence_ids')]:
            if isinstance(e.get(k),list):vals[f]=count(len(e[k]))
        vals.update(edge_context[e['id']])
        edge_rows.append([vals.get(f,0.0) for f in EDGE_FEATURES]);edge_masks.append([float(f in vals) for f in EDGE_FEATURES])
    return {'schema':SCHEMA,'snapshot_sha256':fingerprint(report),'node_ids':ids,'edge_ids':[e['id'] for e in edges],
            'feature_names':list(FEATURES),'edge_feature_names':list(EDGE_FEATURES),'relation_names':list(RELATIONS),
            'x':rows,'x_known':masks,'edges':links,'edge_x':edge_rows,'edge_x_known':edge_masks}


def _torch():
    try:
        import torch
    except ImportError as exc:
        raise ValueError('GNN commands require the optional dependency: pip install "linuxhound[gnn]"') from exc
    return torch


def _network(hidden=24):
    torch = _torch()
    class RelationalGNN(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.input = torch.nn.Linear(len(FEATURES)*2, hidden)
            self.messages = torch.nn.ModuleList([torch.nn.Linear(hidden, hidden, bias=False) for _ in range(len(RELATIONS) * 2)])
            self.edge_input = torch.nn.Linear(len(EDGE_FEATURES)*2, hidden, bias=False)
            self.self_update = torch.nn.Linear(hidden, hidden)
            self.output = torch.nn.Linear(hidden, 1)

        def forward(self, data):
            x = torch.tensor([a+b for a,b in zip(data['x'],data['x_known'])], dtype=torch.float32).reshape(-1, len(FEATURES)*2)
            h = torch.relu(self.input(x))
            links = torch.tensor(data['edges'], dtype=torch.long).reshape(-1, 3)
            edge_x = torch.tensor([a+b for a,b in zip(data['edge_x'],data['edge_x_known'])],dtype=torch.float32).reshape(-1,len(EDGE_FEATURES)*2)
            for _ in range(2):
                aggregate = torch.zeros_like(h)
                for relation in range(len(RELATIONS)):
                    subset = links[links[:, 2] == relation]
                    for reverse in (0, 1):
                        source, target = subset[:, reverse], subset[:, 1 - reverse]
                        if not len(source):
                            continue
                        count = torch.zeros(len(h), dtype=h.dtype)
                        count.index_add_(0, target, torch.ones(len(target)))
                        messages = torch.zeros_like(h)
                        messages.index_add_(0, target, self.messages[relation * 2 + reverse](h[source]) + self.edge_input(edge_x[links[:,2]==relation]))
                        aggregate = aggregate + messages / count.clamp(min=1).unsqueeze(1)
                h = torch.relu(self.self_update(h) + aggregate)
            return self.output(h).squeeze(-1)
    return RelationalGNN()


def _samples(manifest, load_report, feature_fn=features, label_ids="node_ids", label_values=(0, 1)):
    samples = {'train': [], 'validation': []}
    hosts, hashes = {'train': set(), 'validation': set()}, {'train': set(), 'validation': set()}
    identities = {'train': set(), 'validation': set()}
    source_hosts = {'train': set(), 'validation': set()}
    hostnames = {'train': set(), 'validation': set()}
    environments = {'train': set(), 'validation': set()}
    protocol = manifest.get('evaluation_protocol', 'source_host_holdout')
    if protocol not in ('source_host_holdout', 'isolated_environment_holdout'):
        raise ValueError('unsupported evaluation protocol')
    for item in manifest.get('graphs', []):
        split = item.get('split')
        if split not in samples:
            raise ValueError('each labeled graph needs train or validation split')
        report = load_report(item['report'])
        data = feature_fn(report)
        if item.get('snapshot_sha256') != data['snapshot_sha256']:
            raise ValueError('labels do not match the exact snapshot SHA256')
        labels = item.get('labels', {})
        if not isinstance(labels, dict) or not labels or any(type(v) not in (int, float) or v not in label_values for v in labels.values()):
            raise ValueError('review labels must be explicit supported class values, not inferred from rule findings')
        if not set(labels).issubset(data[label_ids]):
            raise ValueError('label refers to an unknown node or path')
        host = report.get('host', {}).get('id')
        if not host:
            raise ValueError('host identity is required for leakage checks')
        source_host = item.get('source_host_id')
        if not isinstance(source_host, str) or not source_host.strip():
            raise ValueError('source_host_id provenance is required; a report host ID is not a physical-host split')
        source_hosts[split].add(source_host.strip())
        if protocol == 'isolated_environment_holdout':
            environment = item.get('source_environment_id')
            if not isinstance(environment,str) or not environment.strip() or item.get('environment_kind') != 'container':
                raise ValueError('isolated lab protocol requires container identity provenance')
            environments[split].add(environment.strip())
        hostname = report.get('host', {}).get('hostname')
        if hostname:
            hostnames[split].add(str(hostname).strip().casefold())
        hosts[split].add(host); hashes[split].add(data['snapshot_sha256']); identities[split].update(data['node_ids'])
        samples[split].append((data, labels))
    if not all(samples.values()):
        raise ValueError('training requires separate train and validation graphs')
    if hosts['train'] & hosts['validation'] or hashes['train'] & hashes['validation'] or identities['train'] & identities['validation']:
        raise ValueError('train and validation must have disjoint host identities and snapshots')
    if (protocol == 'source_host_holdout' and source_hosts['train'] & source_hosts['validation']) or hostnames['train'] & hostnames['validation'] or environments['train'] & environments['validation']:
        raise ValueError('train and validation share a source host; renaming report IDs does not create independent hosts')
    for split in samples:
        if len({v for _, labels in samples[split] for v in labels.values()}) < 2:
            raise ValueError('each split needs both reviewed label classes')
    return samples


def train(manifest, load_report, epochs=100, seed=7):
    if not 1 <= epochs <= 2000:
        raise ValueError('epochs must be between 1 and 2000')
    if any(not isinstance(manifest.get(k), str) or not manifest[k].strip() for k in ('reviewer', 'label_policy')):
        raise ValueError('reviewer and label_policy provenance are required')
    samples = _samples(manifest, load_report)
    torch = _torch(); torch.manual_seed(seed)
    model = _network(); optimizer = torch.optim.Adam(model.parameters(), lr=0.005)
    loss_fn = torch.nn.BCEWithLogitsLoss()
    def loss(split):
        values = []
        for data, labels in samples[split]:
            logits = model(data)
            indices = [i for i, name in enumerate(data['node_ids']) if name in labels]
            targets = torch.tensor([float(labels[data['node_ids'][i]]) for i in indices])
            values.append(loss_fn(logits[indices], targets))
        return torch.stack(values).mean()
    best, weights = float('inf'), None
    for _ in range(epochs):
        model.train(); optimizer.zero_grad(); objective = loss('train'); objective.backward(); optimizer.step()
        model.eval()
        with torch.no_grad():
            validation = float(loss('validation'))
        if not math.isfinite(validation):
            raise ValueError('training produced a non-finite validation loss')
        if validation < best:
            best = validation; weights = copy.deepcopy(model.state_dict())
    return {'schema': SCHEMA, 'architecture': 'directed-relational-message-passing-2-layer',
            'feature_names': list(FEATURES), 'edge_feature_names':list(EDGE_FEATURES), 'relation_names': list(RELATIONS),
            'weights': {k: v.tolist() for k, v in weights.items()},
            'metadata': {'seed': seed, 'epochs': epochs, 'reviewer': manifest['reviewer'],
                         'label_policy': manifest['label_policy'], 'validation_loss': best, 'evaluation_protocol': manifest.get('evaluation_protocol','source_host_holdout'),
                         'evaluation_scope': 'controlled isolated environments; shared kernel; not cross-host accuracy' if manifest.get('evaluation_protocol') == 'isolated_environment_holdout' else 'source-host-disjoint validation; not an untouched test set',
                         'source_hosts': {split: sorted({item['source_host_id'] for item in manifest['graphs'] if item['split'] == split}) for split in ('train', 'validation')},
                         'source_environments': {split: sorted({item['source_environment_id'] for item in manifest['graphs'] if item['split'] == split and item.get('source_environment_id')}) for split in ('train','validation')},
                         'training_snapshots': [d['snapshot_sha256'] for d, _ in samples['train']],
                         'validation_snapshots': [d['snapshot_sha256'] for d, _ in samples['validation']],
                         'status': 'experimental_unvalidated', 'calibrated': False}}


def rank(report, checkpoint):
    if checkpoint.get('metadata', {}).get('evaluation_status') == 'invalid_same_source_host':
        raise ValueError('model quarantined: validation reused the training source host; retrain on independent hosts')
    if checkpoint.get('architecture') != 'directed-relational-message-passing-2-layer' or checkpoint.get('schema') != SCHEMA or checkpoint.get('feature_names') != list(FEATURES) or checkpoint.get('relation_names') != list(RELATIONS) or checkpoint.get('edge_feature_names') != list(EDGE_FEATURES):
        raise ValueError('model schema or feature vocabulary mismatch')
    torch = _torch(); model = _network(); expected = model.state_dict()
    weights = checkpoint.get('weights', {})
    if set(weights) != set(expected):
        raise ValueError('model weights do not match the supported architecture')
    def validate(value, shape):
        if shape:
            if not isinstance(value, list) or len(value) != shape[0]:
                raise ValueError('model has invalid weight dimensions or values')
            for item in value:
                validate(item, shape[1:])
        elif type(value) not in (float, int) or not math.isfinite(value):
            raise ValueError('model has invalid weight dimensions or values')
    tensors = {}
    for k, v in weights.items():
        validate(v, list(expected[k].shape))
        tensor = torch.tensor(v, dtype=torch.float32)
        if tensor.shape != expected[k].shape or not torch.isfinite(tensor).all():
            raise ValueError('model has invalid weight dimensions or values')
        tensors[k] = tensor
    model.load_state_dict(tensors); model.eval(); data = features(report)
    if not data['node_ids']:
        raise ValueError('cannot rank an empty graph')
    with torch.no_grad():
        values = model(data).tolist()
    scores = dict(zip(data['node_ids'], values))
    if any(not math.isfinite(v) for v in values):
        raise ValueError('model produced non-finite scores')
    analysis = report.get('analysis', {})
    paths = analysis.get('paths', []) + analysis.get('service_paths', [])
    ranked = {}
    for path in paths:
        ids = [n for n in path.get('node_ids', []) if n in scores]
        if ids:
            ranked[path['id']] = {'path_id': path['id'], 'review_score': sum(scores[n] for n in ids) / len(ids)}
    result = copy.deepcopy(report)
    result['gnn'] = {'schema': SCHEMA, 'snapshot_sha256': data['snapshot_sha256'],
        'model_sha256': hashlib.sha256(json.dumps(checkpoint, sort_keys=True, allow_nan=False).encode()).hexdigest(),
        'status': 'experimental_unvalidated', 'calibrated': False,
        'evaluation_scope': checkpoint.get('metadata', {}).get('evaluation_scope', 'Unknown evaluation scope'),
        'label_policy': str(checkpoint.get('metadata', {}).get('label_policy', 'Unknown reviewer label provenance')),
        'notice': 'Experimental review ordering only. Scores are not exploit probabilities or safety verdicts.',
        'paths': sorted(ranked.values(), key=lambda p: (-p['review_score'], p['path_id']))}
    return result
