import math
from linuxhound.access import ancestor_paths, parent_path, effective_bits, ancestors_allow

NODE_CONTEXT = ('acl_mask_read','acl_mask_write','acl_mask_execute','acl_named_user_count','acl_named_group_count','acl_mask_restricts_named_write','parent_sticky','parent_world_writable','ancestor_restricted_mode','observed_root_consumer_count','observed_write_root_consumer_count','observed_replace_root_consumer_count','observed_sudo_root_nopasswd_count','observed_sudo_root_password_count','observed_sudo_root_unknown_auth_count','observed_privileged_write_fraction','observed_file_write_fraction','observed_file_read_fraction','observed_file_execute_fraction','observed_directory_traverse_fraction')
EDGE_CONTEXT = ('sudo_password_required','sudo_auth_unknown','target_root_identity','source_owns_target','source_in_target_group','target_root_consumer','target_acl_mask_write','target_parent_sticky','effective_peer_read','effective_peer_write','effective_peer_execute','ancestor_traversal_granted','ancestor_traversal_denied','permission_context_conditional')

def scaled_count(n):return min(1.0,math.log1p(n)/math.log1p(1000))

def context(report, nodes, edges, files, mounts):
    by_id={n['id']:n for n in nodes};out={n['id']:[] for n in nodes}
    root_jobs={e['source'] for e in edges if e['type']=='RunsAs' and by_id[e['target']].get('properties',{}).get('uid')==0}
    consumers={n['id']:set() for n in nodes}
    for edge in edges:
        out[edge['source']].append(edge)
        if edge['type'] in ('MayInfluence','Configures') and edge['target'] in root_jobs:consumers[edge['source']].add(edge['target'])
    privileged_resources={n for n,c in consumers.items() if c}
    file_count=sum(n.get('type') in ('file','binary','symlink') for n in nodes)
    dir_count=sum(n.get('type')=='directory' for n in nodes)
    nr={};er={};ancestor_cache={}
    for node in nodes:
        p=node.get('properties',{});kind=node.get('type');path=p.get('path');info=files.get(path,{});acl=info.get('acl');values={}
        if isinstance(acl,dict):
            values['acl_named_user_count']=scaled_count(len(acl.get('users') or {}));values['acl_named_group_count']=scaled_count(len(acl.get('groups') or {}))
            mask=acl.get('mask')
            if type(mask) is int:
                for name,bit in [('read',4),('write',2),('execute',1)]:values['acl_mask_'+name]=float(bool(mask&bit))
                entries=list((acl.get('users') or {}).values())+list((acl.get('groups') or {}).values())
                values['acl_mask_restricts_named_write']=float(any(int(v)&2 for v in entries) and not mask&2)
        if path:
            parent=files.get(parent_path(path),{});mode=parent.get('mode')
            if type(mode) is int:
                values['parent_sticky']=float(bool(mode&0o1000));values['parent_world_writable']=float(bool(mode&0o002))
            ancestors=[files.get(a,{}) for a in ancestor_paths(path)]
            if ancestors and all(type(a.get('mode')) is int for a in ancestors):
                values['ancestor_restricted_mode']=float(any(not a['mode']&0o011 for a in ancestors))
        values['observed_root_consumer_count']=scaled_count(len(consumers[node['id']]))
        if kind=='account':
            links=out[node['id']]
            for relation,name in [('CanWrite','observed_write_root_consumer_count'),('CanReplace','observed_replace_root_consumer_count')]:
                values[name]=scaled_count(len({e['target'] for e in links if e['type']==relation and e['target'] in privileged_resources}))
            sudo=[e for e in links if e['type']=='SudoAllows' and by_id[e['target']].get('properties',{}).get('uid')==0]
            for flag,name in [(True,'nopasswd'),(False,'password'),(None,'unknown_auth')]:
                values['observed_sudo_root_'+name+'_count']=scaled_count(sum((not isinstance(e.get('properties',{}).get('nopasswd'),bool)) if flag is None else e.get('properties',{}).get('nopasswd') is flag for e in sudo))
            if privileged_resources:values['observed_privileged_write_fraction']=len({e['target'] for e in links if e['type'] in ('CanWrite','CanReplace') and e['target'] in privileged_resources})/len(privileged_resources)
            for relation,name,denom in [('CanWrite','write',file_count),('CanRead','read',file_count),('CanExecute','execute',file_count),('CanTraverse','traverse',dir_count)]:
                types=('directory',) if relation=='CanTraverse' else ('file','binary','symlink')
                if denom:values['observed_'+('directory' if relation=='CanTraverse' else 'file')+'_'+name+'_fraction']=len({e['target'] for e in links if e['type']==relation and by_id[e['target']].get('type') in types})/denom
        nr[node['id']]=values
    for edge in edges:
        source=by_id[edge['source']];target=by_id[edge['target']];sp=source.get('properties',{});tp=target.get('properties',{});values={}
        if edge['type']=='SudoAllows':
            flag=edge.get('properties',{}).get('nopasswd')
            values['sudo_auth_unknown']=float(not isinstance(flag,bool))
            if isinstance(flag,bool):values['sudo_password_required']=float(not flag)
        if target.get('type')=='account' and type(tp.get('uid')) is int:values['target_root_identity']=float(tp['uid']==0)
        values['target_root_consumer']=float(edge['target'] in privileged_resources)
        path=tp.get('path');info=files.get(path);acl=(info or {}).get('acl');mask=acl.get('mask') if isinstance(acl,dict) else None
        if type(mask) is int:values['target_acl_mask_write']=float(bool(mask&2))
        if path:
            parent=files.get(parent_path(path),{});mode=parent.get('mode')
            if type(mode) is int:values['target_parent_sticky']=float(bool(mode&0o1000))
        if source.get('type')=='account' and info and all(type(info.get(k)) is int for k in ('uid','gid','mode')) and type(sp.get('uid')) is int and isinstance(sp.get('gids'),list):
            uid=sp['uid'];gids=set(sp['gids']);values['source_owns_target']=float(uid==info['uid']);values['source_in_target_group']=float(info['gid'] in gids)
            bits=effective_bits(info,uid,gids) if info.get('type') != 'symlink' else None
            if bits is not None:
                for name,bit in [('read',4),('write',2),('execute',1)]:values['effective_peer_'+name]=float(bool(bits&bit))
            key=(edge['source'],parent_path(path))
            if key not in ancestor_cache:ancestor_cache[key]=ancestors_allow(files,mounts,uid,gids,path)
            decision=ancestor_cache[key]
            if decision.state in ('granted','denied'):
                values['ancestor_traversal_granted']=float(decision.state=='granted');values['ancestor_traversal_denied']=float(decision.state=='denied')
            values['permission_context_conditional']=float(bool(decision.assumptions) or decision.state=='unresolved')
        er[edge['id']]=values
    return nr,er
