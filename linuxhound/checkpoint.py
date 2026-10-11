from __future__ import annotations
import copy, hashlib, json, os, tempfile
from pathlib import Path

FORMAT='linuxhound-safetensors-v1'
MAX_BYTES=64*1024*1024


def _hash(checkpoint):
    return hashlib.sha256(json.dumps(checkpoint,sort_keys=True,allow_nan=False).encode()).hexdigest()


def _expected(checkpoint):
    from linuxhound.gnn import SCHEMA,FEATURES,EDGE_FEATURES,RELATIONS,_network
    if checkpoint.get('schema')==SCHEMA:
        if checkpoint.get('architecture')!='directed-relational-message-passing-2-layer' or checkpoint.get('feature_names')!=list(FEATURES) or checkpoint.get('edge_feature_names')!=list(EDGE_FEATURES) or checkpoint.get('relation_names')!=list(RELATIONS):
            raise ValueError('model schema or vocabulary mismatch')
        return _network().state_dict()
    from linuxhound.path_gnn import SCHEMA as PATH_SCHEMA,NODE_FEATURES,EDGE_FEATURES as PATH_EDGES,CHECKS,OUTCOMES,_network as path_network
    if checkpoint.get('schema')!=PATH_SCHEMA or checkpoint.get('architecture')!='path-local-directed-message-passing-and-ordered-edges' or any(checkpoint.get(k)!=list(v) for k,v in [('node_features',NODE_FEATURES),('edge_features',PATH_EDGES),('relations',RELATIONS),('checks',CHECKS),('outcomes',OUTCOMES)]):
        raise ValueError('model schema or vocabulary mismatch')
    return path_network().state_dict()


def _dependencies():
    try:
        from safetensors.torch import save_file,load
    except ImportError as exc:
        raise ValueError('SafeTensors requires the optional dependency: pip install "linuxhound[gnn]"') from exc
    from linuxhound.gnn import _torch
    return _torch(),save_file,load


def save_checkpoint(path,checkpoint):
    path=Path(path)
    if path.suffix=='.json':
        from linuxhound.cli import _write
        _write(str(path),checkpoint)
        return
    if path.suffix!='.safetensors':raise ValueError('model output must end in .safetensors or .json')
    manifest_path=path.with_suffix('.json')
    if path.exists() or path.is_symlink() or manifest_path.exists() or manifest_path.is_symlink():
        raise ValueError('refusing to overwrite an existing SafeTensors model pair; use a new output name')
    torch,save_file,_=_dependencies();expected=_expected(checkpoint)
    weights=checkpoint.get('weights',{})
    if set(weights)!=set(expected):raise ValueError('model weights do not match architecture')
    tensors={}
    for name,value in weights.items():
        tensor=torch.tensor(value,dtype=torch.float32)
        if tensor.shape!=expected[name].shape or not torch.isfinite(tensor).all():raise ValueError('invalid model weight shape or value')
        tensors[name]=tensor.contiguous()
    canonical=copy.deepcopy(checkpoint);canonical['weights']={k:v.tolist() for k,v in tensors.items()}
    logical_hash=_hash(canonical)
    descriptor,temporary=tempfile.mkstemp(prefix='.linuxhound-model-',dir=path.parent);os.close(descriptor)
    try:
        save_file(tensors,temporary,metadata={'format':FORMAT,'checkpoint_sha256':logical_hash})
        os.chmod(temporary,0o600)
        if Path(temporary).stat().st_size>MAX_BYTES:raise ValueError('checkpoint exceeds 64 MiB')
        digest=hashlib.sha256(Path(temporary).read_bytes()).hexdigest()
        manifest={k:v for k,v in canonical.items() if k!='weights'}
        manifest['storage']={'format':FORMAT,'weights_file':path.name,'weights_sha256':digest,'checkpoint_sha256':logical_hash,'dtype':'float32'}
        os.replace(temporary,path)
        from linuxhound.cli import _write
        _write(str(manifest_path),manifest)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def load_checkpoint(path):
    path=Path(path)
    manifest_path=path.with_suffix('.json') if path.suffix=='.safetensors' else path
    raw=manifest_path.read_bytes()
    if len(raw)>MAX_BYTES:raise ValueError('checkpoint manifest exceeds 64 MiB')
    manifest=json.loads(raw)
    storage=manifest.get('storage')
    if storage is None:
        if path.suffix=='.safetensors':raise ValueError('SafeTensors companion manifest is missing storage metadata')
        return manifest
    if storage.get('format')!=FORMAT or storage.get('dtype')!='float32' or 'weights' in manifest:
        raise ValueError('unsupported model storage format')
    filename=storage.get('weights_file')
    if not isinstance(filename,str) or Path(filename).name!=filename or '/' in filename or '\\' in filename or not filename.endswith('.safetensors'):
        raise ValueError('weights filename must be a local SafeTensors basename')
    weights_path=manifest_path.parent/filename
    if path.suffix=='.safetensors' and weights_path!=path:raise ValueError('manifest references a different weights file')
    if weights_path.is_symlink():raise ValueError('refusing a symlink weights file')
    if weights_path.stat().st_size>MAX_BYTES:raise ValueError('checkpoint exceeds 64 MiB')
    weights_raw=weights_path.read_bytes()
    if hashlib.sha256(weights_raw).hexdigest()!=storage.get('weights_sha256'):raise ValueError('SafeTensors weights checksum mismatch')
    torch,_,load=_dependencies()
    tensors=load(weights_raw);expected=_expected(manifest)
    if set(tensors)!=set(expected):raise ValueError('model weights do not match architecture')
    for name,tensor in tensors.items():
        if tensor.dtype!=torch.float32 or tensor.shape!=expected[name].shape or not torch.isfinite(tensor).all():raise ValueError('invalid model weight dtype, shape or value')
    checkpoint={k:v for k,v in manifest.items() if k!='storage'};checkpoint['weights']={k:v.tolist() for k,v in tensors.items()}
    if _hash(checkpoint)!=storage.get('checkpoint_sha256'):raise ValueError('checkpoint metadata or weights binding mismatch')
    return checkpoint
