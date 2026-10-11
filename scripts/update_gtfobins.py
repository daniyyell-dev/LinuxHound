import argparse, datetime, hashlib, json, sys, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from linuxhound.techniques import SOURCE, normalize_catalog
from linuxhound.cli import _write

def main():
    p=argparse.ArgumentParser();p.add_argument('--output', required=True);a=p.parse_args()
    request=urllib.request.Request(SOURCE,headers={'User-Agent':'LinuxHound reference metadata importer'})
    with urllib.request.urlopen(request,timeout=30) as response:
        raw=response.read(8*1024*1024+1)
    if len(raw)>8*1024*1024:raise ValueError('catalog exceeds 8 MiB')
    catalog=normalize_catalog(json.loads(raw),hashlib.sha256(raw).hexdigest(),datetime.datetime.now(datetime.timezone.utc).isoformat())
    _write(a.output,catalog)
    print('Imported %d metadata entries; recipes excluded. Upstream data: GPL-3.0; keep cache separate from source distribution.'%len(catalog['entries']))
if __name__=='__main__':main()
