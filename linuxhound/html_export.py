from __future__ import annotations
import json
from pathlib import Path
from linuxhound.version import TOOL_NAME, VERSION


def export_html(report: dict, comparison: dict | None = None) -> str:
    document=dict(report)
    if "findings" not in (document.get("analysis") or {}):
        from linuxhound.findings import findings
        document["analysis"] = dict(document.get("analysis") or {})
        document["analysis"]["findings"] = findings(document)
    from linuxhound.gnn import features
    try:
        document['gnn_features'] = features(report)
    except ValueError as exc:
        document['gnn_features'] = {'status': 'unavailable', 'reason': str(exc)}
    if comparison is not None:
        document['comparison']=comparison
    payload=json.dumps(document,sort_keys=True).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026').replace('\u2028','\\u2028').replace('\u2029','\\u2029')
    page=Path(__file__).with_name('viewer.html').read_text(encoding='utf-8')
    page = page.replace('@@VIEWER_CSS@@', Path(__file__).with_name('viewer.css').read_text(encoding='utf-8'))
    page = page.replace('@@GRAPH_JS@@', Path(__file__).with_name('graph.js').read_text(encoding='utf-8'))
    page = page.replace('@@VIEWER_JS@@', Path(__file__).with_name('viewer.js').read_text(encoding='utf-8'))
    return page.replace('@@TOOL@@',TOOL_NAME).replace('@@VERSION@@',VERSION).replace('@@REPORT@@',payload)
