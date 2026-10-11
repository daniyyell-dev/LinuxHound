from __future__ import annotations

import hashlib
import re

_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def require_host_id(host_id: str) -> str:
    if not isinstance(host_id, str) or not _HOST_RE.match(host_id):
        raise ValueError("host id must be 1-128 characters from [A-Za-z0-9._-]")
    return host_id


def node_id(kind: str, host_id: str, key: str) -> str:
    return f"{kind}/{require_host_id(host_id)}/{key}"


def edge_id(edge_type: str, source: str, target: str, qualifier: str = "") -> str:
    raw = f"{edge_type}|{source}|{target}|{qualifier}"
    return "edge/" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def evidence_id(method: str, source: str, statement: str) -> str:
    raw = f"{method}|{source}|{statement}"
    return "evidence/" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def opengraph_id(internal_id: str) -> str:
    digest = hashlib.sha256(internal_id.encode("utf-8")).hexdigest()[:40].upper()
    return "LH" + digest
