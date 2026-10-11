from __future__ import annotations

import re

from linuxhound.ids import opengraph_id

SOURCE_KIND = "LinuxHound"
_KIND_RE = re.compile(r"^[A-Za-z0-9_]+$")
_TAG_PREFIX = "tag_"

_NODE_KIND = {
    "host": "LH_Host",
    "account": "LH_Account",
    "group": "LH_Group",
    "file": "LH_File",
    "directory": "LH_Directory",
    "symlink": "LH_Symlink",
    "binary": "LH_Binary",
    "service": "LH_Service",
    "job": "LH_Job",
    "container": "LH_Container",
    "capability": "LH_Capability",
}

_EDGE_KIND = {
    "OwnedBy": "LH_OwnedBy",
    "GroupOwnedBy": "LH_GroupOwnedBy",
    "Contains": "LH_Contains",
    "LinksTo": "LH_LinksTo",
    "MemberOf": "LH_MemberOf",
    "CanRead": "LH_CanRead",
    "CanWrite": "LH_CanWrite",
    "CanReplace": "LH_CanReplace",
    "CanDelete": "LH_CanDelete",
    "CanExecute": "LH_CanExecute",
    "CanTraverse": "LH_CanTraverse",
    "CanList": "LH_CanList",
    "CanCreate": "LH_CanCreate",
    "RunsAs": "LH_RunsAs",
    "Invokes": "LH_Invokes",
    "SudoAllows": "LH_SudoAllows",
    "HasCapability": "LH_HasCapability",
    "Configures": "LH_Configures",
    "BindMounts": "LH_BindMounts",
    "RunsOn": "LH_RunsOn",
    "MayInfluence": "LH_MayInfluence",
}

_TRAVERSABLE = {
    "LH_OwnedBy": False,
    "LH_GroupOwnedBy": False,
    "LH_Contains": False,
    "LH_LinksTo": False,
    "LH_MemberOf": True,
    "LH_CanRead": False,
    "LH_CanWrite": False,
    "LH_CanReplace": False,
    "LH_CanDelete": False,
    "LH_CanExecute": False,
    "LH_CanTraverse": False,
    "LH_CanList": False,
    "LH_CanCreate": False,
    "LH_RunsAs": False,
    "LH_Invokes": False,
    "LH_SudoAllows": False,
    "LH_SudoAllowsIfAuthenticated": False,
    "LH_HasCapability": False,
    "LH_Configures": False,
    "LH_BindMounts": False,
    "LH_RunsOn": False,
    "LH_MayInfluence": False,
}


def export_opengraph(report: dict) -> dict:
    host_internal = next(node["id"] for node in report["nodes"] if node["type"] == "host")
    host_graph_id = opengraph_id(host_internal)
    id_map = {node["id"]: opengraph_id(node["id"]) for node in report["nodes"]}
    nodes = []
    for node in report["nodes"]:
        kind = _NODE_KIND[node["type"]]
        properties = {
            "displayname": str(node["name"]),
            "name": id_map[node["id"]],
            "environmentid": host_graph_id,
            "classification": "observed_permission",
            "verified": False,
        }
        if node["type"] == "host":
            properties["collected"] = True
        for key, value in (node.get("properties") or {}).items():
            safe = _property(key, value)
            if safe is not None:
                properties[safe[0]] = safe[1]
        nodes.append({"id": id_map[node["id"]], "kinds": [kind], "properties": properties})
    edges = []
    for edge in report["edges"]:
        kind = _EDGE_KIND[edge["type"]]
        if edge["type"] == "SudoAllows" and "authenticated sudo" in (edge.get("prerequisites") or []):
            kind = "LH_SudoAllowsIfAuthenticated"
        edges.append({
            "start": {"match_by": "id", "value": id_map[edge["source"]]},
            "end": {"match_by": "id", "value": id_map[edge["target"]]},
            "kind": kind,
            "properties": {**_edge_properties(edge), "evidence_ids": edge.get("evidence_ids") or [],
                           "collected_at": report["collection"].get("collected_at") or "unknown"},
        })
    payload = {
        "metadata": {"source_kind": SOURCE_KIND},
        "graph": {"nodes": nodes, "edges": edges},
    }
    problems = validate_opengraph(payload)
    if problems:
        raise ValueError("OpenGraph export failed validation: " + "; ".join(problems))
    return {
        "payload": payload,
        "definition": definition_schema(),
        "fidelity": fidelity_notes(),
    }


def definition_schema() -> dict:
    node_kinds = []
    for kind in sorted(set(_NODE_KIND.values())):
        node_kinds.append({
            "name": kind,
            "display_name": kind.replace("_", " "),
            "description": f"LinuxHound {kind} observation. This is not a confirmed vulnerability.",
            "is_display_kind": True,
        })
    relationships = []
    for kind, traversable in sorted(_TRAVERSABLE.items()):
        relationships.append({
            "name": kind,
            "description": (
                "Observed or conditional LinuxHound relationship. "
                "Non-traversable kinds are excluded from BloodHound attack-path search "
                "because OpenGraph cannot represent an unverified prerequisite."
            ),
            "is_traversable": traversable,
        })
    return {
        "schema": {
            "name": "LinuxHound",
            "display_name": "LinuxHound",
            "version": "v0.1.0",
            "namespace": "LH",
        },
        "node_kinds": node_kinds,
        "relationship_kinds": relationships,
        "environments": [{
            "environment_kind": "LH_Host",
            "source_kind": SOURCE_KIND,
            "principal_kinds": ["LH_Account", "LH_Group"],
        }],
    }


def fidelity_notes() -> list[dict]:
    return [
        {
            "topic": "conditional privilege",
            "detail": (
                "BloodHound traversability is a single boolean per relationship kind. "
                "LinuxHound conditional attack paths, password-authenticated sudo, setuid files, "
                "file capabilities, and Docker group membership are exported as edges with "
                "verified=false and are not traversable. BloodHound pathfinding will not show them "
                "as attack paths. The native report remains the source of those explanations."
            ),
        },
        {
            "topic": "verified vulnerabilities",
            "detail": "OpenGraph has no independently verified state. verified=false is a property, not a pathfinding constraint beyond traversability.",
        },
        {
            "topic": "missing evidence",
            "detail": "Collection coverage, errors, and unresolved lookups are not OpenGraph objects. A missing edge in this export is not a clean host.",
        },
        {
            "topic": "evidence model",
            "detail": "Evidence methods, timestamps, and assumptions are flattened to strings and string arrays. Nested evidence objects are omitted because OpenGraph properties cannot be objects.",
        },
        {
            "topic": "identifiers",
            "detail": "OpenGraph ids cannot contain colons, and BloodHound uppercases name and environmentid. Exported ids are uppercase hashes. displayname keeps the human label.",
        },
        {
            "topic": "source kind",
            "detail": "metadata.source_kind is appended to every node kind during ingest. Payload nodes therefore carry only one kind so the ingested total stays within the three-kind limit.",
        },
        {
            "topic": "built-in edges",
            "detail": "Kinds are prefixed with LH_ so they do not collide with built-in edges such as MemberOf or post-processed edges such as AdminTo and Owns, which BloodHound would discard or reinterpret.",
        },
        {
            "topic": "legitimate administrators",
            "detail": "Administrator authority is a property. BloodHound does not separate it from unintended privilege escalation.",
        },
    ]


def validate_opengraph(payload: dict) -> list[str]:
    problems = []
    if not isinstance(payload, dict):
        return ["payload must be an object"]
    metadata = payload.get("metadata")
    if metadata is not None:
        if not isinstance(metadata, dict) or set(metadata) - {"source_kind"}:
            problems.append("metadata accepts only source_kind")
        elif metadata.get("source_kind") is not None and not isinstance(metadata.get("source_kind"), str):
            problems.append("source_kind must be a string or null")
    graph = payload.get("graph")
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        return problems + ["graph.nodes and graph.edges are required arrays"]
    seen = set()
    for node in graph["nodes"]:
        problems.extend(_validate_node(node, seen))
    for edge in graph["edges"]:
        problems.extend(_validate_edge(edge))
    return problems


def _validate_node(node: dict, seen: set[str]) -> list[str]:
    problems = []
    if not isinstance(node, dict):
        return ["node must be an object"]
    identifier = node.get("id")
    if not isinstance(identifier, str) or not identifier:
        problems.append("node id must be a string")
    elif ":" in identifier:
        problems.append(f"node id {identifier} contains a colon")
    elif identifier in seen:
        problems.append(f"duplicate node id {identifier}")
    else:
        seen.add(identifier)
    kinds = node.get("kinds")
    if not isinstance(kinds, list) or len(kinds) > 3 or not all(isinstance(kind, str) for kind in kinds or []):
        problems.append("node kinds must be an array of at most 3 strings")
    else:
        for kind in kinds:
            if kind.lower().startswith(_TAG_PREFIX):
                problems.append(f"kind {kind} uses the reserved tag_ prefix")
    if "properties" in node:
        problems.extend(_validate_properties(node.get("properties"), "node"))
    return problems


def _validate_edge(edge: dict) -> list[str]:
    problems = []
    if not isinstance(edge, dict):
        return ["edge must be an object"]
    for endpoint in ("start", "end"):
        problems.extend(_validate_endpoint(edge.get(endpoint), endpoint))
    kind = edge.get("kind")
    if not isinstance(kind, str) or not _KIND_RE.match(kind):
        problems.append("edge kind must match ^[A-Za-z0-9_]+$")
    elif kind.lower().startswith(_TAG_PREFIX):
        problems.append(f"edge kind {kind} uses the reserved tag_ prefix")
    if "properties" in edge:
        problems.extend(_validate_properties(edge.get("properties"), "edge"))
    return problems


def _validate_endpoint(endpoint: dict, label: str) -> list[str]:
    if not isinstance(endpoint, dict):
        return [f"{label} endpoint must be an object"]
    match_by = endpoint.get("match_by", "id")
    if match_by not in {"id", "name", "property"}:
        return [f"{label} match_by is invalid"]
    if match_by == "property":
        if "value" in endpoint:
            return [f"{label} property match cannot include value"]
        matchers = endpoint.get("property_matchers")
        if not isinstance(matchers, list) or not matchers:
            return [f"{label} property match requires property_matchers"]
        return []
    if "property_matchers" in endpoint or "value" not in endpoint or not isinstance(endpoint.get("value"), str):
        return [f"{label} id or name match requires value and forbids property_matchers"]
    if ":" in endpoint["value"]:
        return [f"{label} id contains a colon"]
    return []


def _validate_properties(properties, label: str) -> list[str]:
    if properties is None:
        return []
    if not isinstance(properties, dict):
        return [f"{label} properties must be an object"]
    problems = []
    if "objectid" in properties:
        problems.append("objectid is reserved and cannot be a property")
    for key, value in properties.items():
        if not isinstance(key, str) or key != key.lower() or not re.match(r"^[a-z][a-z0-9_]*$", key):
            problems.append(f"property name {key!r} must be lowercase")
        if not _primitive(value):
            problems.append(f"property {key} must be a primitive or a homogeneous primitive array")
    return problems


def _primitive(value) -> bool:
    if isinstance(value, (str, int, float, bool)) and not isinstance(value, bool):
        return True
    if isinstance(value, bool):
        return True
    if isinstance(value, list) and value:
        kinds = {type(item) for item in value}
        return len(kinds) == 1 and all(isinstance(item, (str, int, float, bool)) for item in value)
    if isinstance(value, list):
        return True
    return False


def _edge_properties(edge: dict) -> dict:
    properties = {
        "classification": "conditional" if edge.get("classification") == "conditional" else "observed",
        "verified": False,
        "authority": edge.get("authority") or "unknown",
    }
    if edge.get("prerequisites"):
        properties["prerequisites"] = [str(item) for item in edge["prerequisites"]]
    if edge.get("assumptions"):
        properties["assumptions"] = [str(item) for item in edge["assumptions"]]
    return properties


def _property(key: str, value):
    safe_key = re.sub(r"[^a-z0-9_]", "", key.lower())
    if not safe_key or safe_key == "objectid":
        return None
    if isinstance(value, bool) or isinstance(value, str):
        return safe_key, value
    if isinstance(value, int):
        return safe_key, value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return safe_key, value
    if isinstance(value, list) and all(isinstance(item, int) and not isinstance(item, bool) for item in value):
        return safe_key, value
    return None
