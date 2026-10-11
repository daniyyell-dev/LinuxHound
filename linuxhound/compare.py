from __future__ import annotations

from linuxhound.version import TOOL_NAME, VERSION
from fnmatch import fnmatch


_FILE_RIGHTS = {
    "CanRead", "CanWrite", "CanExecute", "CanReplace", "CanDelete",
    "CanCreate", "CanList", "CanTraverse",
}


def compare_reports(before: dict, after: dict) -> dict:
    if before.get("kind") != "linuxhound-report" or after.get("kind") != "linuxhound-report":
        raise ValueError("compare expects two LinuxHound reports")
    if before["host"]["id"] != after["host"]["id"]:
        raise ValueError("reports are for different host ids; comparison stopped")
    warnings = []
    if before["tool"]["version"] != after["tool"]["version"]:
        warnings.append("tool versions differ; review both provenance records before relying on the diff")
    if before["schema_version"] != after["schema_version"]:
        warnings.append("schema versions differ")

    edge_changes = _diff_edges(before, after)
    path_changes = _diff_paths(before, after)
    return {
        "schema_version": before["schema_version"],
        "kind": "linuxhound-comparison",
        "tool": {"name": TOOL_NAME, "version": VERSION},
        "host": before["host"],
        "provenance": {"before": before.get("provenance"), "after": after.get("provenance")},
        "warnings": warnings,
        "coverage_changes": _coverage_changes(before, after),
        "configuration_changes": _configuration_changes(before, after),
        "service_changes": _object_changes(before, after, "services", "name", ("user", "active_state", "sub_state", "absolute_paths", "sandbox")),
        "container_changes": _object_changes(before, after, "containers", "id", ("running", "privileged", "mounts", "userns_mode", "user")),
        "edges": edge_changes,
        "paths": path_changes,
        "summary": {
            "edges_added": len(edge_changes["added"]),
            "edges_changed": len(edge_changes["changed"]),
            "edges_removed_under_complete_coverage": len(edge_changes["removed_under_complete_coverage"]),
            "edges_incomplete_not_a_fix": len(edge_changes["incomplete_not_a_fix"]),
            "paths_removed_under_complete_coverage": len(path_changes["removed_under_complete_coverage"]),
            "paths_incomplete_not_a_fix": len(path_changes["incomplete_not_a_fix"]),
            "configuration_changes": len(_configuration_changes(before, after)),
        },
        "statement": (
            "A path missing from a later incomplete collection is not a fix. "
            "Removed rights are limited to evidence both snapshots covered. "
            "No comparison proves the host is secure."
        ),
    }


def _coverage_changes(before: dict, after: dict) -> list[dict]:
    left = before["collection"].get("coverage") or {}
    right = after["collection"].get("coverage") or {}
    changes = []
    for key in sorted(set(left) | set(right)):
        if left.get(key) != right.get(key):
            changes.append({"domain": key, "before": left.get(key), "after": right.get(key)})
    return changes


def _configuration_changes(before: dict, after: dict) -> list[dict]:
    left = {item["path"]: item for item in before["observations"]["files"]}
    right = {item["path"]: item for item in after["observations"]["files"]}
    changes = []
    for path in sorted(set(left) & set(right)):
        fields = {}
        for field in ("mode", "uid", "gid", "acl", "capabilities", "symlink_target"):
            if left[path].get(field) != right[path].get(field):
                fields[field] = {"before": left[path].get(field), "after": right[path].get(field)}
        if fields:
            changes.append({"path": path, "changes": fields})
    return changes


def _diff_edges(before: dict, after: dict) -> dict:
    left = {edge["id"]: edge for edge in before["edges"]}
    right = {edge["id"]: edge for edge in after["edges"]}
    added = [_public_edge(edge) for edge_id, edge in sorted(right.items()) if edge_id not in left]
    removed = []
    incomplete = []
    for edge_id, edge in sorted(left.items()):
        if edge_id in right:
            continue
        domains = _edge_domains(before, edge)
        record = _public_edge(edge)
        record["coverage_domains"] = domains
        if _complete(after, domains) and _edge_still_in_scope(before, after, edge):
            removed.append(record)
        else:
            record["reason"] = "later snapshot does not completely cover the evidence this edge depends on"
            incomplete.append(record)
    changed = []
    for identifier in sorted(set(left) & set(right)):
        fields = {field: {"before": left[identifier].get(field), "after": right[identifier].get(field)}
                  for field in ("classification", "authority", "assumptions", "prerequisites", "properties")
                  if left[identifier].get(field) != right[identifier].get(field)}
        if fields:
            changed.append({"id": identifier, "type": left[identifier]["type"], "changes": fields})
    unchanged = len(set(left) & set(right)) - len(changed)
    return {
        "added": added,
        "changed": changed,
        "removed_under_complete_coverage": removed,
        "incomplete_not_a_fix": incomplete,
        "unchanged": unchanged,
    }


def _diff_paths(before: dict, after: dict) -> dict:
    left = {path["id"]: path for path in _analysis_paths(before)}
    right = {path["id"]: path for path in _analysis_paths(after)}
    added = [_public_path(path) for path_id, path in sorted(right.items()) if path_id not in left]
    removed = []
    incomplete = []
    changed = []
    for path_id, path in sorted(left.items()):
        if path_id not in right:
            record = _public_path(path)
            if _complete(after, path.get("coverage_domains") or []) and _path_nodes_in_scope(before, after, path):
                removed.append(record)
            else:
                record["reason"] = "the later snapshot is incomplete for this path; absence is not a fix"
                incomplete.append(record)
            continue
        if path.get("conclusion") != right[path_id].get("conclusion"):
            record = _public_path(path)
            record["after_conclusion"] = right[path_id].get("conclusion")
            changed.append(record)
    return {
        "added": added,
        "removed_under_complete_coverage": removed,
        "incomplete_not_a_fix": incomplete,
        "conclusion_changed": changed,
        "unchanged": len(set(left) & set(right)) - len(changed),
    }


def _edge_domains(report: dict, edge: dict) -> list[str]:
    nodes = {node["id"]: node for node in report["nodes"]}
    source = nodes.get(edge["source"], {})
    if edge["type"] in _FILE_RIGHTS:
        domains = ["filesystem", "mounts", "acls", "groups", "users"]
        target = nodes.get(edge["target"], {})
        path = (target.get("properties") or {}).get("path")
        info = next((item for item in report["observations"]["files"] if item["path"] == path), None)
        if info and info.get("acl"):
            domains.append("acls")
        return domains
    if edge["type"] == "MemberOf":
        return ["groups", "users"]
    if edge["type"] == "SudoAllows":
        return ["sudo", "users", "groups"]
    if edge["type"] in {"RunsAs", "Invokes"}:
        origin = "systemd" if source.get("type") == "service" else "cron" if source.get("type") == "job" else None
        domains = [origin, "users"] if origin else ["systemd", "cron", "users"]
        if edge["type"] == "Invokes":
            domains.append("filesystem")
        return domains
    if edge["type"] in ("Configures", "MayInfluence"):
        destination = nodes.get(edge["target"], {})
        return ["cron" if destination.get("type") == "job" else "systemd", "filesystem"]
    if edge["type"] == "BindMounts":
        return ["docker", "filesystem"]
    if edge["type"] == "RunsOn":
        return ["docker"]
    if edge["type"] == "HasCapability":
        return ["capabilities", "filesystem"]
    return ["filesystem"]


def _analysis_paths(report: dict) -> list[dict]:
    analysis = report.get("analysis") or {}
    paths = list(analysis.get("paths") or [])
    seen = {tuple(sorted(step["edge_id"] for step in path["steps"])) for path in paths}
    for path in analysis.get("service_paths") or []:
        key = tuple(sorted(step["edge_id"] for step in path["steps"]))
        if key not in seen:
            paths.append(path)
            seen.add(key)
    return paths


def _complete(report: dict, domains: list[str]) -> bool:
    coverage = report["collection"].get("coverage") or {}
    if not domains:
        return False
    return all(coverage.get(domain) == "complete" for domain in domains)


def _edge_still_in_scope(before: dict, after: dict, edge: dict) -> bool:
    nodes = {node["id"]: node for node in before["nodes"]}
    target = nodes.get(edge["target"], {})
    path = (target.get("properties") or {}).get("path")
    if not path:
        return True
    return _in_scope(path, after["collection"].get("scope") or {})


def _path_nodes_in_scope(before: dict, after: dict, path: dict) -> bool:
    nodes = {node["id"]: node for node in before["nodes"]}
    for node_id in path.get("node_ids") or []:
        node = nodes.get(node_id) or {}
        file_path = (node.get("properties") or {}).get("path")
        if file_path and not _in_scope(file_path, after["collection"].get("scope") or {}):
            return False
    return True


def _in_scope(path: str, scope: dict) -> bool:
    if any(fnmatch(path, pattern) or fnmatch(path.rsplit("/", 1)[-1], pattern) for pattern in scope.get("exclusions") or []):
        return False
    if path in (scope.get("dependency_paths") or []):
        return True
    roots = scope.get("roots") or ["/"]
    for root in roots:
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return True
    return False


def _object_changes(before, after, domain, key, fields):
    left = {obj[key]: obj for obj in before["observations"].get(domain) or []}
    right = {obj[key]: obj for obj in after["observations"].get(domain) or []}
    return [{"resource": identifier, "changes": {field: {"before": left[identifier].get(field), "after": right[identifier].get(field)}
            for field in fields if left[identifier].get(field) != right[identifier].get(field)}}
            for identifier in sorted(set(left) & set(right)) if any(left[identifier].get(field) != right[identifier].get(field) for field in fields)]


def _public_edge(edge: dict) -> dict:
    return {
        "id": edge["id"],
        "type": edge["type"],
        "source": edge["source"],
        "target": edge["target"],
        "classification": edge.get("classification"),
        "verified": False,
    }


def _public_path(path: dict) -> dict:
    return {
        "id": path["id"],
        "pattern": path.get("pattern"),
        "account": path.get("account"),
        "conclusion": path.get("conclusion"),
        "authority": path.get("authority"),
        "verified": bool(path.get("verified")),
        "summary": path.get("summary"),
        "coverage_domains": path.get("coverage_domains") or [],
    }
