from __future__ import annotations

import hashlib

from linuxhound.access import suid_honored
from linuxhound.ids import node_id


_RIGHTS = {
    "read": "CanRead",
    "write": "CanWrite",
    "execute": "CanExecute",
    "replace": "CanReplace",
    "delete": "CanDelete",
    "create": "CanCreate",
    "list": "CanList",
    "traverse": "CanTraverse",
}


def attach_analysis(report: dict) -> dict:
    report = dict(report)
    report["analysis"] = {
        "paths": privilege_paths(report),
        "notes": analysis_notes(report),
        "service_paths": service_paths(report),
        "coverage_warning": (
            "Missing evidence is not evidence of safety. "
            "A report cannot prove that a host is secure."
        ),
    }
    _apply_validation(report)
    from linuxhound.findings import findings
    report["analysis"]["findings"] = findings(report)
    return report


def who_can(report: dict, resource: str, right: str) -> list[dict]:
    edge_type = _RIGHTS[right]
    target = _resource_id(report, resource)
    results = []
    nodes = {node["id"]: node for node in report["nodes"]}
    for edge in report["edges"]:
        if edge["type"] == edge_type and edge["target"] == target:
            actor = nodes.get(edge["source"])
            results.append({
                "account": None if actor is None else actor["name"],
                "account_id": edge["source"],
                "edge_id": edge["id"],
                "classification": edge["classification"],
                "authority": edge["authority"],
                "verified": False,
                "assumptions": edge.get("assumptions") or [],
                "evidence_ids": edge.get("evidence_ids") or [],
                "explanation": _edge_explanation(report, edge),
            })
    for node in report["nodes"]:
        if node["type"] == "account" and node["properties"].get("implicit_dac_override"):
            results.append({
                "account": node["name"],
                "account_id": node["id"],
                "edge_id": None,
                "classification": "conditional",
                "authority": "legitimate_administrator",
                "verified": False,
                "assumptions": [
                    "uid 0 is assumed to bypass DAC except where a mount or capability bound says otherwise; this was not probed",
                ],
                "evidence_ids": [],
                "explanation": f"{node['name']} is uid 0. Root access is legitimate administrator authority, not an unintended escalation finding.",
            })
    return results


def privilege_paths(report: dict) -> list[dict]:
    paths = []
    paths.extend(_writable_root_jobs(report))
    paths.extend(_sudo_paths(report))
    paths.extend(_suid_paths(report))
    paths.extend(_capability_paths(report))
    paths.extend(_docker_paths(report))
    return paths


def paths_from_account(report: dict, account: str) -> list[dict]:
    account_id = _account_id(report, account)
    return [path for path in report.get("analysis", {}).get("paths") or privilege_paths(report)
            if path["account_id"] == account_id]


def influencing_root_jobs(report: dict) -> list[dict]:
    return [path for path in (report.get("analysis", {}).get("paths") or privilege_paths(report))
            if path["pattern"] == "writable-root-job"]


def analysis_notes(report: dict) -> list[dict]:
    notes = []
    files = {item["path"]: item for item in report["observations"]["files"]}
    mounts = report["observations"].get("mounts")
    host_id = report["host"]["id"]
    for info in files.values():
        if info.get("capabilities"):
            notes.append({
                "kind": "capability_not_a_vulnerability",
                "verified": False,
                "summary": (
                    f"{info['path']} has file capabilities {', '.join(info['capabilities'])}. "
                    "A capability grant is not a confirmed vulnerability."
                ),
            })
        if not (int(info.get("mode") or 0) & 0o4000):
            continue
        decision = suid_honored(info, mounts)
        file_id = node_id("file", host_id, info["path"])
        executable = any(
            edge["type"] == "CanExecute" and edge["target"] == file_id
            for edge in report["edges"]
        )
        if decision.state != "granted" or not executable:
            notes.append({
                "kind": "suid_not_a_path",
                "verified": False,
                "summary": (
                    f"{info['path']} is setuid, and that fact alone is not a confirmed vulnerability. "
                    f"{decision.reason} "
                    + ("No collected non-root account can execute it." if not executable else "")
                ),
            })
    for item in report["collection"].get("unresolved") or []:
        notes.append({
            "kind": "unresolved",
            "verified": False,
            "summary": f"{item.get('message')} {item.get('impact')}".strip(),
        })
    return notes


def _writable_root_jobs(report: dict) -> list[dict]:
    paths=[]
    nodes={node["id"]:node for node in report["nodes"]}
    for path in service_paths(report, include_jobs=True):
        service=nodes[path["service_id"]]
        run_as=next((edge for edge in report["edges"] if edge["type"]=="RunsAs" and edge["source"]==service["id"]),None)
        if not run_as or nodes[run_as["target"]]["properties"].get("uid")!=0:
            continue
        if path["influence_type"]!="Invokes":
            continue
        copy=dict(path)
        copy["pattern"]="writable-root-job"
        copy["id"]=_path_id(["writable-root-job",*[step["edge_id"] for step in path["steps"]]])
        copy["coverage_domains"]=sorted(set(path["coverage_domains"]+["users"]))
        copy["summary"] += " The recorded run-as identity is root."
        paths.append(copy)
    return paths


def service_paths(report: dict, service: str | None = None, include_jobs: bool = False) -> list[dict]:
    nodes={node["id"]:node for node in report["nodes"]}
    grants={};runs={}
    for edge in report["edges"]:
        if edge["type"] in ("CanWrite","CanReplace"):
            grants.setdefault(edge["target"],[]).append(edge)
        elif edge["type"]=="RunsAs":runs[edge["source"]]=edge
    paths=[]
    for relation in report["edges"]:
        if relation["type"] in ("MayInfluence", "Configures"):job_id,file_id=relation["target"],relation["source"]
        else:continue
        job=nodes[job_id]
        if job["type"] not in ({"service","job"} if include_jobs else {"service"}):continue
        if service and service not in (job_id,job["name"]):continue
        for grant in grants.get(file_id,[]):
            actor=nodes[grant["source"]]
            if actor["type"]!="account":continue
            sequence=[grant,relation]+([runs[job_id]] if job_id in runs else [])
            assumptions=list(dict.fromkeys(item for edge in sequence for item in edge.get("assumptions") or []))
            prerequisites=["the affected service/job must run; writable metadata alone is not exploitation"]
            prerequisites+=relation.get("prerequisites") or []
            path=_path("service-influence",actor,
                f"{actor['name']} has {grant['type']} on {nodes[file_id]['name']}. The file has a {relation['type']} relationship to {job['name']}. Its effect on service behavior is conditional.",
                sequence,prerequisites,assumptions,grant.get("authority","unknown"),"conditional_attack_path")
            path.update(service=job["name"],service_id=job_id,influence_type="Invokes" if relation["type"]=="MayInfluence" else relation["type"],
                active_state=job["properties"].get("active_state","unknown"),
                coverage_domains=["systemd" if job["type"]=="service" else "cron","filesystem","acls","groups","users","mounts"])
            paths.append(path)
    return paths


def list_services(report: dict, running_only: bool = False) -> list[dict]:
    return [node for node in report["nodes"] if node["type"]=="service"
            and (not running_only or node["properties"].get("active_state")=="active")]


def _sudo_paths(report: dict) -> list[dict]:
    nodes = {node["id"]: node for node in report["nodes"]}
    paths = []
    for edge in report["edges"]:
        if edge["type"] != "SudoAllows":
            continue
        actor = nodes.get(edge["source"])
        target = nodes.get(edge["target"])
        if actor is None or target is None:
            continue
        commands = ", ".join(edge.get("properties", {}).get("commands") or [])
        authenticated = "authenticated sudo" in (edge.get("prerequisites") or [])
        authority = edge.get("authority") or "unknown"
        if authority == "legitimate_administrator":
            conclusion = "conditional_administrator_authority" if authenticated else "observed_administrator_authority"
        else:
            conclusion = "conditional_attack_path"
        prerequisites = list(edge.get("prerequisites") or [])
        prerequisites.append("the sudo rule was not executed; command behavior is not a verified vulnerability")
        if authenticated:
            summary = (
                f"{actor['name']} has a password-authenticated sudo rule ({commands}) "
                f"toward {target['name']}. The grant remains conditional on authentication "
                "and is not a verified vulnerability."
            )
        else:
            summary = (
                f"{actor['name']} has a NOPASSWD sudo rule ({commands}) toward {target['name']}. "
                "The rule is observed configuration. It is not an independently verified vulnerability, "
                "and a specific command is not treated as proof of full root control."
            )
        paths.append(_path(
            "sudo",
            actor,
            summary,
            [edge],
            prerequisites,
            list(edge.get("assumptions") or []),
            authority,
            conclusion,
        ))
    return paths


def _suid_paths(report: dict) -> list[dict]:
    nodes = {node["id"]: node for node in report["nodes"]}
    files = {item["path"]: item for item in report["observations"]["files"]}
    mounts = report["observations"].get("mounts")
    paths = []
    for info in files.values():
        if "mode" not in info:
            continue
        honored = suid_honored(info, mounts)
        if honored.state != "granted":
            continue
        file_id = node_id("file", report["host"]["id"], info["path"])
        for edge in report["edges"]:
            if edge["type"] != "CanExecute" or edge["target"] != file_id:
                continue
            actor = nodes.get(edge["source"])
            if actor is None:
                continue
            summary = (
                f"{actor['name']} can execute setuid file {info['path']} and the recorded mount "
                "does not set nosuid. Setuid plus execute permission is still not a confirmed "
                "vulnerability because the binary was not verified."
            )
            paths.append(_path(
                "suid-execute",
                actor,
                summary,
                [edge],
                ["the setuid binary would have to grant privilege when executed; that behavior was not tested"],
                list(honored.assumptions) + list(edge.get("assumptions") or []),
                edge.get("authority", "possible_unintended"),
                "conditional_attack_path",
            ))
    return paths


def _capability_paths(report: dict) -> list[dict]:
    nodes = {node["id"]: node for node in report["nodes"]}
    execution = {}
    for edge in report["edges"]:
        if edge["type"] == "CanExecute":
            execution.setdefault(edge["target"], []).append(edge)
    paths = []
    for edge in report["edges"]:
        if edge["type"] != "HasCapability":
            continue
        for grant in execution.get(edge["source"], []):
            actor = nodes[grant["source"]]
            path = _path("capability-execute", actor,
                f"{actor['name']} can execute {nodes[edge['source']]['name']}, which records {nodes[edge['target']]['name']}. Capability behavior is untested.",
                [grant, edge],
                ["the mount, process bounding set and namespace must honor the file capability", "the program must expose relevant capability behavior; no program was executed"],
                list(grant.get("assumptions") or []), grant.get("authority", "possible_unintended"), "conditional_attack_path")
            path["coverage_domains"] = ["capabilities", "filesystem", "acls", "users", "groups", "mounts"]
            paths.append(path)
    return paths


def _docker_paths(report: dict) -> list[dict]:
    nodes = {node["id"]: node for node in report["nodes"]}
    docker_groups = [
        node for node in report["nodes"]
        if node["type"] == "group" and node["name"] == "docker"
    ]
    paths = []
    for group in docker_groups:
        for edge in report["edges"]:
            if edge["type"] != "MemberOf" or edge["target"] != group["id"]:
                continue
            actor = nodes.get(edge["source"])
            if actor is None or actor["properties"].get("uid") == 0:
                continue
            summary = (
                f"{actor['name']} is a member of the docker group. Membership can be a conditional "
                "path to host control when the Docker socket is available. Group membership alone "
                "is not a confirmed vulnerability, and the collector does not exploit the socket."
            )
            path = _path(
                "docker-group",
                actor,
                summary,
                [edge],
                ["access to a live Docker API was not used to validate host control"],
                ["docker group membership is not host root by itself"],
                "possible_unintended",
                "conditional_attack_path",
            )
            path["coverage_domains"] = ["docker", "groups", "users"]
            paths.append(path)
    for container in report["observations"].get("containers") or []:
        boundary = container.get("identity_boundary") or "unknown"
        privileged = bool(container.get("privileged")) or any(
            "docker.sock" in bind for bind in container.get("binds") or []
        )
        if not privileged:
            continue
        if boundary == "container_uid_not_host_uid" and privileged:
            summary = (
                f"Container {container.get('name')} keeps a user-namespace boundary for ordinary "
                "container root, but privileged mode or a Docker socket bind is a conditional host-control "
                "path. It was not verified."
            )
        elif boundary == "host_user_namespace" and str(container.get("user") or "") in {"0", "root"}:
            summary = (
                f"Container {container.get('name')} records host user-namespace root. "
                "That is observed metadata, not a verified vulnerability."
            )
        else:
            summary = (
                f"Container {container.get('name')} has privileged mode or a Docker socket bind, "
                "with an unresolved identity boundary. Host control remains conditional and untested."
            )
        container_id = node_id("container", report["host"]["id"], str(container["id"]))
        related = [edge for edge in report["edges"] if edge["source"] == container_id and edge["type"] in ("RunsOn", "BindMounts")]
        paths.append({
            "id": _path_id(["docker-boundary", container.get("id") or ""]),
            "pattern": "docker-boundary",
            "account_id": None,
            "account": None,
            "conclusion": "conditional_attack_path",
            "authority": "unknown",
            "verified": False,
            "summary": summary,
            "prerequisites": ["container runtime configuration was not exploited"],
            "assumptions": ["environment variables were not collected"],
            "steps": [{"edge_id": edge["id"], "edge_type": edge["type"], "explanation": edge["type"]} for edge in related],
            "evidence_ids": sorted({ev for edge in related for ev in edge["evidence_ids"]}),
            "node_ids": sorted({container_id} | {endpoint for edge in related for endpoint in (edge["source"], edge["target"])}),
            "coverage_domains": ["docker"],
        })
    return paths


def _apply_validation(report: dict) -> None:
    supplied = list(report.get("validation_evidence") or [])
    for path in report["analysis"]["paths"]:
        item = next((candidate for candidate in supplied if candidate.get("host_id")==report["host"]["id"] and candidate.get("collected_at")==report["collection"]["collected_at"] and _validation_matches(path, candidate)), None)
        if not item:
            path["verified"] = False
            continue
        path["verified"] = True
        path["conclusion"] = "verified_vulnerability"
        path["prerequisites"] = list(path["prerequisites"]) + [
            f"independent validation {item.get('id')}: {item.get('statement')}"
        ]


def _validation_matches(path: dict, item: dict) -> bool:
    return bool(item.get("path_key") == path["id"] and item.get("method")
                and item.get("statement") and item.get("id") and item.get("reviewer")
                and item.get("collected_at"))


def _path(pattern, actor, summary, edges, prerequisites, assumptions, authority, conclusion) -> dict:
    node_ids = [actor["id"]]
    for edge in edges:
        node_ids.extend([edge["source"], edge["target"]])
    ordered = list(dict.fromkeys(node_ids))
    domains = []
    for edge in edges:
        domains.extend(_domains_for(edge["type"]))
    return {
        "id": _path_id([pattern, actor["id"], *[edge["id"] for edge in edges]]),
        "pattern": pattern,
        "account_id": actor["id"],
        "account": actor["name"],
        "conclusion": conclusion,
        "authority": authority,
        "verified": False,
        "summary": summary,
        "prerequisites": list(dict.fromkeys(prerequisites)),
        "assumptions": list(dict.fromkeys(assumptions)),
        "steps": [
            {"edge_id": edge["id"], "edge_type": edge["type"], "explanation": edge["type"]}
            for edge in edges
        ],
        "evidence_ids": list(dict.fromkeys(ev for edge in edges for ev in edge.get("evidence_ids") or [])),
        "node_ids": ordered,
        "coverage_domains": sorted(set(domains)),
    }


def _domains_for(edge_type: str) -> list[str]:
    if edge_type in {"CanRead", "CanWrite", "CanExecute", "CanReplace", "CanDelete", "CanCreate", "CanList", "CanTraverse"}:
        return ["filesystem", "mounts", "acls", "groups", "users"]
    if edge_type == "MemberOf":
        return ["groups", "users"]
    if edge_type == "SudoAllows":
        return ["sudo", "users", "groups"]
    if edge_type == "RunsAs":
        return ["systemd", "cron"]
    if edge_type == "Invokes":
        return ["systemd", "cron", "filesystem"]
    return []


def _path_id(parts: list[str]) -> str:
    raw = "|".join(parts)
    return "path/" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _resource_id(report: dict, resource: str) -> str:
    if resource.startswith("file/") or resource.startswith("directory/"):
        return resource
    return node_id("file", report["host"]["id"], resource)


def _account_id(report: dict, account: str) -> str:
    if account.startswith("account/"):
        return account
    for node in report["nodes"]:
        if node["type"] == "account" and (node["name"] == account or str(node["properties"].get("uid")) == account):
            return node["id"]
    raise KeyError(account)


def _edge_explanation(report: dict, edge: dict) -> str:
    evidence = {item["id"]: item for item in report["evidence"]}
    statements = [evidence[item]["statement"] for item in edge.get("evidence_ids") or [] if item in evidence]
    prefix = "; ".join(statements) or edge["type"]
    if edge.get("assumptions"):
        return prefix + " Assumptions: " + "; ".join(edge["assumptions"])
    return prefix
