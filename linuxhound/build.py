from __future__ import annotations

import posixpath

from linuxhound.access import (
    can_create,
    can_delete,
    can_execute,
    can_list,
    can_read,
    can_replace,
    can_traverse,
    can_write_content,
    suid_honored,
)
from linuxhound.ids import edge_id, evidence_id, node_id, require_host_id
from linuxhound.sanitize import redact
from linuxhound.version import COLLECTION_METHOD, SCHEMA_VERSION, TOOL_NAME, VERSION


def build_report(snapshot: dict) -> dict:
    host_id = require_host_id(snapshot["host"]["id"])
    files = {}
    for info in snapshot.get("files") or []:
        item = dict(info)
        item["path"] = item["path"]
        files[item["path"]] = item
    accounts = list(snapshot.get("accounts") or [])
    groups = list(snapshot.get("groups") or [])
    by_name = {account["name"]: account for account in accounts}
    by_uid = {int(account["uid"]): account for account in accounts}
    group_by_name = {group["name"]: group for group in groups}
    designated = set(snapshot.get("designated_admins") or [])
    mounts = snapshot.get("mounts")
    collected_at = snapshot.get("collected_at")
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}
    evidence: dict[str, dict] = {}
    unresolved = list(snapshot.get("unresolved") or [])
    errors = list(snapshot.get("errors") or [])

    def add_evidence(method: str, source: str, statement: str, assumptions: list[str] | None = None) -> str:
        statement = redact(statement)
        identifier = evidence_id(method, source, statement)
        evidence[identifier] = {
            "id": identifier,
            "collected_at": collected_at,
            "method": method,
            "source": source,
            "statement": statement,
            "assumptions": list(assumptions or []),
        }
        return identifier

    def add_node(identifier: str, node_type: str, name: str, properties: dict) -> dict:
        node = nodes.get(identifier)
        if node is None:
            node = {
                "id": identifier,
                "type": node_type,
                "host_id": host_id,
                "name": name,
                "properties": {},
            }
            nodes[identifier] = node
        node["properties"].update(properties)
        return node

    def add_edge(edge_type: str, source: str, target: str, *, classification: str, authority: str,
                 evidence_ids: list[str], assumptions: list[str] | None = None,
                 prerequisites: list[str] | None = None, qualifier: str = "", properties: dict | None = None) -> dict:
        identifier = edge_id(edge_type, source, target, qualifier)
        edge = {
            "id": identifier,
            "type": edge_type,
            "source": source,
            "target": target,
            "classification": classification,
            "authority": authority,
            "verified": False,
            "evidence_ids": evidence_ids,
            "assumptions": list(assumptions or []),
            "prerequisites": list(prerequisites or []),
            "qualifier": qualifier,
            "properties": properties or {},
        }
        edges[identifier] = edge
        return edge

    host_node = node_id("host", host_id, host_id)
    add_node(host_node, "host", snapshot["host"].get("hostname") or host_id, {
        "hostname": snapshot["host"].get("hostname") or host_id,
    })
    root = by_uid.get(0)
    root_id = node_id("account", host_id, "0") if root else None
    if root:
        add_node(root_id, "account", root["name"], _account_properties(root, designated))
        add_evidence(
            "posix-account",
            "accounts",
            "uid 0 is recorded as legitimate administrator authority with implicit DAC override; the capability bounding set was not verified",
            ["Linux uid 0 DAC override is assumed unless the mount is NFS"],
        )

    for group in groups:
        gid = int(group["gid"])
        add_node(node_id("group", host_id, str(gid)), "group", group["name"], {
            "gid": gid,
            "members": list(group.get("members") or []),
        })

    for account in accounts:
        uid = int(account["uid"])
        account_node = node_id("account", host_id, str(uid))
        gids = _gids(account)
        add_node(account_node, "account", account["name"], _account_properties(account, designated))
        for gid in sorted(gids):
            group_node = node_id("group", host_id, str(gid))
            if group_node not in nodes:
                add_node(group_node, "group", str(gid), {"gid": gid, "members": []})
            statement = f"{account['name']} is a member of gid {gid}"
            ev = add_evidence("group-membership", f"account:{account['name']}", statement)
            add_edge(
                "MemberOf",
                account_node,
                group_node,
                classification="observed_permission",
                authority=_authority(account, designated),
                evidence_ids=[ev],
                qualifier=str(gid),
            )

    for info in files.values():
        file_node = node_id("file", host_id, info["path"])
        node_type = "binary" if _is_binary(info) else _file_type(info)
        add_node(file_node, node_type, info["path"], {
            "path": info["path"],
            "file_type": info.get("type"),
            "uid": info.get("uid"),
            "gid": info.get("gid"),
            "mode": info.get("mode"),
            "suid": bool(int(info.get("mode") or 0) & 0o4000),
            "sgid": bool(int(info.get("mode") or 0) & 0o2000),
            "sticky": bool(int(info.get("mode") or 0) & 0o1000),
            "capabilities": list(info.get("capabilities") or []),
            "symlink_target": info.get("symlink_target"),
        })
        if info.get("capabilities"):
            ev = add_evidence(
                "file-capability",
                info["path"],
                f"{info['path']} has capabilities {', '.join(info['capabilities'])}; a capability is not a confirmed vulnerability",
                ["file capability behavior was not executed"],
            )
            for capability in info["capabilities"]:
                cap_id = node_id("capability", host_id, capability)
                add_node(cap_id, "capability", capability, {"context": "file"})
                add_edge("HasCapability", file_node, cap_id, classification="observed_permission",
                         authority="unknown", evidence_ids=[ev], qualifier=capability)

    for info in files.values():
        if info.get("metadata_collected") is False:
            continue
        path = info["path"]
        file_node = node_id("file", host_id, path)
        for property_name, kind, relationship in (
            ("uid", "account", "OwnedBy"), ("gid", "group", "GroupOwnedBy"),
        ):
            numeric_id = info.get(property_name)
            if numeric_id is None:
                continue
            target = node_id(kind, host_id, str(numeric_id))
            if target not in nodes:
                continue
            ev = add_evidence("filesystem-metadata", path,
                              f"{path} records {property_name} {numeric_id}; ownership alone is not an execution or privilege-escalation grant")
            add_edge(relationship, file_node, target, classification="observed_permission",
                     authority="unknown", evidence_ids=[ev])
        parent = posixpath.dirname(path)
        if parent != path and parent in files and files[parent].get("type") == "dir":
            ev = add_evidence("filesystem-path", path,
                              f"{path} is a recorded child of {parent}; containment alone grants no access")
            add_edge("Contains", node_id("file", host_id, parent), file_node,
                     classification="observed_permission", authority="unknown", evidence_ids=[ev])
        target_path = info.get("symlink_target")
        if info.get("type") == "symlink" and isinstance(target_path, str):
            target_path = posixpath.normpath(target_path if target_path.startswith("/") else posixpath.join(parent, target_path))
            if target_path in files:
                ev = add_evidence("symlink-metadata", path,
                                  f"{path} names {target_path}; target was derived from recorded link metadata, not executed")
                add_edge("LinksTo", file_node, node_id("file", host_id, target_path),
                         classification="observed_permission", authority="unknown", evidence_ids=[ev],
                         assumptions=["runtime symlink resolution and target access are not established by this relationship"])

    for account in accounts:
        if int(account["uid"]) == 0:
            continue
        uid = int(account["uid"])
        gids = _gids(account)
        account_node = node_id("account", host_id, str(uid))
        authority = _authority(account, designated)
        acl_gap = (snapshot.get("coverage") or {}).get("acls") != "complete"
        identity_gap = any((snapshot.get("coverage") or {}).get(domain) != "complete" for domain in ("users", "groups"))
        for info in files.values():
            _emit_file_edges(
                add_edge, add_evidence, files, mounts, account, account_node, authority, uid, gids, info, host_id,
                acl_gap=acl_gap,
                identity_gap=identity_gap,
            )

    for rule in snapshot.get("sudo_rules") or []:
        _emit_sudo(
            add_edge, add_evidence, rule, by_name, group_by_name, host_id, designated, unresolved, root_id,
        )

    for service in snapshot.get("services") or []:
        _emit_job_like(
            add_edge, add_evidence, add_node, service, "service", by_name, host_id, files, unresolved, root_id,
        )
    for job in snapshot.get("jobs") or []:
        _emit_job_like(
            add_edge, add_evidence, add_node, job, "job", by_name, host_id, files, unresolved, root_id,
        )

    for container in snapshot.get("containers") or []:
        identifier = node_id("container", host_id, str(container["id"]))
        add_node(identifier, "container", container.get("name") or container["id"], {
            "user": container.get("user"),
            "privileged": container.get("privileged"),
            "pid_mode": container.get("pid_mode") or "",
            "userns_mode": container.get("userns_mode") or "",
            "binds": list(container.get("binds") or []),
            "cap_add": list(container.get("cap_add") or []),
            "cap_drop": container.get("cap_drop"),
            "security_opt": container.get("security_opt"),
            "mounts": [{key: mount.get(key) for key in ("type", "source", "destination", "rw")} for mount in container["mounts"]] if isinstance(container.get("mounts"), list) else None,
            "identity_boundary": container.get("identity_boundary") or "unknown",
            "running": container.get("running"),
            "status": container.get("status", "unknown"),
            "readonly_rootfs": container.get("readonly_rootfs"),
        })
        ev = add_evidence(
            "docker-metadata",
            identifier,
            "container identity was recorded from metadata only; environment variables were not collected",
            ["container uid is not treated as host uid unless the snapshot says the user namespace is the host namespace"],
        )
        add_edge("RunsOn", identifier, node_id("host", host_id, host_id),
                 classification="observed_permission", authority="unknown", evidence_ids=[ev],
                 assumptions=["runtime placement does not grant host administrative access"])
        for mount in container.get("mounts") or []:
            source = mount.get("source")
            if source not in files or mount.get("type") != "bind":
                continue
            add_edge("BindMounts", identifier, node_id("file", host_id, source),
                     classification="observed_permission", authority="unknown", evidence_ids=[ev],
                     qualifier=source + ":" + mount.get("destination", ""),
                     properties={"rw": bool(mount.get("rw")), "destination": mount.get("destination")},
                     assumptions=["a read-write bind flag does not override host DAC, LSM or a user-namespace boundary"])

    report = {
        "schema_version": SCHEMA_VERSION,
        "kind": "linuxhound-report",
        "tool": {"name": TOOL_NAME, "version": VERSION},
        "provenance": {
            "tool_name": TOOL_NAME,
            "tool_version": VERSION,
            "schema_version": SCHEMA_VERSION,
            "collected_at": collected_at,
            "collection_method": COLLECTION_METHOD,
            "designated_admins": sorted(designated),
        },
        "host": {"id": host_id, "hostname": snapshot["host"].get("hostname") or host_id},
        "collection": {
            "collected_at": collected_at,
            "running_as_root": bool((snapshot.get("collector") or {}).get("running_as_root")),
            "method": COLLECTION_METHOD,
            "scope": snapshot.get("scope") or {},
            "coverage": dict(snapshot.get("coverage") or {}),
            "errors": errors,
            "unresolved": unresolved,
        },
        "observations": {
            "accounts": accounts,
            "groups": groups,
            "files": list(files.values()),
            "sudo_rules": list(snapshot.get("sudo_rules") or []),
            "services": list(snapshot.get("services") or []),
            "jobs": list(snapshot.get("jobs") or []),
            "containers": list(snapshot.get("containers") or []),
            "mounts": mounts,
        },
        "validation_evidence": list(snapshot.get("validation_evidence") or []),
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "evidence": list(evidence.values()),
    }
    from linuxhound.analyze import attach_analysis
    return attach_analysis(report)


def _account_properties(account: dict, designated: set[str]) -> dict:
    return {
        "uid": int(account["uid"]),
        "gid": int(account.get("gid") or 0),
        "gids": sorted(_gids(account)),
        "shell": account.get("shell") or "",
        "password_status": account.get("password_status") or "not_collected",
        "designated_admin": account["name"] in designated or int(account["uid"]) == 0,
        "implicit_dac_override": int(account["uid"]) == 0,
    }


def _authority(account: dict, designated: set[str]) -> str:
    if int(account["uid"]) == 0 or account["name"] in designated:
        return "legitimate_administrator"
    return "possible_unintended"


def _gids(account: dict) -> set[int]:
    gids = {int(gid) for gid in account.get("gids") or []}
    if account.get("gid") is not None:
        gids.add(int(account["gid"]))
    return gids


def _file_type(info: dict) -> str:
    kind = info.get("type")
    if kind == "dir":
        return "directory"
    if kind == "symlink":
        return "symlink"
    return "file"


def _is_binary(info: dict) -> bool:
    mode = int(info.get("mode") or 0)
    return bool(mode & 0o4000 or mode & 0o2000 or info.get("capabilities") or info.get("type") == "binary")


def _emit_file_edges(add_edge, add_evidence, files, mounts, account, account_node, authority, uid, gids, info, host_id, acl_gap=False, identity_gap=False):
    path = info["path"]
    file_node = node_id("file", host_id, path)
    checks = []
    if info.get("type") == "dir":
        checks.extend([
            ("CanTraverse", can_traverse(files, mounts, uid, gids, path)),
            ("CanList", can_list(files, mounts, uid, gids, path)),
            ("CanCreate", can_create(files, mounts, uid, gids, path)),
        ])
    elif info.get("type") != "symlink":
        checks.extend([
            ("CanRead", can_read(files, mounts, uid, gids, path)),
            ("CanWrite", can_write_content(files, mounts, uid, gids, path)),
            ("CanExecute", can_execute(files, mounts, uid, gids, path)),
            ("CanReplace", can_replace(files, mounts, uid, gids, path)),
            ("CanDelete", can_delete(files, mounts, uid, gids, path)),
        ])
    else:
        checks.extend([
            ("CanRead", can_read(files, mounts, uid, gids, path)),
            ("CanWrite", can_write_content(files, mounts, uid, gids, path)),
            ("CanExecute", can_execute(files, mounts, uid, gids, path)),
            ("CanReplace", can_replace(files, mounts, uid, gids, path)),
            ("CanDelete", can_delete(files, mounts, uid, gids, path)),
        ])
    for edge_type, decision in checks:
        if decision.state == "unresolved":
            continue
        if not decision.granted:
            continue
        assumptions = list(decision.assumptions)
        if acl_gap:
            assumptions.append("ACLs were not fully collected; a named entry or mask could change this result")
        if identity_gap:
            assumptions.append("account or supplementary-group coverage is incomplete; effective rights may differ")
        ev = add_evidence("dac-acl-mount", path, f"{account['name']} {edge_type} {path}: {decision.reason}", assumptions)
        classification = "conditional" if assumptions else decision.classification
        add_edge(
            edge_type,
            account_node,
            file_node,
            classification=classification,
            authority=authority,
            evidence_ids=[ev],
            assumptions=assumptions,
            qualifier=path,
        )


def _emit_sudo(add_edge, add_evidence, rule, by_name, group_by_name, host_id, designated, unresolved, root_id):
    principals = []
    if rule.get("source_type") == "group":
        group = group_by_name.get(rule.get("source_name"))
        if not group:
            unresolved.append({
                "component": "sudo",
                "source": rule.get("source_file") or "sudoers",
                "message": f"sudo group {rule.get('source_name')} was not collected",
                "impact": "members of this group were not granted SudoAllows edges",
            })
            return
        for name in group.get("members") or []:
            if name in by_name:
                principals.append(by_name[name])
    else:
        account = by_name.get(rule.get("source_name"))
        if account:
            principals.append(account)
        else:
            unresolved.append({
                "component": "sudo",
                "source": rule.get("source_file") or "sudoers",
                "message": f"sudo user {rule.get('source_name')} was not collected",
                "impact": "this sudo rule was not applied to an account",
            })
            return
    run_as = rule.get("run_as_user") or "root"
    if run_as in {"root", "ALL"} and root_id:
        target = root_id
    elif run_as in by_name:
        target = node_id("account", host_id, str(by_name[run_as]["uid"]))
    else:
        unresolved.append({
            "component": "sudo",
            "source": rule.get("source_file") or "sudoers",
            "message": f"sudo run-as account {run_as} was not collected",
            "impact": "SudoAllows target is unresolved",
        })
        return
    authentication = not bool(rule.get("nopasswd"))
    assumptions = []
    classification = "observed_permission"
    if authentication:
        classification = "conditional"
        assumptions.append("password or another sudo authenticator is required; the rule was not treated as a non-interactive grant")
    if rule.get("host_restricted"):
        classification = "conditional"
        assumptions.append("the sudo rule is host-qualified and this collection did not prove the current host matches")
    assumptions.append("sudo policy was read as configuration; command behavior was not executed")
    commands = ", ".join(rule.get("commands") or [])
    for account in principals:
        statement = redact(
            f"{account['name']} sudo as {run_as}: {rule.get('raw_sanitized') or commands}"
        )
        ev = add_evidence("sudoers", rule.get("source_file") or "sudoers", statement, assumptions)
        add_edge(
            "SudoAllows",
            node_id("account", host_id, str(account["uid"])),
            target,
            classification=classification,
            authority=_authority(account, designated),
            evidence_ids=[ev],
            assumptions=assumptions,
            prerequisites=(["authenticated sudo"] if authentication else []),
            qualifier=commands,
            properties={
                "nopasswd": bool(rule.get("nopasswd")),
                "host_restricted": bool(rule.get("host_restricted")),
                "commands": list(rule.get("commands") or []),
                "run_as": run_as,
                "verified": False,
            },
        )


def _emit_job_like(add_edge, add_evidence, add_node, spec, kind, by_name, host_id, files, unresolved, root_id):
    name = spec["name"]
    identifier = node_id(kind, host_id, name)
    user_name = spec.get("user")
    defaulted = bool(spec.get("user_defaulted"))
    add_node(identifier, kind, name, {
        "user": user_name or ("root" if defaulted else ""),
        "user_defaulted": defaulted,
        "resolution": spec.get("resolution"),
        "sanitized_command": redact(spec.get("sanitized_exec") or spec.get("sanitized_command") or ""),
        "absolute_paths": list(spec.get("absolute_paths") or []),
        "active_state": spec.get("active_state", "unknown"),
        "sub_state": spec.get("sub_state", "unknown"),
        "enabled_state": spec.get("enabled_state", "unknown"),
        "runtime_observed": bool(spec.get("runtime_observed")),
        "main_pid": spec.get("main_pid"),
        "unit_kind": spec.get("unit_kind", kind),
        "sandbox": spec.get("sandbox") or {},
        "dynamic_user": spec.get("dynamic_user"),
    })
    if spec.get("unit_kind") == "timer":
        return
    for config in [spec.get("fragment_path")] + (spec.get("drop_in_paths") or []):
        if config not in files:
            continue
        ev = add_evidence("unit-configuration", config, f"{name} loads configuration from {config}")
        add_edge("Configures", node_id("file", host_id, config), identifier,
                 classification="conditional", authority="unknown", evidence_ids=[ev], qualifier=config,
                 prerequisites=["configuration must be reloaded and the affected command run"],
                 assumptions=["editing a unit is not proof of immediate service control"])
    if defaulted and root_id:
        target = root_id
        assumptions = ["a system unit without User= is assumed to run as root; this was not verified by executing it"]
        classification = "conditional"
        user_label = "root (default)"
    else:
        account = by_name.get(user_name)
        if account is None and user_name == "root" and root_id:
            target = root_id
            assumptions = []
            classification = "observed_permission"
            user_label = "root"
        elif account is None:
            unresolved.append({
                "component": kind,
                "source": spec.get("fragment_path") or spec.get("source") or name,
                "message": f"{name} run-as account {user_name} was not collected",
                "impact": "RunsAs was not created; missing account evidence is not proof the job is unprivileged",
            })
            target = None
            assumptions = []
            classification = "conditional"
            user_label = user_name or ""
        else:
            target = node_id("account", host_id, str(account["uid"]))
            assumptions = []
            classification = "observed_permission"
            user_label = account["name"]
    if target:
        ev = add_evidence(
            "unit-or-cron",
            spec.get("fragment_path") or spec.get("source") or name,
            f"{name} is configured to run as {user_label}",
            assumptions,
        )
        add_edge(
            "RunsAs",
            identifier,
            target,
            classification=classification,
            authority="legitimate_administrator" if user_label.startswith("root") else "unknown",
            evidence_ids=[ev],
            assumptions=assumptions,
            qualifier=user_label,
        )
    if spec.get("resolution") != "absolute":
        unresolved.append({
            "component": kind,
            "source": spec.get("fragment_path") or spec.get("source") or name,
            "message": f"{name} does not name an absolute executable and script",
            "impact": "Invokes was not bound to a file; a writable file with a similar basename remains unconnected",
        })
        return
    for path in spec.get("absolute_paths") or []:
        if path not in files:
            unresolved.append({
                "component": kind,
                "source": spec.get("fragment_path") or spec.get("source") or name,
                "message": f"{name} names {path}, which was not collected",
                "impact": "the invocation stays unresolved and is not evidence that the path is safe",
            })
            continue
        ev = add_evidence(
            "command-line",
            spec.get("fragment_path") or spec.get("source") or name,
            f"{name} names absolute path {path}; interpreter and symlink behavior were not executed",
            ["an absolute command-line path is evidence the job names that path, not proof of how the interpreter uses it"],
        )
        add_edge(
            "MayInfluence", node_id("file", host_id, path), identifier,
            classification="conditional", authority="unknown", evidence_ids=[ev],
            qualifier=path,
            prerequisites=["the named path must be executed as code or otherwise affect privileged behavior", "the affected job must run with the changed file"],
            assumptions=["naming a file does not prove an exploitable code dependency"],
        )
        add_edge(
            "Invokes",
            identifier,
            node_id("file", host_id, path),
            classification="observed_permission",
            authority="unknown",
            evidence_ids=[ev],
            assumptions=["interpreter, import, and symlink behavior were not independently verified"],
            prerequisites=["the named path is executed as code rather than used only as data"],
            qualifier=path,
        )
