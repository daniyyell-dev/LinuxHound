from __future__ import annotations

from linuxhound.build import build_report

HOST = "lab-01"
COLLECTED = "2026-01-15T00:00:00Z"


def _coverage() -> dict:
    return {
        "users": "complete",
        "groups": "complete",
        "filesystem": "complete",
        "acls": "complete",
        "sudo": "complete",
        "systemd": "complete",
        "cron": "complete",
        "capabilities": "complete",
        "docker": "complete",
        "mounts": "complete",
    }


def _accounts(docker_member: bool) -> list[dict]:
    app_gids = [2003, 130] if docker_member else [2003]
    return [
        {"name": "root", "uid": 0, "gid": 0, "gids": [0], "shell": "/bin/bash", "password_status": "not_collected"},
        {"name": "dev", "uid": 2002, "gid": 2002, "gids": [2002, 110], "shell": "/bin/bash", "password_status": "not_collected"},
        {"name": "backup", "uid": 2001, "gid": 2001, "gids": [2001, 120], "shell": "/usr/sbin/nologin", "password_status": "not_collected"},
        {"name": "app", "uid": 2003, "gid": 2003, "gids": app_gids, "shell": "/usr/sbin/nologin", "password_status": "not_collected"},
    ]


def _groups(docker_member: bool) -> list[dict]:
    return [
        {"name": "root", "gid": 0, "members": ["root"]},
        {"name": "devs", "gid": 110, "members": ["dev"]},
        {"name": "backup", "gid": 120, "members": ["backup"]},
        {"name": "docker", "gid": 130, "members": ["app"] if docker_member else []},
    ]


def _files(hardened: bool) -> list[dict]:
    lab_mode = 0o755 if hardened else 0o775
    script_mode = 0o644 if hardened else 0o664
    script_gid = 0 if hardened else 120
    return [
        {"path": "/", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
        {"path": "/opt", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
        {"path": "/opt/lab", "type": "dir", "uid": 0, "gid": 110, "mode": lab_mode},
        {"path": "/opt/lab/backup.py", "type": "file", "uid": 0, "gid": script_gid, "mode": script_mode},
        {
            "path": "/opt/lab/secrets.dat",
            "type": "file",
            "uid": 0,
            "gid": 0,
            "mode": 0o640,
            "acl": {
                "user_obj": 6,
                "group_obj": 4,
                "other": 0,
                "mask": 4,
                "users": {"2003": 7},
                "groups": {},
            },
        },
        {"path": "/opt/lab/helper", "type": "file", "uid": 0, "gid": 0, "mode": 0o755, "capabilities": ["cap_setuid"]},
        {"path": "/opt/ro", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
        {"path": "/opt/ro/data", "type": "file", "uid": 0, "gid": 0, "mode": 0o666},
        {"path": "/home", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
        {"path": "/home/app", "type": "dir", "uid": 2003, "gid": 2003, "mode": 0o700},
        {"path": "/home/app/notes", "type": "file", "uid": 2003, "gid": 2003, "mode": 0o644},
        {"path": "/tmp", "type": "dir", "uid": 0, "gid": 0, "mode": 0o1777},
        {"path": "/tmp/note", "type": "file", "uid": 2003, "gid": 2003, "mode": 0o644},
        {"path": "/usr", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
        {"path": "/usr/local", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
        {"path": "/usr/local/bin", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
        {"path": "/usr/local/bin/status", "type": "binary", "uid": 0, "gid": 0, "mode": 0o4750},
        {"path": "/usr/local/bin/runme", "type": "file", "uid": 0, "gid": 0, "mode": 0o755},
        {"path": "/var", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
        {"path": "/var/run", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
        {"path": "/var/run/docker.sock", "type": "socket", "uid": 0, "gid": 130, "mode": 0o660},
        {"path": "/opt/lab/current", "type": "symlink", "uid": 0, "gid": 0, "mode": 0o777, "symlink_target": "/opt/lab/backup.py"},
        {"path": "/opt/lab/external", "type": "symlink", "uid": 0, "gid": 0, "mode": 0o777, "symlink_target": "/outside/missing"},
    ]


def _jobs() -> tuple[list[dict], list[dict]]:
    services = [{
        "name": "backup.service",
        "active_state": "active", "sub_state": "running", "runtime_observed": True,
        "enabled_state": "enabled", "main_pid": "1234",
        "user": "root",
        "user_defaulted": False,
        "group": None,
        "argv": ["/usr/bin/python3", "/opt/lab/backup.py"],
        "absolute_paths": ["/usr/bin/python3", "/opt/lab/backup.py"],
        "resolution": "absolute",
        "fragment_path": "/etc/systemd/system/backup.service",
        "sanitized_exec": "/usr/bin/python3 /opt/lab/backup.py",
    }]
    jobs = [
        {
            "name": "/etc/crontab:10",
            "user": "root",
            "argv": ["/opt/lab/backup.py"],
            "absolute_paths": ["/opt/lab/backup.py"],
            "resolution": "absolute",
            "source": "/etc/crontab",
            "sanitized_command": "/opt/lab/backup.py",
        },
        {
            "name": "/etc/crontab:11",
            "user": "root",
            "argv": ["backup.sh"],
            "absolute_paths": [],
            "resolution": "unresolved",
            "source": "/etc/crontab",
            "sanitized_command": "backup.sh",
        },
    ]
    return services, jobs


def snapshot(hardened: bool = False, docker_member: bool = True, complete: bool = True) -> dict:
    services, jobs = _jobs()
    coverage = _coverage()
    unresolved = [{
        "component": "cron",
        "source": "/etc/crontab",
        "message": "relative command backup.sh was not bound to a file",
        "impact": "a writable file named backup.sh is not treated as the job target",
    }]
    if not complete:
        services = []
        jobs = []
        coverage["systemd"] = "unavailable"
        coverage["cron"] = "unavailable"
        unresolved.append({
            "component": "systemd",
            "source": "scope",
            "message": "systemd definitions were not collected",
            "impact": "paths that depend on unit files cannot be reported as fixed",
        })
    return {
        "schema_version": "1.0.0",
        "kind": "linuxhound-snapshot",
        "host": {"id": HOST, "hostname": "lab-01"},
        "collected_at": COLLECTED,
        "collector": {"running_as_root": False, "euid": 2002},
        "scope": {"roots": ["/"], "exclusions": [], "truncated": False},
        "coverage": coverage,
        "errors": [],
        "unresolved": unresolved,
        "designated_admins": ["dev"],
        "accounts": _accounts(docker_member),
        "groups": _groups(docker_member),
        "files": _files(hardened),
        "mounts": [
            {"path": "/", "fstype": "ext4", "flags": ["rw"]},
            {"path": "/usr/local", "fstype": "ext4", "flags": ["rw", "nosuid", "noexec"]},
            {"path": "/opt/ro", "fstype": "ext4", "flags": ["ro"]},
        ],
        "sudo_rules": [
            {
                "source_type": "user",
                "source_name": "dev",
                "run_as_user": "root",
                "nopasswd": False,
                "commands": ["/usr/bin/id"],
                "source_file": "/etc/sudoers.d/dev",
                "raw_sanitized": "dev ALL=(root) /usr/bin/id",
                "host_restricted": False,
            },
            {
                "source_type": "user",
                "source_name": "backup",
                "run_as_user": "root",
                "nopasswd": True,
                "commands": ["/usr/bin/true"],
                "source_file": "/etc/sudoers.d/backup",
                "raw_sanitized": "backup ALL=(root) NOPASSWD: /usr/bin/true",
                "host_restricted": False,
            },
        ],
        "services": services,
        "jobs": jobs,
        "containers": [{
            "id": "ctr-lab-1",
            "name": "appbox",
            "user": "0",
            "privileged": False,
            "pid_mode": "",
            "userns_mode": "private",
            "binds": [],
            "cap_add": [],
            "identity_boundary": "container_uid_not_host_uid",
        }],
        "validation_evidence": [],
    }


def before_report() -> dict:
    return build_report(snapshot(False, True, True))


def after_report() -> dict:
    return build_report(snapshot(True, False, True))


def incomplete_after_report() -> dict:
    return build_report(snapshot(True, False, False))


def injection_report() -> dict:
    payload = "</script><img src=x onerror=alert(1)>"
    document = snapshot(True, False, True)
    document["accounts"] = [
        {"name": "root", "uid": 0, "gid": 0, "gids": [0], "shell": "/bin/bash", "password_status": "not_collected"},
        {"name": payload, "uid": 2004, "gid": 2004, "gids": [2004], "shell": "/bin/bash", "password_status": "not_collected"},
    ]
    document["groups"] = [{"name": payload, "gid": 2004, "members": [payload]}]
    document["sudo_rules"] = []
    document["services"] = []
    document["jobs"] = []
    document["containers"] = []
    document["files"] = [
        {"path": "/", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
        {"path": "/opt", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
        {"path": "/opt/lab", "type": "dir", "uid": 0, "gid": 0, "mode": 0o755},
    ]
    return build_report(document)


def with_validation(report: dict) -> dict:
    source = snapshot(False, True, True)
    paths=build_report(source)["analysis"]["paths"]
    source["validation_evidence"] = [{
        "id": "val-lab-"+str(index), "path_key":path["id"],
        "host_id":HOST,"collected_at":COLLECTED,"reviewer":"synthetic-reviewer",
        "method": "independent-review",
        "statement": "Synthetic external validation example, not an executed exploit.",
    } for index,path in enumerate(paths) if path["pattern"]=="writable-root-job" and path["account"]=="backup"]
    return build_report(source)
