from __future__ import annotations

import os
import shutil
import stat
import subprocess
import time
from fnmatch import fnmatch
from pathlib import Path

from linuxhound.parsers import (
    parse_crontab,
    parse_getfacl,
    parse_mounts,
    parse_sudoers,
    parse_systemctl_exec,
    parse_unit,
)
from linuxhound.sanitize import NEVER_READ_NAMES, NEVER_READ_SUFFIXES, may_read_config_text, redact
from linuxhound.version import SCHEMA_VERSION
from linuxhound import runtime


class CollectionError(RuntimeError):
    pass


def collect(
    roots: list[str],
    host_id: str,
    hostname: str | None = None,
    timeout: float = 60,
    max_files: int = 5000,
    max_depth: int = 8,
    exclusions: list[str] | None = None,
    designated_admins: list[str] | None = None,
    probe_current_user: bool = False,
    runtime_systemd: bool = True,
    docker: bool = False,
    max_services: int = 200,
    max_containers: int = 100,
) -> dict:
    if not roots:
        raise CollectionError("at least one collection root is required")
    if timeout <= 0 or max_files < 1 or max_depth < 0 or max_services < 1 or max_containers < 1:
        raise CollectionError("collection bounds must be positive (depth may be zero)")
    roots = [os.path.abspath(root) for root in roots]
    deadline = time.monotonic() + timeout
    exclusions = exclusions or []
    errors: list[dict] = []
    unresolved: list[dict] = []
    files: dict[str, dict] = {}
    truncated = False
    acl_attempted = 0
    acl_failed = 0
    getfacl = shutil.which("getfacl")

    def remaining() -> float:
        return deadline - time.monotonic()

    def record_error(component: str, message: str, impact: str) -> None:
        errors.append({"component": component, "message": message, "impact": impact})

    for root in roots:
        if remaining() <= 0:
            truncated = True
            record_error("filesystem", "collection timeout before the walk finished",
                         "files not visited are unknown; this is not evidence they are safe")
            break
        root_path = Path(root)
        if not root_path.exists():
            record_error("filesystem", f"root {root} does not exist", "that tree was not collected")
            continue
        def walk_error(exc):
            record_error("filesystem", "directory traversal failed: " + str(exc.filename),
                         "inaccessible subtrees were not visited")
        if root_path.is_file() or root_path.is_symlink():
            _record_path(files, root, errors)
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=walk_error):
            if remaining() <= 0 or len(files) >= max_files:
                truncated = True
                break
            depth = _depth(root, dirpath)
            if depth > max_depth:
                dirnames[:] = []
                truncated = True
                continue
            kept = []
            for name in dirnames:
                path = os.path.join(dirpath, name)
                if _excluded(path, exclusions):
                    continue
                if os.path.islink(path):
                    _record_path(files, path, errors)
                    continue
                kept.append(name)
            dirnames[:] = kept
            if not _excluded(dirpath, exclusions):
                _record_path(files, dirpath, errors)
            for name in filenames:
                path = os.path.join(dirpath, name)
                if _excluded(path, exclusions):
                    continue
                if len(files) >= max_files:
                    truncated = True
                    break
                _record_path(files, path, errors)
        if truncated:
            record_error(
                "filesystem",
                f"stopped at {len(files)} files or the timeout",
                "the filesystem picture is partial; missing paths are not safe paths",
            )
            break

    services, jobs = _scheduled(files, unresolved, record_error, remaining)
    systemd_coverage = "partial" if services else "not_in_scope"
    if runtime_systemd:
        observed, systemd_coverage = runtime.services(remaining, record_error, max_services)
        by_name = {service["name"]: service for service in services}
        by_name.update({service["name"]: service for service in observed})
        services = list(by_name.values())
    containers, docker_coverage = runtime.containers(remaining, record_error, max_containers) if docker else ([], "not_in_scope")
    dependency_paths = []
    for service in services:
        dependency_paths += service.get("absolute_paths") or []
        dependency_paths += [service.get("fragment_path")] + (service.get("drop_in_paths") or [])
    for job in jobs:
        dependency_paths += job.get("absolute_paths") or []
    for container in containers:
        dependency_paths += [m["source"] for m in container.get("mounts") or [] if m.get("type") == "bind"]
    for path in sorted(set(p for p in dependency_paths if p and p.startswith("/"))):
        if path in files or _excluded(path, exclusions):
            continue
        if remaining() <= 0 or len(files) >= max_files:
            truncated = True
            record_error("filesystem", "dependency metadata bound reached", "remaining referenced resources are unknown")
            break
        _record_path(files, path, errors)
    _add_ancestors(files, errors)
    if getfacl:
        for path, info in list(files.items()):
            if remaining() <= 0:
                acl_failed += 1
                break
            if info.get("metadata_collected") is False or info.get("type") == "symlink":
                continue
            acl_attempted += 1
            try:
                result = subprocess.run(
                    [getfacl, "-n", "-p", path],
                    capture_output=True,
                    text=True,
                    timeout=max(1, min(5, remaining())),
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                acl_failed += 1
                record_error("acls", f"getfacl failed for {path}: {exc.__class__.__name__}",
                             "ACL rights for this path are unknown")
                continue
            if result.returncode != 0:
                acl_failed += 1
                continue
            parsed = parse_getfacl(result.stdout)
            if parsed:
                info["acl"] = parsed
                info["acl_collected"] = True
            else:
                acl_failed += 1
    else:
        record_error("acls", "getfacl is not available",
                     "named-user and mask ACLs were not collected and must not be treated as absent")

    accounts, groups, group_coverage = _identities(record_error)
    sudo_rules, sudo_coverage = _sudo(files, unresolved, record_error, remaining)
    mounts, mount_coverage = _mounts(record_error, remaining)
    capability_coverage = _capabilities(files, record_error, remaining)
    if probe_current_user:
        _probe_self(files, mounts, record_error)

    acl_candidates = sum(1 for info in files.values() if info.get("metadata_collected") is not False and info.get("type") != "symlink")
    if acl_attempted < acl_candidates:
        acl_failed += 1
    coverage = {
        "users": "partial" if any(e["component"] == "users" for e in errors) else "complete" if accounts else "unavailable",
        "groups": group_coverage,
        "filesystem": "partial" if truncated or exclusions or any(item["component"] == "filesystem" for item in errors) else "complete",
        "acls": "unavailable" if not getfacl else ("partial" if acl_failed else "complete"),
        "sudo": sudo_coverage,
        "systemd": systemd_coverage,
        "cron": "partial" if jobs or any("cron" in path for path in files) else "not_in_scope",
        "capabilities": capability_coverage,
        "docker": docker_coverage,
        "mounts": mount_coverage,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "linuxhound-snapshot",
        "host": {"id": host_id, "hostname": hostname or _hostname()},
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "collector": {"running_as_root": os.geteuid() == 0, "euid": os.geteuid()},
        "scope": {
            "roots": roots,
            "exclusions": exclusions,
            "max_files": max_files,
            "max_depth": max_depth,
            "timeout_seconds": timeout,
            "truncated": truncated,
            "docker_api_queried": docker,
            "runtime_systemd_queried": runtime_systemd,
            "dependency_paths": sorted(set(p for p in dependency_paths if p)),
            "max_services": max_services,
            "max_containers": max_containers,
            "secret_contents_read": False,
        },
        "coverage": coverage,
        "errors": errors,
        "unresolved": unresolved,
        "designated_admins": list(designated_admins or []),
        "accounts": accounts,
        "groups": groups,
        "files": list(files.values()),
        "mounts": mounts,
        "sudo_rules": sudo_rules,
        "services": services,
        "jobs": jobs,
        "containers": containers,
        "validation_evidence": [],
    }


def _record_path(files: dict[str, dict], path: str, errors: list[dict]) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        errors.append({
            "component": "filesystem",
            "message": f"could not stat {path}: {exc.__class__.__name__}",
            "impact": "this path has no metadata; that is not a clean finding",
        })
        files[path] = {"path": path, "metadata_collected": False, "type": "unknown"}
        return
    kind = "file"
    if stat.S_ISDIR(info.st_mode):
        kind = "dir"
    elif stat.S_ISLNK(info.st_mode):
        kind = "symlink"
    elif stat.S_ISSOCK(info.st_mode):
        kind = "socket"
    record = {
        "path": path,
        "type": kind,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "metadata_collected": True,
        "capabilities": [],
    }
    if kind == "symlink":
        try:
            record["symlink_target"] = os.readlink(path)
        except OSError:
            record["symlink_target"] = None
    files[path] = record


def _add_ancestors(files: dict[str, dict], errors: list[dict]) -> None:
    needed = []
    for path in list(files):
        current = path
        while current != "/":
            parent = os.path.dirname(current.rstrip("/")) or "/"
            if parent == current:
                break
            if parent not in files:
                needed.append(parent)
            current = parent
    for path in needed:
        _record_path(files, path, errors)


def _identities(record_error) -> tuple[list[dict], list[dict], str]:
    try:
        import grp
        import pwd
    except ImportError:
        record_error("users", "pwd/grp are unavailable", "accounts were not collected")
        return [], [], "unavailable"
    groups = []
    group_gap = False
    try:
        for group in grp.getgrall():
            groups.append({"name": group.gr_name, "gid": group.gr_gid, "members": list(group.gr_mem)})
    except OSError as exc:
        group_gap = True
        record_error("groups", exc.__class__.__name__, "group membership may be incomplete")
    by_gid = {group["gid"]: group for group in groups}
    accounts = []
    try:
        for account in pwd.getpwall():
            try:
                extra = list(os.getgrouplist(account.pw_name, account.pw_gid))
            except (OSError, OverflowError):
                extra = [account.pw_gid]
                group_gap = True
            for gid in extra:
                group = by_gid.get(gid)
                if group and account.pw_name not in group["members"]:
                    group["members"].append(account.pw_name)
            accounts.append({
                "name": account.pw_name,
                "uid": account.pw_uid,
                "gid": account.pw_gid,
                "gids": sorted(set(extra)),
                "shell": account.pw_shell,
                "password_status": "not_collected",
            })
    except OSError as exc:
        record_error("users", exc.__class__.__name__, "the account list is incomplete")
        return accounts, groups, "partial"
    if group_gap:
        record_error(
            "groups",
            "supplementary groups could not be read for every account",
            "rights that depend on those groups are incomplete and are not evidence of safety",
        )
        return accounts, groups, "partial" if accounts else "unavailable"
    if not groups and not accounts:
        return accounts, groups, "unavailable"
    return accounts, groups, "complete"


def _sudo(files, unresolved, record_error, remaining) -> tuple[list[dict], str]:
    rules: list[dict] = []
    saw = False
    for path, info in files.items():
        if info.get("type") != "file":
            continue
        name = Path(path).name
        in_policy = name == "sudoers" or "sudoers.d" in path
        if not in_policy:
            continue
        lowered = name.lower()
        if lowered in NEVER_READ_NAMES or any(lowered.endswith(suffix) for suffix in NEVER_READ_SUFFIXES):
            continue
        saw = True
        try:
            if remaining() <= 0:
                break
            text = _bounded_config(path)
        except OSError as exc:
            record_error("sudo", f"could not read {path}: {exc.__class__.__name__}",
                         "unreadable sudo policy is not evidence of no sudo rights")
            continue
        if len(text) > 1_000_000:
            record_error("sudo", f"{path} exceeds the read bound", "that sudoers file was skipped")
            continue
        parsed, pending = parse_sudoers(text, path)
        rules.extend(parsed)
        unresolved.extend(pending)
    if not saw:
        record_error("sudo", "no sudoers file was inside the collection roots",
                     "sudo coverage is outside this scope and is not a finding of no sudo access")
        return [], "not_in_scope"
    return rules, "partial"


def _scheduled(files, unresolved, record_error, remaining):
    services = []
    jobs = []
    for path, info in list(files.items()):
        if info.get("type") != "file":
            continue
        name = Path(path).name
        if remaining() <= 0:
            record_error("systemd", "configuration deadline reached", "remaining definitions were not parsed")
            break
        if not _readable_config(path, name):
            continue
        try:
            if info.get("mode") is not None and os.path.getsize(path) > 1_000_000:
                record_error("filesystem", f"{path} exceeds the config read bound", "its text was not parsed")
                continue
            text = _bounded_config(path)
        except OSError as exc:
            record_error("filesystem", f"could not read config {path}: {exc.__class__.__name__}",
                         "this scheduled definition was not collected")
            continue
        if name.endswith(".service") or name.endswith(".timer"):
            unit, pending = parse_unit(text, name, path)
            services.append(unit)
            if unit.get("resolution") != "absolute":
                unresolved.extend(pending)
        elif name in {"crontab"} or name.endswith(".crontab") or "/cron" in path.replace("\\", "/"):
            implied = Path(path).name if "/crontabs/" in path.replace("\\", "/") else None
            parsed, pending = parse_crontab(text, path, implied)
            jobs.extend(parsed)
            unresolved.extend(pending)
    return services, jobs


def _mounts(record_error, remaining):
    proc = Path("/proc/self/mountinfo")
    mounts_file = Path("/proc/mounts")
    try:
        if mounts_file.is_file():
            return parse_mounts(mounts_file.read_text(errors="replace"), "proc"), "complete"
    except OSError:
        pass
    mount_bin = shutil.which("mount")
    if not mount_bin or remaining() <= 0:
        record_error("mounts", "mount table was not readable",
                     "noexec, nosuid, and read-only restrictions are unknown")
        return None, "unavailable"
    try:
        result = subprocess.run([mount_bin], capture_output=True, text=True,
                                timeout=max(1, min(8, remaining())), check=False)
    except (OSError, subprocess.TimeoutExpired):
        record_error("mounts", "mount command failed", "mount restrictions are unknown")
        return None, "unavailable"
    if result.returncode != 0:
        record_error("mounts", "mount command returned non-zero", "mount restrictions are unknown")
        return None, "unavailable"
    return parse_mounts(result.stdout, "mount"), "complete"


def _capabilities(files, record_error, remaining) -> str:
    getcap = shutil.which("getcap")
    if not getcap:
        record_error("capabilities", "getcap is not available",
                     "file capabilities are unknown and are not treated as absent")
        return "unavailable"
    checked = 0
    candidates = 0
    for path, info in files.items():
        mode = int(info.get("mode") or 0)
        if info.get("type") != "file":
            continue
        if not (mode & 0o111 or mode & 0o4000):
            continue
        candidates += 1
        if checked >= 100 or remaining() <= 0:
            record_error("capabilities", "capability collection hit its bound",
                         "unchecked files may still have capabilities")
            return "partial"
        checked += 1
        try:
            result = subprocess.run([getcap, path], capture_output=True, text=True,
                                    timeout=max(1, min(4, remaining())), check=False)
        except (OSError, subprocess.TimeoutExpired):
            record_error("capabilities", "getcap failed", "capabilities are unresolved")
            return "partial"
        if result.returncode:
            record_error("capabilities", "getcap returned an error", "capabilities are unresolved")
            return "partial"
        if result.stdout.strip():
            info["capabilities"] = [part for part in result.stdout.strip().split() if part.startswith("cap_")]
    return "complete" if checked == candidates else "partial"


def _probe_self(files, mounts, record_error) -> None:
    from linuxhound.access import can_read
    uid = os.geteuid()
    gids = set(os.getgroups())
    checked = 0
    indexed = {info["path"]: info for info in files.values() if info.get("metadata_collected", True)}
    for path, info in indexed.items():
        if checked >= 200 or info.get("type") != "file":
            continue
        checked += 1
        try:
            actual = os.access(path, os.R_OK)
        except OSError:
            continue
        decision = can_read(indexed, mounts, uid, gids, path)
        if decision.state == "granted" and not actual:
            record_error("access-probe", f"model allows read of {path} but the current user cannot",
                         "LSM, NFS, or ignored mount state may be tighter than the model")
        if decision.state == "denied" and actual:
            record_error("access-probe", f"model denies read of {path} but the current user can read it",
                         "an ACL or capability may be missing from the collection")


def _readable_config(path: str, name: str) -> bool:
    lowered = name.lower()
    if lowered in NEVER_READ_NAMES or any(lowered.endswith(suffix) for suffix in NEVER_READ_SUFFIXES):
        return False
    if may_read_config_text(name):
        return True
    return any(path.startswith(root) for root in ("/etc/cron.d/", "/var/spool/cron/crontabs/"))


def _excluded(path: str, patterns: list[str]) -> bool:
    name = Path(path).name
    return any(fnmatch(path, pattern) or fnmatch(name, pattern) for pattern in patterns)


def _depth(root: str, path: str) -> int:
    relative = os.path.relpath(path, root)
    if relative == ".":
        return 0
    return relative.count(os.sep) + 1


def _hostname() -> str:
    try:
        return os.uname().nodename
    except AttributeError:
        return "localhost"


def _bounded_config(path: str) -> str:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1_000_000:
            raise OSError("configuration input outside bounds")
        data = handle.read(1_000_001)
        if len(data) > 1_000_000:
            raise OSError("configuration input outside bounds")
    return data.decode("utf-8", errors="replace")
