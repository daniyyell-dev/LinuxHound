from __future__ import annotations

import posixpath
from dataclasses import dataclass, field


R = 4
W = 2
X = 1


@dataclass
class Decision:
    state: str
    reason: str
    assumptions: list[str] = field(default_factory=list)
    blocked_by: str | None = None
    mount_flags: list[str] = field(default_factory=list)

    @property
    def granted(self) -> bool:
        return self.state == "granted"

    @property
    def classification(self) -> str:
        if not self.granted:
            return "not_applicable"
        if self.assumptions:
            return "conditional"
        return "observed_permission"


def ancestor_paths(path: str) -> list[str]:
    if path == "/":
        return []
    parts = [part for part in path.split("/") if part]
    ancestors = ["/"]
    current = ""
    for part in parts[:-1]:
        current += "/" + part
        ancestors.append(current)
    return ancestors


def parent_path(path: str) -> str | None:
    if path == "/":
        return None
    parent = posixpath.dirname(path.rstrip("/"))
    return parent if parent else "/"


def normalize_path(path: str) -> str:
    if not path.startswith("/"):
        raise ValueError("paths must be absolute")
    normalized = posixpath.normpath(path)
    return "/" if normalized == "." else normalized


def mount_for(mounts: list[dict] | None, path: str) -> dict | None:
    if not mounts:
        return None
    best: dict | None = None
    for mount in mounts:
        mount_path = mount.get("path") or "/"
        if path == mount_path or path.startswith(mount_path.rstrip("/") + "/") or mount_path == "/":
            if best is None or len(str(mount_path)) > len(str(best.get("path") or "")):
                best = mount
    return best


def _perm(mode: int, shift: int) -> int:
    return (mode >> shift) & 7


def _acl_mask(acl: dict, mode: int) -> int:
    if acl.get("mask") is not None:
        return int(acl["mask"]) & 7
    if acl.get("users") or acl.get("groups"):
        return _perm(mode, 3)
    return 7


def _any_execute(mode: int, acl: dict | None) -> bool:
    if mode & 0o111:
        return True
    if not acl:
        return False
    values = [acl.get("user_obj", 0), acl.get("group_obj", 0), acl.get("other", 0)]
    values.extend((acl.get("users") or {}).values())
    values.extend((acl.get("groups") or {}).values())
    if acl.get("mask") is not None:
        values.append(acl["mask"])
    return any(int(value) & X for value in values)


def effective_bits(file_info: dict, uid: int, gids: set[int]) -> int | None:
    if file_info.get("metadata_collected") is False:
        return None
    mode = int(file_info["mode"])
    acl = file_info.get("acl")
    file_uid = int(file_info["uid"])
    file_gid = int(file_info["gid"])
    is_dir = file_info.get("type") == "dir"
    if uid == 0:
        bits = R | W
        if is_dir or _any_execute(mode, acl):
            bits |= X
        return bits
    if acl:
        mask = _acl_mask(acl, mode)
        if uid == file_uid:
            return int(acl.get("user_obj", _perm(mode, 6))) & 7
        named = (acl.get("users") or {}).get(str(uid))
        if named is None:
            named = (acl.get("users") or {}).get(uid)
        if named is not None:
            return int(named) & mask
        group_bits = 0
        matched = False
        if file_gid in gids:
            group_bits |= int(acl.get("group_obj", _perm(mode, 3)))
            matched = True
        for gid, bits in (acl.get("groups") or {}).items():
            if int(gid) in gids:
                group_bits |= int(bits)
                matched = True
        if matched:
            return group_bits & mask
        return int(acl.get("other", mode & 7)) & 7
    if uid == file_uid:
        return _perm(mode, 6)
    if file_gid in gids:
        return _perm(mode, 3)
    return mode & 7


def _resolve_follow(files: dict[str, dict], path: str, depth: int = 0) -> tuple[str | None, str | None]:
    if depth > 8:
        return None, "symlink loop or chain longer than 8"
    info = files.get(path)
    if info is None:
        return None, f"{path} was not collected"
    if info.get("type") != "symlink":
        return path, None
    target = info.get("symlink_target")
    if not target:
        return None, f"{path} is a symlink with no recorded target"
    if target.startswith("/"):
        resolved = normalize_path(target)
    else:
        resolved = normalize_path(posixpath.join(posixpath.dirname(path), target))
    return _resolve_follow(files, resolved, depth + 1)


def _mount_assumption(mount: dict | None) -> list[str]:
    if mount is None:
        return ["mount flags were not collected; ro, noexec, or nosuid could change this result"]
    fstype = str(mount.get("fstype") or "")
    if fstype in {"nfs", "nfs4"}:
        return [f"filesystem type {fstype} may apply root squash or server-side ACL checks that this model does not evaluate"]
    return []


def _flags(mount: dict | None) -> list[str]:
    if not mount:
        return []
    return list(mount.get("flags") or [])


def traverse_directory(
    files: dict[str, dict],
    mounts: list[dict] | None,
    uid: int,
    gids: set[int],
    directory: str,
) -> Decision:
    resolved, error = _resolve_follow(files, directory)
    if error:
        return Decision("unresolved", error)
    info = files[resolved]
    if info.get("type") not in {"dir", "symlink"}:
        return Decision("denied", f"{resolved} is not a directory", blocked_by=resolved)
    bits = effective_bits(info, uid, gids)
    if bits is None:
        return Decision("unresolved", f"metadata for {resolved} was not collected")
    mount = mount_for(mounts, resolved)
    assumptions = _mount_assumption(mount)
    if uid == 0 and assumptions:
        return Decision("unresolved", assumptions[0], assumptions=assumptions, mount_flags=_flags(mount))
    if bits & X:
        return Decision(
            "granted",
            f"execute bit grants traversal of {resolved}",
            assumptions=assumptions,
            mount_flags=_flags(mount),
        )
    return Decision("denied", f"missing execute (traversal) permission on {resolved}", blocked_by=resolved)


def ancestors_allow(
    files: dict[str, dict],
    mounts: list[dict] | None,
    uid: int,
    gids: set[int],
    path: str,
) -> Decision:
    assumptions: list[str] = []
    flags: list[str] = []
    for ancestor in ancestor_paths(path):
        decision = traverse_directory(files, mounts, uid, gids, ancestor)
        assumptions.extend(decision.assumptions)
        flags = decision.mount_flags or flags
        if decision.state != "granted":
            return Decision(decision.state, decision.reason, assumptions, decision.blocked_by, flags)
    return Decision("granted", "every collected ancestor grants traversal", assumptions, None, flags)


def _content_right(
    files: dict[str, dict],
    mounts: list[dict] | None,
    uid: int,
    gids: set[int],
    path: str,
    bit: int,
    label: str,
) -> Decision:
    walk = ancestors_allow(files, mounts, uid, gids, path)
    if walk.state != "granted":
        return walk
    resolved, error = _resolve_follow(files, path)
    if error:
        return Decision("unresolved", error, walk.assumptions)
    if resolved != path:
        target_walk = ancestors_allow(files, mounts, uid, gids, resolved)
        if target_walk.state != "granted":
            return target_walk
        walk.assumptions.extend(target_walk.assumptions)
    info = files[resolved]
    if info.get("type") == "dir":
        return Decision("denied", f"{resolved} is a directory; {label} applies to files", blocked_by=resolved)
    bits = effective_bits(info, uid, gids)
    if bits is None:
        return Decision("unresolved", f"metadata for {resolved} was not collected", walk.assumptions)
    mount = mount_for(mounts, resolved)
    assumptions = list(walk.assumptions) + _mount_assumption(mount)
    flags = _flags(mount)
    if uid == 0 and any("nfs" in item for item in assumptions):
        return Decision("unresolved", assumptions[-1], assumptions, None, flags)
    if not bits & bit:
        return Decision("denied", f"mode or ACL does not grant {label} on {resolved}", assumptions, resolved, flags)
    if bit == W and "ro" in flags:
        return Decision("denied", f"{resolved} is on a read-only mount", assumptions, resolved, flags)
    if bit == X and "noexec" in flags:
        return Decision("denied", f"{resolved} is on a noexec mount", assumptions, resolved, flags)
    if bit == W and mount is None:
        return Decision(
            "granted",
            f"{label} is allowed by DAC on {resolved}",
            assumptions,
            None,
            flags,
        )
    if bit == X and mount is None:
        return Decision(
            "granted",
            f"{label} is allowed by DAC on {resolved}",
            assumptions,
            None,
            flags,
        )
    return Decision("granted", f"{label} is allowed on {resolved}", assumptions, None, flags)


def can_read(files, mounts, uid, gids, path) -> Decision:
    return _content_right(files, mounts, uid, gids, path, R, "read")


def can_write_content(files, mounts, uid, gids, path) -> Decision:
    return _content_right(files, mounts, uid, gids, path, W, "write")


def can_execute(files, mounts, uid, gids, path) -> Decision:
    return _content_right(files, mounts, uid, gids, path, X, "execute")


def _directory_bits(files, mounts, uid, gids, directory: str) -> tuple[Decision, dict | None, int | None]:
    walk = ancestors_allow(files, mounts, uid, gids, directory)
    if walk.state != "granted":
        return walk, None, None
    resolved, error = _resolve_follow(files, directory)
    if error:
        return Decision("unresolved", error, walk.assumptions), None, None
    info = files[resolved]
    if info.get("type") != "dir":
        return Decision("denied", f"{resolved} is not a directory", walk.assumptions, resolved), None, None
    bits = effective_bits(info, uid, gids)
    if bits is None:
        return Decision("unresolved", f"metadata for {resolved} was not collected"), None, None
    return walk, info, bits


def can_traverse(files, mounts, uid, gids, directory: str) -> Decision:
    walk, info, bits = _directory_bits(files, mounts, uid, gids, directory)
    if info is None or bits is None:
        return walk
    mount = mount_for(mounts, info["path"] if "path" in info else directory)
    assumptions = list(walk.assumptions) + _mount_assumption(mount)
    if bits & X:
        return Decision("granted", f"traversal allowed on {directory}", assumptions, None, _flags(mount))
    return Decision("denied", f"missing execute permission on {directory}", assumptions, directory, _flags(mount))


def can_list(files, mounts, uid, gids, directory: str) -> Decision:
    walk, info, bits = _directory_bits(files, mounts, uid, gids, directory)
    if info is None or bits is None:
        return walk
    mount = mount_for(mounts, directory)
    assumptions = list(walk.assumptions) + _mount_assumption(mount)
    if (bits & R) and (bits & X):
        return Decision("granted", f"listing allowed on {directory}", assumptions, None, _flags(mount))
    return Decision(
        "denied",
        f"listing requires read and execute on {directory}",
        assumptions,
        directory,
        _flags(mount),
    )


def can_create(files, mounts, uid, gids, directory: str) -> Decision:
    walk, info, bits = _directory_bits(files, mounts, uid, gids, directory)
    if info is None or bits is None:
        return walk
    mount = mount_for(mounts, directory)
    flags = _flags(mount)
    assumptions = list(walk.assumptions) + _mount_assumption(mount)
    if "ro" in flags:
        return Decision("denied", f"{directory} is on a read-only mount", assumptions, directory, flags)
    if (bits & W) and (bits & X):
        state_assumptions = assumptions
        return Decision("granted", f"create allowed on {directory}", state_assumptions, None, flags)
    return Decision(
        "denied",
        f"creating an entry requires write and execute on {directory}",
        assumptions,
        directory,
        flags,
    )


def can_delete(files, mounts, uid, gids, child: str) -> Decision:
    parent = parent_path(child)
    if parent is None:
        return Decision("denied", "the root directory entry cannot be deleted here")
    created = can_create(files, mounts, uid, gids, parent)
    if created.state != "granted":
        return created
    parent_resolved, error = _resolve_follow(files, parent)
    if error:
        return Decision("unresolved", error, created.assumptions)
    parent_info = files[parent_resolved]
    child_info = files.get(child)
    if child_info is None:
        return Decision("unresolved", f"{child} was not collected", created.assumptions)
    sticky = int(parent_info["mode"]) & 0o1000
    if sticky and uid != 0 and uid != int(parent_info["uid"]) and uid != int(child_info["uid"]):
        return Decision(
            "denied",
            f"sticky bit on {parent} limits deletion to the owner of the entry or the directory",
            created.assumptions,
            parent,
            created.mount_flags,
        )
    return Decision(
        "granted",
        f"directory write allows deletion of {child}",
        created.assumptions,
        None,
        created.mount_flags,
    )


def can_replace(files, mounts, uid, gids, child: str) -> Decision:
    deleted = can_delete(files, mounts, uid, gids, child)
    if deleted.state != "granted":
        return deleted
    parent = parent_path(child)
    assert parent is not None
    created = can_create(files, mounts, uid, gids, parent)
    if created.state != "granted":
        return created
    assumptions = list(dict.fromkeys(deleted.assumptions + created.assumptions))
    return Decision(
        "granted",
        f"the parent directory allows replacing the entry {child}",
        assumptions,
        None,
        created.mount_flags or deleted.mount_flags,
    )


def suid_honored(file_info: dict, mounts: list[dict] | None) -> Decision:
    mode = int(file_info["mode"])
    if not mode & 0o4000:
        return Decision("denied", "setuid bit is not set")
    mount = mount_for(mounts, file_info["path"])
    assumptions = ["a setuid bit is not a vulnerability; the binary behavior was not executed or verified"]
    assumptions.extend(_mount_assumption(mount))
    flags = _flags(mount)
    if "nosuid" in flags:
        return Decision("denied", "mount nosuid prevents the setuid bit from taking effect", assumptions, file_info["path"], flags)
    if mount is None:
        return Decision("unresolved", "setuid bit is present but mount suid policy was not collected", assumptions, None, flags)
    return Decision("granted", "setuid bit would be honored by the recorded mount policy", assumptions, None, flags)
