from __future__ import annotations

import re
import shlex

from linuxhound.sanitize import redact, safe_argv

_SUDO_TAGS = {"NOPASSWD", "PASSWD", "SETENV", "NOSETENV", "LOG_INPUT", "LOG_OUTPUT", "EXEC", "NOEXEC"}


def parse_getfacl(text: str) -> dict | None:
    entries_user: dict[str, int] = {}
    entries_group: dict[str, int] = {}
    parsed: dict[str, int | dict | None] = {
        "user_obj": None,
        "group_obj": None,
        "other": None,
        "mask": None,
        "users": entries_user,
        "groups": entries_group,
    }
    saw = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        kind, name, perms = line.split(":", 2)
        bits = _rwx(perms)
        if bits is None:
            continue
        saw = True
        if kind == "user" and name == "":
            parsed["user_obj"] = bits
        elif kind == "user":
            entries_user[name] = bits
        elif kind == "group" and name == "":
            parsed["group_obj"] = bits
        elif kind == "group":
            entries_group[name] = bits
        elif kind == "mask":
            parsed["mask"] = bits
        elif kind == "other":
            parsed["other"] = bits
    if not saw or parsed["user_obj"] is None:
        return None
    return parsed


def _rwx(text: str) -> int | None:
    token = text.strip()
    if len(token) < 3:
        return None
    token = token[:3]
    if any(char not in "rwx-" for char in token):
        return None
    value = 0
    if token[0] == "r":
        value |= 4
    if token[1] == "w":
        value |= 2
    if token[2] == "x":
        value |= 1
    return value


def parse_sudoers(text: str, source: str) -> tuple[list[dict], list[dict]]:
    rules: list[dict] = []
    unresolved: list[dict] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith(("#include", "@include")):
            unresolved.append({"component": "sudo", "source": source, "message": "sudo include not expanded", "impact": "effective policy is partial"})
            continue
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("Defaults") or line.startswith("@include") or line.startswith("#include") or line.startswith("@includedir"):
            unresolved.append({
                "component": "sudo",
                "source": source,
                "message": f"unsupported sudoers construct at {source}:{line_no}",
                "impact": "rules from this construct were not expanded; their absence is not evidence of no sudo rights",
            })
            continue
        rule = _parse_sudo_rule(line, source, line_no)
        if rule is None:
            unresolved.append({
                "component": "sudo",
                "source": source,
                "message": f"unparsed sudoers line at {source}:{line_no}",
                "impact": "this line was not turned into a SudoAllows edge",
            })
            continue
        rules.append(rule)
    return rules, unresolved


def _parse_sudo_rule(line: str, source: str, line_no: int) -> dict | None:
    match = re.match(
        r"^(?P<principal>\S+)\s+\S+\s*=\s*(?:\((?P<runas>[^)]*)\))?\s*(?P<rest>.+)$",
        line,
    )
    if not match:
        return None
    principal = match.group("principal")
    source_type = "group" if principal.startswith("%") else "user"
    source_name = principal[1:] if source_type == "group" else principal
    runas = (match.group("runas") or "root").split(":")[0].strip() or "root"
    rest = match.group("rest").strip()
    tags: set[str] = set()
    while True:
        tag_match = re.match(r"^(NOPASSWD|PASSWD|SETENV|NOSETENV|LOG_INPUT|LOG_OUTPUT|EXEC|NOEXEC)\s*:\s*(.*)$", rest)
        if not tag_match or tag_match.group(1) not in _SUDO_TAGS:
            break
        tags.add(tag_match.group(1))
        rest = tag_match.group(2).strip()
    commands = [part.strip() for part in rest.split(",") if part.strip()]
    if not commands or any(command.startswith("!") or ":" in command for command in commands) or "," in principal or "," in runas:
        return None
    sanitized_commands = []
    for command in commands:
        try:
            sanitized_commands.append(" ".join(safe_argv(shlex.split(command))))
        except ValueError:
            return None
    return {
        "source_type": source_type,
        "source_name": source_name,
        "run_as_user": runas,
        "nopasswd": "NOPASSWD" in tags and "PASSWD" not in tags,
        "commands": sanitized_commands,
        "source_file": source,
        "line": line_no,
        "raw_sanitized": f"{principal} as {runas}: {', '.join(sanitized_commands)}",
        "host_restricted": "ALL" not in line.split("=", 1)[0],
    }


def parse_unit(text: str, name: str, source: str) -> tuple[dict, list[dict]]:
    section = ""
    values: dict[str, list[str]] = {"ExecStart": [], "ExecStartPre": [], "User": [], "Group": []}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section != "Service" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in values:
            values[key].append(value.strip())
    argv: list[str] = []
    for command in values["ExecStart"] + values["ExecStartPre"]:
        argv.extend(safe_argv(_split_command(command)))
    user = values["User"][-1] if values["User"] else None
    group = values["Group"][-1] if values["Group"] else None
    operands = [token for token in argv if token and not token.startswith("-")]
    absolute = [token for token in operands if token.startswith("/")]
    relative = [
        token for token in operands[1:]
        if not token.startswith("/") and "[redacted]" not in token and "[argument omitted]" not in token and "[option omitted]" not in token
    ] if operands and operands[0].startswith("/") else []
    unresolved = []
    if not operands or not operands[0].startswith("/"):
        resolution = "unresolved"
        absolute = []
        unresolved.append({
            "component": "systemd",
            "source": source,
            "message": f"{name} has a relative or empty executable path",
            "impact": "no Invokes edge was bound to a specific file; PATH and interpreter behavior stay unresolved",
        })
    else:
        resolution = "absolute"
        if relative:
            unresolved.append({
                "component": "systemd",
                "source": source,
                "message": f"{name} has relative arguments that were not bound to files",
                "impact": "only absolute command-line paths were connected; a similarly named writable file stays unconnected",
            })
    return {
        "name": name,
        "user": user,
        "user_defaulted": user is None,
        "group": group,
        "argv": argv,
        "absolute_paths": absolute if resolution == "absolute" else [],
        "resolution": resolution,
        "fragment_path": source,
        "sanitized_exec": " ".join(argv),
        "unit_kind": "timer" if name.endswith(".timer") else "service",
        "active_state": "unknown",
        "runtime_observed": False,
    }, unresolved


def parse_systemctl_exec(show_text: str) -> list[str]:
    argv: list[str] = []
    for match in re.finditer(r"argv\[\]=([^;}]*)", show_text):
        argv.extend(_split_command(match.group(1)))
    return argv


def parse_crontab(text: str, source: str, implied_user: str | None = None) -> tuple[list[dict], list[dict]]:
    jobs = []
    unresolved = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("@"):
            parts = line.split(None, 2 if implied_user is None else 1)
            if implied_user is None:
                if len(parts) < 3:
                    unresolved.append(_cron_unresolved(source, line_no))
                    continue
                user, command = parts[1], parts[2]
            else:
                if len(parts) < 2:
                    unresolved.append(_cron_unresolved(source, line_no))
                    continue
                user, command = implied_user, parts[1]
        else:
            parts = line.split()
            if implied_user is None:
                if len(parts) < 7:
                    unresolved.append(_cron_unresolved(source, line_no))
                    continue
                user = parts[5]
                command = " ".join(parts[6:])
            else:
                if len(parts) < 6:
                    unresolved.append(_cron_unresolved(source, line_no))
                    continue
                user = implied_user
                command = " ".join(parts[5:])
        tokens = safe_argv(_split_command(command))
        operands = [token for token in tokens if token and not token.startswith("-")]
        absolute = [token for token in operands if token.startswith("/")] if operands and operands[0].startswith("/") else []
        resolution = "absolute" if absolute else "unresolved"
        if resolution != "absolute":
            unresolved.append({
                "component": "cron",
                "source": source,
                "message": f"cron command at {source}:{line_no} is not an absolute invocation",
                "impact": "the command was not bound to a collected file; a writable script with a similar name is not treated as the target",
            })
        jobs.append({
            "name": f"{source}:{line_no}",
            "user": user,
            "argv": tokens,
            "absolute_paths": absolute,
            "resolution": resolution,
            "source": source,
            "sanitized_command": " ".join(tokens),
        })
    return jobs, unresolved


def _cron_unresolved(source: str, line_no: int) -> dict:
    return {
        "component": "cron",
        "source": source,
        "message": f"unparsed cron line at {source}:{line_no}",
        "impact": "this line produced no job node",
    }


def _split_command(command: str) -> list[str]:
    cleaned = command.strip()
    if cleaned.startswith("-"):
        cleaned = cleaned[1:].strip()
    try:
        import shlex
        return [token for token in shlex.split(cleaned, posix=True) if token]
    except ValueError:
        return cleaned.split()


def parse_mounts(text: str, style: str) -> list[dict]:
    mounts = []
    if style == "proc":
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            options = set(parts[3].split(","))
            flags = []
            if "ro" in options:
                flags.append("ro")
            else:
                flags.append("rw")
            for flag in ("nosuid", "noexec", "nodev"):
                if flag in options:
                    flags.append(flag)
            mounts.append({"path": _unescape(parts[1]), "fstype": parts[2], "flags": flags})
        return mounts
    for line in text.splitlines():
        match = re.search(r" on (.+?) \(([^)]*)\)", line)
        if not match:
            continue
        options = {item.strip() for item in match.group(2).split(",")}
        flags = ["ro" if "read-only" in options or "ro" in options else "rw"]
        for flag in ("nosuid", "noexec", "nodev"):
            if flag in options:
                flags.append(flag)
        mounts.append({"path": match.group(1), "fstype": "", "flags": flags})
    return mounts


def _unescape(path: str) -> str:
    return path.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
