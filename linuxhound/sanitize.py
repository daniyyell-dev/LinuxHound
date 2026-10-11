from __future__ import annotations

import re

_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"authorization|credential|private[_-]?key)\b(\s*[=:]\s*|\s+)(\S+)"
)
_QUOTED = re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization|credential|private[_-]?key)\b(\s*[=:]\s*|\s+)(\"[^\"]*\"|'[^']*')")
_BEARER = re.compile(r"(?i)\bbearer\s+\S+")
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:]+:[^@\s/]+@")

NEVER_READ_NAMES = {
    "shadow",
    "gshadow",
    "shadow-",
    "gshadow-",
    "passwd-",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "authorized_keys",
    "known_hosts",
}
NEVER_READ_SUFFIXES = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".kdbx",
    ".env",
    ".json",
    ".yml",
    ".yaml",
    ".sqlite",
    ".db",
}
CONFIG_READ_NAMES = {"sudoers", "crontab"}
CONFIG_READ_SUFFIXES = {".service", ".timer", ".socket", ".mount", ".crontab"}


def redact(text: str) -> str:
    if not text:
        return text
    redacted = _QUOTED.sub(r"\1\2[redacted]", text)
    redacted = _BEARER.sub("Bearer [redacted]", redacted)
    redacted = _URL_USERINFO.sub(r"\1[redacted]@", redacted)
    redacted = _ASSIGNMENT.sub(r"\1\2[redacted]", redacted)
    return redacted


def may_read_config_text(name: str) -> bool:
    lowered = name.lower()
    if lowered in NEVER_READ_NAMES or name in NEVER_READ_NAMES:
        return False
    for suffix in NEVER_READ_SUFFIXES:
        if lowered.endswith(suffix):
            return False
    if name in CONFIG_READ_NAMES or lowered in CONFIG_READ_NAMES:
        return True
    return any(lowered.endswith(suffix) for suffix in CONFIG_READ_SUFFIXES)


def safe_argv(argv: list[str]) -> list[str]:
    result=[]
    hide_next=False
    for index, token in enumerate(argv):
        if hide_next:
            result.append("[argument omitted]");hide_next=False;continue
        if index==0:
            result.append(redact(token));continue
        if token.startswith("--"):
            name=token.split("=",1)[0]
            result.append(name+"=[argument omitted]" if "=" in token else name)
            hide_next="=" not in token
        elif token.startswith("-"):
            result.append("[option omitted]");hide_next=True
        elif token.startswith("/"):
            result.append(redact(token))
        else:
            result.append("[argument omitted]")
    return result
