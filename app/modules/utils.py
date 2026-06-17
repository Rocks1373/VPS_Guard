"""Shared helpers: safe subprocess execution and validation utilities."""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess

from app.modules.logger import get_logger

log = get_logger()

# Hostname per RFC 1123 (labels of letters/digits/hyphen, dot separated)
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def run_command(cmd: list[str], timeout: int = 60, check: bool = False) -> dict:
    """Run a command WITHOUT a shell (argument list only) and capture output.

    Returns a dict with ``rc``, ``stdout``, ``stderr`` and ``ok``. Using an
    argument list (never ``shell=True``) avoids shell-injection entirely.
    """
    if not cmd:
        return {"rc": -1, "stdout": "", "stderr": "empty command", "ok": False}
    binary = shutil.which(cmd[0]) or cmd[0]
    try:
        proc = subprocess.run(
            [binary] + cmd[1:],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )
        return {
            "rc": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "ok": proc.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        log.warning("Command timed out: %s", " ".join(cmd))
        return {"rc": -1, "stdout": "", "stderr": "timeout", "ok": False}
    except FileNotFoundError:
        return {"rc": -1, "stdout": "", "stderr": f"{cmd[0]} not found", "ok": False}
    except subprocess.CalledProcessError as exc:
        return {"rc": exc.returncode, "stdout": exc.stdout or "",
                "stderr": exc.stderr or str(exc), "ok": False}


def have_binary(name: str) -> bool:
    return shutil.which(name) is not None


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.match(value))


def is_valid_target(value: str) -> bool:
    """A scan target may be a single IP, a CIDR network, or a hostname."""
    if is_valid_ip(value) or is_valid_hostname(value):
        return True
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def target_in_scope(value: str, allowlist: list[str], denylist: list[str]) -> tuple[bool, str]:
    """Check a scan target against allow/deny CIDR lists.

    Returns ``(allowed, reason)``. Denylist always wins. An empty allowlist
    means "no allowlist restriction" (but config warns against this)."""
    # Resolve the candidate to a network for comparison where possible.
    def _matches(item: str, rule: str) -> bool:
        try:
            rule_net = ipaddress.ip_network(rule, strict=False)
        except ValueError:
            # rule is a hostname - compare literally
            return item == rule
        try:
            item_net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            return False
        return item_net.subnet_of(rule_net) or item_net == rule_net

    for rule in denylist or []:
        if value == rule or _matches(value, rule):
            return False, f"target matches denylist entry {rule}"

    if not allowlist:
        return True, "no allowlist configured"

    for rule in allowlist:
        if value == rule or _matches(value, rule):
            return True, f"target permitted by allowlist entry {rule}"
    return False, "target not in allowlist"
