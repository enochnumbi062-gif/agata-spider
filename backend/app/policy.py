"""Périmètre autorisé (fail-closed) + protection SSRF / DNS-rebinding."""
import ipaddress
import socket

from . import config


def normalize_target(target: str) -> str:
    t = target.strip().lower().rstrip(".")
    if not t or len(t) > 253 or any(c in t for c in "/\\@?#% \t\r\n"):
        raise ValueError("Target format rejected")
    return t


def target_is_allowed(target: str) -> bool:
    t = normalize_target(target)
    if t in config.ALLOWED_TARGETS:
        return True
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        return False
    for entry in config.ALLOWED_TARGETS:
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def resolve_pinned(target: str) -> list[str]:
    """Résout UNE fois ; rejette link-local (métadonnées cloud), multicast, réservé, non spécifié."""
    ips: list[str] = []
    for info in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM):
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise PermissionError("Resolved address is in a blocked range")
        if str(ip) not in ips:
            ips.append(str(ip))
    if not ips:
        raise ValueError("Target did not resolve")
    return ips


def validate_connect_check(target: str, ports: list[int], engagement_id: str, confirmed: bool) -> str:
    target = normalize_target(target)
    if config.MODE not in ("lab", "enterprise"):
        raise ValueError("Unknown deployment mode")
    if not config.ACTIVE_CHECKS:
        raise PermissionError("Active checks are disabled by policy")
    if not confirmed:
        raise PermissionError("Explicit authorization confirmation is required")
    if not engagement_id.strip():
        raise PermissionError("Engagement ID is required")
    if not target_is_allowed(target):
        raise PermissionError("Target is not in the configured allowlist")
    if not ports or len(ports) > 10:
        raise ValueError("Provide between 1 and 10 ports")
    if any(p not in config.ALLOWED_PORTS for p in ports):
        raise PermissionError("One or more ports are not in the approved port allowlist")
    return target
