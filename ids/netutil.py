"""Small network helpers: CIDR membership and traffic direction relative to the
networks the operator considers 'home'. Used to add context to alerts and to cut
external->external noise."""
from __future__ import annotations
import ipaddress
from typing import Optional


def parse_nets(cidrs):
    """Turn a list of CIDR strings into ip_network objects, skipping bad entries."""
    nets = []
    for c in cidrs or []:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    return nets


def in_net(ip: Optional[str], nets) -> bool:
    if not ip or not nets:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def direction(src: Optional[str], dst: Optional[str], nets) -> str:
    """inbound = to us, outbound = from us, internal = both ours, external = neither."""
    s, d = in_net(src, nets), in_net(dst, nets)
    if s and d:
        return "internal"
    if d:
        return "inbound"
    if s:
        return "outbound"
    return "external"
