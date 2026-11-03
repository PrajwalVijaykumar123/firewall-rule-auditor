"""
A normalized firewall Rule model, plus parsers for two real input formats:

- iptables-save syntax (the real format `iptables-save`/`iptables-restore`
  use - chain policy lines and -A rule lines with real flags: -p, -s, -d,
  --dport, --sport, -j).
- A generic JSON policy-rule schema that the field layout of vendor
  firewall policy exports (FortiGate, Sophos XG/Firewall) reduces to:
  an ordered list of {name, action, protocol, src, dst, port, enabled}
  objects. This repo does not include a FortiGate/Sophos-specific
  adapter (that needs real access to export from one, which this
  environment doesn't have) - but the engine underneath is format-
  agnostic specifically so that writing one is a small parsing function,
  not a rewrite of the detection logic.
"""
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional


ANY_NET = ipaddress.ip_network("0.0.0.0/0")

RISKY_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
}


@dataclass
class Rule:
    order: int
    action: str                  # "accept" | "drop" | "reject"
    protocol: str                 # "tcp" | "udp" | "icmp" | "any"
    src: ipaddress._BaseNetwork
    dst: ipaddress._BaseNetwork
    port: Optional[int]           # None means "any port"
    name: str = ""
    enabled: bool = True
    raw: str = ""


def _parse_net(value) -> ipaddress._BaseNetwork:
    if value is None:
        return ANY_NET
    value = str(value).strip()
    if value.lower() in ("any", "all", "0.0.0.0/0", "*"):
        return ANY_NET
    if "/" not in value:
        value = value + "/32"
    return ipaddress.ip_network(value, strict=False)


def _normalize_action(action: str) -> str:
    action = action.strip().lower()
    if action in ("accept", "allow", "permit"):
        return "accept"
    if action in ("drop", "deny"):
        return "drop"
    if action in ("reject",):
        return "reject"
    raise ValueError(f"Unrecognized action: {action}")


# ------------------------------------------------------------ iptables-save

_DPORT_RE = re.compile(r"--dport\s+(\d+)")
_SRC_RE = re.compile(r"-s\s+(\S+)")
_DST_RE = re.compile(r"-d\s+(\S+)")
_PROTO_RE = re.compile(r"-p\s+(\S+)")
_JUMP_RE = re.compile(r"-j\s+(\S+)")


def parse_iptables_save(text: str):
    """
    Returns (rules, default_policies) where default_policies maps
    chain name -> policy ("ACCEPT"/"DROP") from the ':CHAIN POLICY [...]'
    header lines.
    """
    rules = []
    default_policies = {}
    order = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("*") or line == "COMMIT":
            continue
        if line.startswith(":"):
            parts = line[1:].split()
            if len(parts) >= 2:
                default_policies[parts[0]] = parts[1]
            continue
        if not line.startswith("-A"):
            continue

        jump = _JUMP_RE.search(line)
        if not jump or jump.group(1) not in ("ACCEPT", "DROP", "REJECT"):
            continue  # rule jumps to a custom chain or logs - out of scope for this engine

        proto_m = _PROTO_RE.search(line)
        protocol = proto_m.group(1).lower() if proto_m else "any"

        src_m = _SRC_RE.search(line)
        src = _parse_net(src_m.group(1) if src_m else None)

        dst_m = _DST_RE.search(line)
        dst = _parse_net(dst_m.group(1) if dst_m else None)

        dport_m = _DPORT_RE.search(line)
        port = int(dport_m.group(1)) if dport_m else None

        order += 1
        rules.append(Rule(
            order=order,
            action=_normalize_action(jump.group(1)),
            protocol=protocol,
            src=src,
            dst=dst,
            port=port,
            name=f"rule#{order}",
            raw=line,
        ))
    return rules, default_policies


# --------------------------------------------------------------- generic JSON

def parse_generic_policy(policy_list: list):
    """
    policy_list: list of dicts shaped like
        {"name": str, "action": "allow"|"deny", "protocol": "tcp"|"udp"|"any",
         "src": "10.0.0.0/8"|"any", "dst": "any", "port": 22|"any", "enabled": true}
    which is the common shape a FortiGate or Sophos policy rule reduces to
    once vendor-specific field names (srcintf/dstintf, service objects,
    etc.) are flattened - a vendor adapter would translate into this
    shape and call this same parser.
    """
    rules = []
    for i, item in enumerate(policy_list, start=1):
        port = item.get("port")
        port = None if port is None or str(port).lower() == "any" else int(port)
        rules.append(Rule(
            order=i,
            action=_normalize_action(item["action"]),
            protocol=str(item.get("protocol", "any")).lower(),
            src=_parse_net(item.get("src")),
            dst=_parse_net(item.get("dst")),
            port=port,
            name=item.get("name", f"rule#{i}"),
            enabled=bool(item.get("enabled", True)),
            raw=str(item),
        ))
    return rules
