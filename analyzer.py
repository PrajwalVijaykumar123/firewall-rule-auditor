"""
The rule-set analysis engine: four checks that operate on a normalized
list of Rule objects (see rules.py), regardless of which parser produced
them. Firewalls evaluate rules top-to-bottom, first match wins - that
ordering is what makes shadowing possible and is central to two of these
four checks, not an afterthought.
"""
from dataclasses import dataclass
from typing import Optional

from rules import Rule, ANY_NET, RISKY_PORTS

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


@dataclass
class Finding:
    check: str
    severity: str
    message: str
    rule_name: str = ""

    def to_dict(self):
        return {"check": self.check, "severity": self.severity,
                "message": self.message, "rule_name": self.rule_name}


def _is_any(net) -> bool:
    return net == ANY_NET


def check_any_any_allow(rules: list[Rule]) -> list[Finding]:
    findings = []
    for r in rules:
        if not r.enabled or r.action != "accept":
            continue
        if _is_any(r.src) and _is_any(r.dst) and r.protocol == "any" and r.port is None:
            findings.append(Finding(
                "any_any_allow", "critical",
                f"Rule '{r.name}' allows ANY protocol from ANY source to ANY destination on "
                f"ANY port - this is equivalent to having no firewall at all for this chain/policy.",
                r.name,
            ))
    return findings


def check_risky_port_exposed(rules: list[Rule]) -> list[Finding]:
    findings = []
    for r in rules:
        if not r.enabled or r.action != "accept":
            continue
        if not _is_any(r.src):
            continue  # only flag when the source is unrestricted (internet-facing)
        if r.port is not None and r.port in RISKY_PORTS:
            service = RISKY_PORTS[r.port]
            findings.append(Finding(
                "risky_port_exposed", "high",
                f"Rule '{r.name}' exposes {service} (port {r.port}) to ANY source address - "
                f"management/database protocols like this should never accept connections "
                f"from the unrestricted internet.",
                r.name,
            ))
    return findings


def _rule_shadows(earlier: Rule, later: Rule) -> bool:
    """True if `earlier` fully covers every packet `later` would match -
    meaning `later` can never actually be reached, since `earlier` is
    evaluated first and firewalls stop at the first match."""
    if earlier.protocol != "any" and earlier.protocol != later.protocol:
        return False
    if earlier.port is not None and earlier.port != later.port:
        return False
    try:
        if not later.src.subnet_of(earlier.src):
            return False
        if not later.dst.subnet_of(earlier.dst):
            return False
    except TypeError:
        return False  # mixed IPv4/IPv6 - treat as non-overlapping, out of scope
    return True


def check_shadowed_rules(rules: list[Rule]) -> list[Finding]:
    findings = []
    enabled = [r for r in rules if r.enabled]
    for i, later in enumerate(enabled):
        for earlier in enabled[:i]:
            if _rule_shadows(earlier, later):
                if earlier.action == later.action:
                    findings.append(Finding(
                        "shadowed_rule", "low",
                        f"Rule '{later.name}' is redundant - earlier rule '{earlier.name}' "
                        f"already matches every packet it would match, with the same action. "
                        f"Safe to remove.",
                        later.name,
                    ))
                else:
                    findings.append(Finding(
                        "shadowed_rule", "high",
                        f"Rule '{later.name}' ({later.action}) can NEVER be reached - earlier "
                        f"rule '{earlier.name}' ({earlier.action}) already matches every packet "
                        f"it would match, and firewalls stop at the first match. This usually "
                        f"means the intended policy of '{later.name}' is silently not enforced.",
                        later.name,
                    ))
                break  # first (closest) shadowing rule is the meaningful one to report
    return findings


def check_missing_default_deny(rules: list[Rule], default_policies: Optional[dict] = None) -> list[Finding]:
    findings = []
    default_policies = default_policies or {}

    # iptables-style: an explicit chain default policy was supplied.
    # OUTPUT is intentionally excluded - an ACCEPT default on outbound
    # traffic is standard practice on most hosts (you control what you
    # originate); INPUT and FORWARD are the chains default-deny matters for.
    if default_policies:
        for chain, policy in default_policies.items():
            if chain not in ("INPUT", "FORWARD"):
                continue
            if policy.upper() == "ACCEPT":
                findings.append(Finding(
                    "missing_default_deny", "medium",
                    f"Chain '{chain}' has a default policy of ACCEPT - any traffic not matched "
                    f"by an earlier rule is allowed through. Default policy should be DROP, with "
                    f"explicit ACCEPT rules only for what's actually needed.",
                    chain,
                ))
        return findings

    # Generic policy list: no concept of a chain default - the convention
    # is an explicit catch-all deny rule at the end of the list instead.
    enabled = [r for r in rules if r.enabled]
    if not enabled:
        return findings
    last = enabled[-1]
    has_catchall_deny = (
        last.action in ("drop", "reject")
        and _is_any(last.src) and _is_any(last.dst)
        and last.protocol == "any" and last.port is None
    )
    if not has_catchall_deny:
        findings.append(Finding(
            "missing_default_deny", "medium",
            "The policy has no explicit catch-all deny rule at the end - depending on the "
            "platform's implicit default, unmatched traffic may be silently allowed. Add an "
            "explicit deny-any-any rule as the last rule in the policy.",
        ))
    return findings


def run_all(rules: list[Rule], default_policies: Optional[dict] = None) -> list[Finding]:
    findings = []
    findings += check_any_any_allow(rules)
    findings += check_risky_port_exposed(rules)
    findings += check_shadowed_rules(rules)
    findings += check_missing_default_deny(rules, default_policies)
    return findings
