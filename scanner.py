#!/usr/bin/env python3
"""
firewall-rule-auditor: audits a firewall rule set for the policy mistakes
that actually cause incidents - a wide-open any/any rule, a management
port exposed to the internet, a rule that's silently unreachable because
an earlier, broader rule already matches everything it would, and a
chain with no default-deny.

Usage:
    python3 scanner.py --iptables-save /path/to/iptables-save.txt
    python3 scanner.py --policy-json /path/to/policy.json
    python3 scanner.py --iptables-save rules.txt --json report.json --fail-on high
"""
import argparse
import json
import sys

from rules import parse_iptables_save, parse_generic_policy
from analyzer import run_all, SEVERITY_ORDER


def load_rules(args):
    if args.iptables_save:
        with open(args.iptables_save) as f:
            text = f.read()
        return parse_iptables_save(text)
    if args.policy_json:
        with open(args.policy_json) as f:
            data = json.load(f)
        return parse_generic_policy(data), {}
    print("error: provide --iptables-save <file> or --policy-json <file>", file=sys.stderr)
    sys.exit(2)


def severity_at_or_above(sev: str, threshold: str) -> bool:
    return SEVERITY_ORDER.index(sev) >= SEVERITY_ORDER.index(threshold)


def main():
    parser = argparse.ArgumentParser(description="Audit a firewall rule set for common policy mistakes.")
    parser.add_argument("--iptables-save", help="Path to an iptables-save formatted rule dump")
    parser.add_argument("--policy-json", help="Path to a generic policy-rule JSON file (FortiGate/Sophos-shaped)")
    parser.add_argument("--json", dest="json_out", help="Write the full findings list to this JSON file")
    parser.add_argument("--fail-on", choices=["any", "low", "medium", "high", "critical"], default="high",
                         help="Minimum severity that causes a non-zero exit code (default: high)")
    args = parser.parse_args()

    rules, default_policies = load_rules(args)
    findings = run_all(rules, default_policies)

    by_sev = {s: [f for f in findings if f.severity == s] for s in SEVERITY_ORDER}
    print(f"Firewall rule audit: {len(rules)} rules loaded, {len(findings)} findings\n")

    if not findings:
        print("No findings - no any/any-allow, risky exposed ports, shadowed rules, "
              "or missing default-deny detected.")
    else:
        for sev in reversed(SEVERITY_ORDER):
            for f in by_sev[sev]:
                print(f"  [{f.severity.upper()}] {f.check}")
                print(f"      {f.message}\n")

    if args.json_out:
        with open(args.json_out, "w") as out:
            json.dump([f.to_dict() for f in findings], out, indent=2)
        print(f"Wrote {len(findings)} findings to {args.json_out}")

    threshold = "low" if args.fail_on == "any" else args.fail_on
    failing = [f for f in findings if severity_at_or_above(f.severity, threshold)]
    sys.exit(1 if failing else 0)


if __name__ == "__main__":
    main()
