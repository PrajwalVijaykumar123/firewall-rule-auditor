# Firewall Rule Auditor

Audits a firewall rule set for the four policy mistakes that actually cause real incidents - a wide-open any/any rule, a management or database port exposed to the internet, a rule that's silently unreachable because an earlier, broader rule already matches everything it would (firewalls evaluate top-to-bottom, first match wins), and a chain with no default-deny posture.

**Only audit rule sets you own or are authorized to assess.**

## What This Project Does

Parses two real input formats into one normalized rule model, then runs four checks against it:

- **`parse_iptables_save()`** — real `iptables-save`/`iptables-restore` syntax: chain default-policy headers (`:INPUT ACCEPT [0:0]`) and `-A` rule lines with real flags (`-p`, `-s`, `-d`, `--dport`, `-j`)
- **`parse_generic_policy()`** — a generic JSON schema (`{name, action, protocol, src, dst, port, enabled}`) that the field layout of vendor policy exports reduces to, once vendor-specific plumbing (zone/interface bindings, service objects) is flattened

The four checks:

| Check | What it catches |
|---|---|
| `any_any_allow` | An enabled ACCEPT rule matching any protocol, any source, any destination, any port — equivalent to no firewall at all |
| `risky_port_exposed` | An enabled ACCEPT rule opens a known management/database port (SSH, RDP, SMB, MySQL, MSSQL, PostgreSQL, Redis, MongoDB, Elasticsearch, VNC, FTP, Telnet) to **any** source |
| `shadowed_rule` | A rule that can never actually be reached because an earlier, broader rule already matches every packet it would — using real CIDR-containment logic (`ipaddress.subnet_of`), not a string comparison. Flagged **HIGH** when the shadowed rule's action differs from the one shadowing it (the intended policy is silently not enforced), **LOW** when it's just a redundant duplicate |
| `missing_default_deny` | For iptables input: the `INPUT`/`FORWARD` chain's default policy is `ACCEPT` rather than `DROP`. For generic policy lists (no chain-policy concept): no explicit catch-all deny rule at the end of the list |

## Why `shadowed_rule` Is the Interesting One

Any linter can flag an any/any/allow rule. Catching a rule that's *provably dead* because of ordering is a different kind of check — it needs to actually model rule precedence, not just inspect each rule in isolation. The engine walks each enabled rule against every rule that precedes it and asks: does the earlier rule's protocol, port, and source/destination network fully cover this one? If so, this rule is unreachable regardless of what it says, and if its action disagrees with the rule shadowing it, that's a live policy bug — someone added a specific DENY believing it would take effect, and it silently never will.

This is also exactly the kind of mistake Fortinet/Sophos policy lists accumulate over years of ad-hoc additions: a broad early ALLOW, followed much later by a narrower DENY someone added for a specific bad actor, that has never actually been enforced.

## No Vendor-Specific Adapter Included — By Design, Stated Honestly

This repo does not ship a FortiGate- or Sophos-specific export parser. Writing one needs real access to export a policy from one of those platforms to see the actual field names and JSON/XML shape, which this environment doesn't have. What it does ship is a detection engine that's deliberately format-agnostic: `parse_generic_policy()`'s docstring documents the normalized shape a FortiGate or Sophos policy rule reduces to, so adding real vendor support later is a small parsing function targeting that same shape — not a rewrite of the four checks above.

## Tech Stack

- Python 3.11, standard library only (`ipaddress`, `re`, `dataclasses`, `argparse`) — no third-party dependencies

## Setup

```bash
python3 scanner.py --iptables-save /path/to/iptables-save-dump.txt
python3 scanner.py --policy-json /path/to/policy.json
python3 scanner.py --iptables-save rules.txt --json report.json --fail-on high
```

Getting a real iptables-save dump to audit: `iptables-save > rules.txt` on a Linux host with the rules loaded, or `sudo iptables-save` if not run as root.

## Testing

`test_fixtures/` has four real fixture files — a compliant and a deliberately broken rule set for *each* input format (iptables-save and generic JSON) — built to exercise every one of the four checks in both directions. `run_test.sh` runs the real scanner against all four and asserts specific findings by check name and rule name, plus exit codes:

```bash
sh test_fixtures/run_test.sh
```

20 assertions, all passing — both compliant fixtures produce **zero** findings and exit 0; both noncompliant fixtures trigger every applicable check (critical any/any-allow, high risky-port exposure, high and low shadowed-rule cases, and missing-default-deny) and exit 1.

Sample run against the noncompliant iptables fixture:

```
Firewall rule audit: 4 rules loaded, 7 findings

  [CRITICAL] any_any_allow
      Rule 'rule#1' allows ANY protocol from ANY source to ANY destination on ANY port - this is equivalent to having no firewall at all for this chain/policy.

  [HIGH] risky_port_exposed
      Rule 'rule#2' exposes SSH (port 22) to ANY source address - management/database protocols like this should never accept connections from the unrestricted internet.

  [HIGH] shadowed_rule
      Rule 'rule#4' (drop) can NEVER be reached - earlier rule 'rule#1' (accept) already matches every packet it would match, and firewalls stop at the first match. This usually means the intended policy of 'rule#4' is silently not enforced.

  [MEDIUM] missing_default_deny
      Chain 'INPUT' has a default policy of ACCEPT - any traffic not matched by an earlier rule is allowed through. Default policy should be DROP, with explicit ACCEPT rules only for what's actually needed.
  ...
```

Every line above is real scanner output against a real fixture file, not hand-written example text.

## Architecture

```
scanner.py (CLI: picks a parser, runs the engine, formats output, --fail-on exit codes)
        |
        v
rules.py: Rule dataclass + two parsers -> normalized list[Rule] + default_policies
        |
        v
analyzer.py: 4 checks, each operating purely on the normalized model
  - any_any_allow, risky_port_exposed: single-rule checks
  - shadowed_rule: pairwise CIDR-containment + protocol/port containment
  - missing_default_deny: chain-policy dict OR trailing-catchall-rule check
        |
        v
Console report (grouped by severity) + optional JSON; exit code reflects --fail-on
```

## Project Structure

```
firewall-rule-auditor/
├── scanner.py                           # CLI
├── rules.py                              # Rule model + iptables-save / generic-JSON parsers
├── analyzer.py                           # The 4 checks
└── test_fixtures/
    ├── compliant_iptables.save         # Real iptables-save syntax, passes every check
    ├── noncompliant_iptables.save      # Deliberately fails any/any, risky-port, shadow, default-deny
    ├── compliant_policy.json            # Generic-schema equivalent, passes every check
    ├── noncompliant_policy.json        # Generic-schema equivalent, deliberately broken
    └── run_test.sh                        # Runs scanner.py against all four, asserts findings + exit codes
```

## What I Learned

- Modeling rule *precedence*, not just individual rules, is what turns a basic linter into something closer to real security review — the `shadowed_rule` check needed the engine to reason about an ordered list, not treat each rule independently, which is a meaningfully different design than every single-rule check in this portfolio so far.
- `ipaddress.subnet_of()` does the actual CIDR-containment math so the shadowing check is correct for real subnet relationships (`10.0.0.0/8` contains `10.1.2.0/24`) rather than an approximation based on string prefixes or exact-match comparisons.
- Separating "no vendor adapter exists yet" from "the detection logic is vendor-agnostic" mattered for being honest about scope: the four checks here are the actual security-relevant logic a FortiGate/Sophos version would reuse unchanged, and documenting the normalized shape those platforms' exports reduce to is a concrete, truthful step toward that — not a claim that Fortinet/Sophos integration already works.
- Excluding the `OUTPUT` chain from the missing-default-deny check was a deliberate correction after testing against a realistic rule set: an `ACCEPT` default on outbound traffic is standard practice on most hosts (you control what you originate), and flagging it would have been noise that undermines trust in the other findings.

## Next Steps

- A real FortiGate or Sophos XG export adapter, once access to a real export sample exists to parse against (not fabricated test data).
- Extend the shadowing check to also flag *partial* overlap (two rules that overlap but neither fully contains the other) as a lower-severity "overlapping rules — review ordering" finding.
- A `--diff` mode comparing two rule-set snapshots over time, to catch configuration drift the way `detection-as-code`'s CI pattern catches detection-rule drift.
- Direct ingestion from a live `iptables-save` pipe (`python3 scanner.py --iptables-save -` reading stdin) for use in a scheduled host-fleet audit.
