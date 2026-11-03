#!/bin/sh
# Runs the real scanner.py against four real fixture files (two
# iptables-save dumps, two generic-policy JSON files - one compliant,
# one deliberately broken, per format) and asserts specific findings
# fire on the broken ones and don't fire on the clean ones.
set -e
cd "$(dirname "$0")/.."

OUT=/tmp/fwa_test_$$
mkdir -p "$OUT"

run() {
  label="$1"; shift
  python3 scanner.py "$@" --json "$OUT/$label.json" --fail-on any > "$OUT/$label.txt" 2>&1
  echo $? > "$OUT/$label.exit"
}

assert_exit() {
  label="$1"; expected="$2"
  actual=$(cat "$OUT/$label.exit")
  if [ "$actual" = "$expected" ]; then
    echo "PASS: $label exit code $actual"
  else
    echo "FAIL: $label expected exit $expected, got $actual"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1
  fi
}

assert_check_present() {
  label="$1"; check="$2"; rule_name="$3"
  python3 -c "
import json, sys
findings = json.load(open('$OUT/$label.json'))
match = [f for f in findings if f['check'] == '$check' and f.get('rule_name') == '$rule_name']
sys.exit(0 if match else 1)
" && echo "PASS: $label -> $check on '$rule_name' fired" \
  || { echo "FAIL: $label -> $check on '$rule_name' did not fire"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

assert_no_findings() {
  label="$1"
  python3 -c "
import json, sys
findings = json.load(open('$OUT/$label.json'))
sys.exit(0 if len(findings) == 0 else 1)
" && echo "PASS: $label produced zero findings" \
  || { echo "FAIL: $label expected zero findings"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

echo "== iptables-save: compliant fixture =="
set +e; run iptables_compliant --iptables-save test_fixtures/compliant_iptables.save; set -e
cat "$OUT/iptables_compliant.txt"
assert_exit iptables_compliant 0
assert_no_findings iptables_compliant

echo
echo "== iptables-save: noncompliant fixture =="
set +e; run iptables_noncompliant --iptables-save test_fixtures/noncompliant_iptables.save; set -e
cat "$OUT/iptables_noncompliant.txt"
assert_exit iptables_noncompliant 1
assert_check_present iptables_noncompliant any_any_allow "rule#1"
assert_check_present iptables_noncompliant risky_port_exposed "rule#2"
assert_check_present iptables_noncompliant risky_port_exposed "rule#3"
assert_check_present iptables_noncompliant shadowed_rule "rule#4"
assert_check_present iptables_noncompliant missing_default_deny "INPUT"

echo
echo "== generic policy JSON: compliant fixture =="
set +e; run policy_compliant --policy-json test_fixtures/compliant_policy.json; set -e
cat "$OUT/policy_compliant.txt"
assert_exit policy_compliant 0
assert_no_findings policy_compliant

echo
echo "== generic policy JSON: noncompliant fixture =="
set +e; run policy_noncompliant --policy-json test_fixtures/noncompliant_policy.json; set -e
cat "$OUT/policy_noncompliant.txt"
assert_exit policy_noncompliant 1
assert_check_present policy_noncompliant any_any_allow "allow-anything"
assert_check_present policy_noncompliant risky_port_exposed "allow-mysql-admin"
assert_check_present policy_noncompliant shadowed_rule "block-known-bad-ip"
assert_check_present policy_noncompliant missing_default_deny ""

rm -rf "$OUT"
echo
echo "All tests passed."
