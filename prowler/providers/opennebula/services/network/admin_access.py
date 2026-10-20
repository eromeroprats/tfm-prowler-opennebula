"""IPv4 administration policy evaluation, independent of Prowler/PyONE imports.

Prototype scope: running VMs, VN_MAD=fw, TCP and IPv4 source permissions.
This evaluates configured permissions, not reachability or attack activity.
"""

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
import ipaddress
import json


class NotEvaluable(ValueError):
    """Insufficient, unsupported or inconsistent evidence; never implies PASS."""


@dataclass(frozen=True)
class Target:
    vm_id: int
    nic_id: int
    tcp_ports: tuple
    allowed_ipv4: tuple


@dataclass
class Result:
    id: str
    name: str
    status: str
    reason: str
    evidence: dict = field(default_factory=dict)
    location: str = "local"


def items(value):
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def mapping(value):
    value = getattr(value, "_attributes", value)
    if not isinstance(value, Mapping):
        raise NotEvaluable("Expected a structured TEMPLATE, NIC or rule.")
    return dict(value)


def integer(value, minimum, maximum):
    if isinstance(value, bool) or not str(value).isascii() or not str(value).isdigit():
        raise NotEvaluable("Expected a non-negative decimal integer.")
    number = int(value)
    if not minimum <= number <= maximum:
        raise NotEvaluable("Integer outside the supported range.")
    return number


def load_targets(audit_config):
    if not isinstance(audit_config, Mapping):
        raise NotEvaluable("Missing audit configuration.")
    policy = audit_config.get("tfm_network_admin_policy")
    if not isinstance(policy, Mapping) or set(policy) != {"targets"}:
        raise NotEvaluable("Configure tfm_network_admin_policy.targets explicitly.")
    rows = policy["targets"]
    if not isinstance(rows, list) or not rows:
        raise NotEvaluable("Policy targets must be a non-empty list.")
    targets, seen = [], set()
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {
            "vm_id", "nic_id", "tcp_ports", "allowed_ipv4"
        }:
            raise NotEvaluable("Each target needs vm_id, nic_id, tcp_ports, allowed_ipv4.")
        vm_id = integer(row["vm_id"], 0, 2**31 - 1)
        nic_id = integer(row["nic_id"], 0, 2**31 - 1)
        if (vm_id, nic_id) in seen:
            raise NotEvaluable("Duplicate VM/NIC policy target.")
        seen.add((vm_id, nic_id))
        if not isinstance(row["tcp_ports"], list) or not row["tcp_ports"]:
            raise NotEvaluable("tcp_ports must be a non-empty list.")
        ports = tuple(sorted({integer(p, 1, 65535) for p in row["tcp_ports"]}))
        if not isinstance(row["allowed_ipv4"], list) or not row["allowed_ipv4"]:
            raise NotEvaluable("allowed_ipv4 must be a non-empty list of IPv4 CIDRs.")
        networks = []
        for cidr in row["allowed_ipv4"]:
            if not isinstance(cidr, str) or "/" not in cidr:
                raise NotEvaluable("Use explicit IPv4 CIDRs, including /32 for a host.")
            try:
                network = ipaddress.ip_network(cidr, strict=True)
            except ValueError:
                raise NotEvaluable("Invalid IPv4 policy CIDR.") from None
            if network.version != 4:
                raise NotEvaluable("This prototype supports IPv4 policies only.")
            networks.append(network)
        targets.append(Target(vm_id, nic_id, ports,
                              tuple(ipaddress.collapse_addresses(networks))))
    return targets


def port_selected(rule, ports):
    """Check all tokens: malformed later tokens must not be hidden by a match."""
    protocol = rule.get("PROTOCOL", "").strip().upper()
    if protocol in {"UDP", "ICMP", "ICMPV6", "IPSEC"}:
        return ()
    if protocol not in {"ALL", "TCP"}:
        raise NotEvaluable("Unsupported or missing rule protocol.")
    # OpenNebula RANGE constrains only TCP/UDP, not protocol ALL.
    raw = rule.get("RANGE", "").strip()
    if protocol == "ALL" or not raw:
        return ports
    ranges = []
    for token in raw.split(","):
        pair = token.strip().split(":")
        if len(pair) == 1:
            lo = hi = integer(pair[0], 0, 65535)
        elif len(pair) == 2:
            lo, hi = (integer(p.strip(), 0, 65535) for p in pair)
        else:
            raise NotEvaluable("Unsupported TCP port range.")
        if hi < lo:
            raise NotEvaluable("Reversed TCP port range.")
        ranges.append((lo, hi))
    return tuple(p for p in ports if any(lo <= p <= hi for lo, hi in ranges))


def source_interval(rule):
    if rule.get("NETWORK_ID", "").strip():
        raise NotEvaluable("NETWORK_ID source resolution is not implemented.")
    if any(rule.get(k, "").strip() for k in ("IP6", "IP6_GLOBAL", "IP6_ULA")):
        raise NotEvaluable("IPv6 source rules are outside this prototype.")
    ip, size = rule.get("IP", "").strip(), rule.get("SIZE", "").strip()
    if not ip and not size:
        return 0, 2**32 - 1
    if not ip or not size:
        raise NotEvaluable("IP and SIZE must be provided together.")
    try:
        start = ipaddress.ip_address(ip)
    except ValueError:
        raise NotEvaluable("Invalid rule source IP.") from None
    if start.version != 4:
        raise NotEvaluable("IPv6 source rules are outside this prototype.")
    count = integer(size, 1, 2**32)
    first, last = int(start), int(start) + count - 1
    if last > 2**32 - 1:
        raise NotEvaluable("IPv4 source interval overflow.")
    return first, last


def unauthorized_address(first, last, networks):
    """Return one witness outside the union, without enumerating addresses."""
    cursor = first
    for network in sorted(networks, key=lambda n: int(n.network_address)):
        lo, hi = int(network.network_address), int(network.broadcast_address)
        if hi < cursor:
            continue
        if lo > cursor:
            break
        cursor = hi + 1
        if cursor > last:
            return None
    return str(ipaddress.IPv4Address(cursor)) if cursor <= last else None


def flat_rule(raw):
    result = {}
    for key, value in mapping(raw).items():
        if isinstance(value, (Mapping, list, tuple)) or value is None:
            raise NotEvaluable("Unsupported nested rule value.")
        result[str(key)] = str(value)
    return result


def evaluate_rules(target, rules):
    violations, unknown = [], []
    for index, raw in enumerate(rules):
        try:
            rule = flat_rule(raw)
            direction = rule.get("RULE_TYPE", "").strip().upper()
            if direction == "OUTBOUND":
                continue
            if direction != "INBOUND":
                raise NotEvaluable("Unsupported or missing rule direction.")
            ports = port_selected(rule, target.tcp_ports)
            if not ports:
                continue
            first, last = source_interval(rule)
            witness = unauthorized_address(first, last, target.allowed_ipv4)
            if witness is not None:
                violations.append({
                    "security_group_id": rule.get("SECURITY_GROUP_ID", "unknown"),
                    "rule_index": index,
                    "tcp_ports": list(ports),
                    "ipv4_source_interval": [str(ipaddress.IPv4Address(first)),
                                             str(ipaddress.IPv4Address(last))],
                    "example_unauthorized_ipv4": witness,
                })
        except NotEvaluable as error:
            unknown.append({"rule_index": index, "reason": str(error)})
    evidence = {
        "tcp_ports": list(target.tcp_ports),
        "allowed_ipv4": [str(n) for n in target.allowed_ipv4],
        "violation_count": len(violations),
        "violations": violations[:20],
        "unsupported_rules": unknown[:20],
    }
    if violations:
        return "FAIL", "Copied rules permit TCP administration from outside the allowed IPv4 sources.", evidence
    if unknown:
        return "MANUAL", "Some relevant rules cannot be evaluated; no PASS is asserted.", evidence
    return "PASS", "No copied rule permits the selected TCP ports from outside the allowed IPv4 sources. Availability is not assessed.", evidence


def vm_ids(group, attribute):
    value = getattr(group, attribute, None)
    if value is None:
        return set()
    raw = value.get("ID") if isinstance(value, Mapping) else getattr(value, "ID", None)
    return {str(i) for i in items(raw)}


def canonical_rules(rules):
    excluded = {"SECURITY_GROUP_ID", "SECURITY_GROUP_NAME"}
    return Counter(json.dumps({k: v for k, v in flat_rule(r).items()
                               if k not in excluded}, sort_keys=True)
                   for r in rules)


def audit_target(client, target):
    result = Result(f"vm/{target.vm_id}/nic/{target.nic_id}",
                    f"VM {target.vm_id} NIC {target.nic_id}", "MANUAL", "Not evaluated.")
    try:
        vm = client.vm.info(target.vm_id)
        result.name = f"{vm.NAME} / NIC {target.nic_id}"
        if str(vm.STATE) != "3" or str(vm.LCM_STATE) != "3":
            raise NotEvaluable("Only ACTIVE/RUNNING VMs are supported by this prototype.")
        template = mapping(vm.TEMPLATE)
        nics = [mapping(n) for n in items(template.get("NIC"))]
        matches = [n for n in nics if str(n.get("NIC_ID")) == str(target.nic_id)]
        if len(matches) != 1:
            raise NotEvaluable("Policy NIC is missing or ambiguous.")
        nic = matches[0]
        if nic.get("VN_MAD") != "fw":
            raise NotEvaluable("Only the fw network driver is supported by this prototype.")
        raw_ids = str(nic.get("SECURITY_GROUPS", "")).split(",")
        group_ids = sorted({integer(s.strip(), 0, 2**31 - 1) for s in raw_ids})
        if not group_ids:
            raise NotEvaluable("Missing security group association.")
        copied = [flat_rule(r) for r in items(template.get("SECURITY_GROUP_RULE"))]
        for rule in copied:
            integer(rule.get("SECURITY_GROUP_ID"), 0, 2**31 - 1)
        selected = [r for r in copied if int(r["SECURITY_GROUP_ID"]) in group_ids]
        result.evidence = {"security_group_ids": group_ids,
                           "network_id": str(nic.get("NETWORK_ID", "")),
                           "vm_ipv4": str(nic.get("IP", ""))}
        # Check propagation and that the copied rules still match each catalog SG.
        for group_id in group_ids:
            group = client.secgroup.info(group_id)
            vm_id = str(target.vm_id)
            if any(vm_id in vm_ids(group, field) for field in
                   ("OUTDATED_VMS", "UPDATING_VMS", "ERROR_VMS")):
                raise NotEvaluable("Security group propagation is pending or failed.")
            if vm_id not in vm_ids(group, "UPDATED_VMS"):
                raise NotEvaluable("Security group application is not confirmed as UPDATED.")
            expected = items(mapping(group.TEMPLATE).get("RULE"))
            actual = [r for r in selected if int(r["SECURITY_GROUP_ID"]) == group_id]
            if canonical_rules(expected) != canonical_rules(actual):
                raise NotEvaluable("Catalog and copied rules differ; repeat after propagation.")
        result.status, result.reason, evaluation = evaluate_rules(target, selected)
        result.evidence.update(evaluation)
    except NotEvaluable as error:
        result.status, result.reason = "MANUAL", str(error)
    except Exception as error:
        # Exception messages can contain URLs or other sensitive response material.
        result.status = "MANUAL"
        result.reason = f"API read or representation failed ({type(error).__name__}); no PASS is asserted."
    return result
