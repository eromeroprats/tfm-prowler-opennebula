"""Unit/adapter tests with synthetic data; no connection to a real OpenNebula."""

import copy
import importlib.util
import ipaddress
from pathlib import Path
import sys
from types import SimpleNamespace as Obj
import unittest

ROOT = Path(__file__).resolve().parents[5]
SOURCE = ROOT / "prowler/providers/opennebula/services/network/admin_access.py"
spec = importlib.util.spec_from_file_location("tfm_admin_access_under_test", SOURCE)
core = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = core
spec.loader.exec_module(core)


def policy(**overrides):
    row = dict(vm_id=2, nic_id=0, tcp_ports=[22], allowed_ipv4=["172.16.100.1/32"])
    row.update(overrides)
    return {"tfm_network_admin_policy": {"targets": [row]}}


def rule(**overrides):
    value = dict(RULE_TYPE="INBOUND", PROTOCOL="TCP", RANGE="22",
                 IP="172.16.100.1", SIZE="1", SECURITY_GROUP_ID="100")
    value.update(overrides)
    return value


def client_fixture(rules=None, groups="100"):
    if rules is None:
        rules = [rule(), rule(RULE_TYPE="OUTBOUND", PROTOCOL="ALL")]
    vm = Obj(ID=2, NAME="tfm-prueba-arm64", STATE=3, LCM_STATE=3,
             TEMPLATE={"NIC": {"NIC_ID": "0", "VN_MAD": "fw", "IP": "172.16.100.4",
                               "NETWORK_ID": "0", "SECURITY_GROUPS": groups},
                       "SECURITY_GROUP_RULE": copy.deepcopy(rules)})
    catalog = {}
    for gid in groups.split(","):
        catalog[int(gid)] = Obj(
            UPDATED_VMS=Obj(ID=[2]), OUTDATED_VMS=Obj(ID=[]),
            UPDATING_VMS=Obj(ID=[]), ERROR_VMS=Obj(ID=[]),
            TEMPLATE={"RULE": [{k: v for k, v in r.items()
                                 if k not in {"SECURITY_GROUP_ID", "SECURITY_GROUP_NAME"}}
                                for r in rules if r.get("SECURITY_GROUP_ID") == gid]})
    client = Obj(vm=Obj(info=lambda _: vm), secgroup=Obj(info=lambda i: catalog[i]))
    return client, vm, catalog


class PolicyTests(unittest.TestCase):
    def test_explicit_lab_policy(self):
        target = core.load_targets(policy())[0]
        self.assertEqual((target.vm_id, target.nic_id, target.tcp_ports), (2, 0, (22,)))

    def test_missing_empty_or_misspelled_configuration_is_not_evaluable(self):
        for config in ({}, None, {"tfm_network_admin_policy": {"targets": []}},
                       {"tfm_network_admin_policy": {"target": []}}):
            with self.subTest(config=config), self.assertRaises(core.NotEvaluable):
                core.load_targets(config)

    def test_invalid_target_fields(self):
        for change in (dict(vm_id=True), dict(vm_id=-1), dict(nic_id="x"),
                       dict(tcp_ports=[]), dict(tcp_ports=[65536]), dict(tcp_ports=[True]),
                       dict(allowed_ipv4=[]), dict(allowed_ipv4=["172.16.100.1"]),
                       dict(allowed_ipv4=["172.16.100.1/24"]), dict(allowed_ipv4=["::1/128"]),
                       dict(allowed_ipv4=["bad/32"]), dict(typo=1)):
            with self.subTest(change=change), self.assertRaises(core.NotEvaluable):
                core.load_targets(policy(**change))

    def test_duplicate_targets_rejected(self):
        config = policy()
        config["tfm_network_admin_policy"]["targets"] *= 2
        with self.assertRaises(core.NotEvaluable):
            core.load_targets(config)


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.target = core.load_targets(policy())[0]

    def result(self, *rules, target=None):
        return core.evaluate_rules(target or self.target, rules)

    def test_restricted_host_passes(self):
        self.assertEqual(self.result(rule())[0], "PASS")

    def test_default_any_fails_and_includes_witness(self):
        status, _, evidence = self.result(dict(RULE_TYPE="INBOUND", PROTOCOL="ALL",
                                              SECURITY_GROUP_ID="0"))
        self.assertEqual(status, "FAIL")
        violation = evidence["violations"][0]
        self.assertEqual(violation["security_group_id"], "0")
        self.assertNotEqual(violation["example_unauthorized_ipv4"], "172.16.100.1")

    def test_combination_does_not_override_permissive_group(self):
        permissive = dict(RULE_TYPE="INBOUND", PROTOCOL="ALL", SECURITY_GROUP_ID="0")
        self.assertEqual(self.result(rule(), permissive)[0], "FAIL")
        self.assertEqual(self.result(permissive, rule())[0], "FAIL")

    def test_outbound_all_does_not_allow_inbound_ssh(self):
        self.assertEqual(self.result(dict(RULE_TYPE="OUTBOUND", PROTOCOL="ALL"))[0], "PASS")

    def test_other_ports_and_protocols_do_not_allow_tcp_ssh(self):
        for candidate in (rule(RANGE="80,443"), rule(PROTOCOL="UDP"),
                          rule(PROTOCOL="ICMP"), rule(PROTOCOL="IPSEC")):
            with self.subTest(candidate=candidate):
                self.assertEqual(self.result(candidate)[0], "PASS")

    def test_port_ranges_boundary_and_list(self):
        for ports, expected in (("20:22", "FAIL"), ("23:25", "PASS"),
                                ("80,20:25,443", "FAIL"), ("22:22", "FAIL")):
            with self.subTest(ports=ports):
                self.assertEqual(self.result(rule(RANGE=ports, IP="172.16.100.5"))[0], expected)

    def test_no_tcp_range_means_all_ports(self):
        self.assertEqual(self.result(rule(RANGE="", IP="172.16.100.5"))[0], "FAIL")

    def test_all_protocol_ignores_tcp_only_range(self):
        self.assertEqual(self.result(rule(PROTOCOL="ALL", RANGE="80", IP="172.16.100.5"))[0], "FAIL")

    def test_size_can_spill_beyond_allowed_source(self):
        self.assertEqual(self.result(rule(SIZE="2"))[0], "FAIL")

    def test_broader_allowed_cidr_accepts_authorized_exception(self):
        target = core.load_targets(policy(allowed_ipv4=["172.16.100.0/24"]))[0]
        self.assertEqual(self.result(rule(IP="172.16.100.0", SIZE="256"), target=target)[0], "PASS")

    def test_adjacent_allowed_cidrs_cover_complete_interval(self):
        target = core.load_targets(policy(allowed_ipv4=["172.16.100.0/25", "172.16.100.128/25"]))[0]
        self.assertEqual(self.result(rule(IP="172.16.100.0", SIZE="256"), target=target)[0], "PASS")

    def test_gap_in_allowed_union_is_detected(self):
        target = core.load_targets(policy(allowed_ipv4=["172.16.100.0/32", "172.16.100.2/32"]))[0]
        status, _, evidence = self.result(rule(IP="172.16.100.0", SIZE="3"), target=target)
        self.assertEqual(status, "FAIL")
        self.assertEqual(evidence["violations"][0]["example_unauthorized_ipv4"], "172.16.100.1")

    def test_full_ipv4_range_without_enumeration(self):
        target = core.load_targets(policy(allowed_ipv4=["0.0.0.0/0"]))[0]
        self.assertEqual(self.result(rule(IP="0.0.0.0", SIZE=str(2**32)), target=target)[0], "PASS")

    def test_malformed_and_unsupported_relevant_rules_never_pass(self):
        for change in (dict(IP="", SIZE="1"), dict(SIZE=""), dict(SIZE="0"),
                       dict(IP="255.255.255.255", SIZE="2"), dict(IP="::1"),
                       dict(IP="x"), dict(RANGE="22,garbage"), dict(RANGE="25:20"),
                       dict(RANGE="-1"), dict(RANGE="1:2:3"), dict(RANGE="65536"),
                       dict(PROTOCOL="UNKNOWN"), dict(RULE_TYPE="BAD"),
                       dict(NETWORK_ID="0"), dict(IP6="::1")):
            with self.subTest(change=change):
                self.assertEqual(self.result(rule(**change))[0], "MANUAL")

    def test_known_violation_survives_another_unknown_rule(self):
        self.assertEqual(self.result(rule(IP="172.16.100.5"), rule(NETWORK_ID="0"))[0], "FAIL")

    def test_missing_inbound_permission_does_not_claim_service_availability(self):
        status, reason, _ = self.result()
        self.assertEqual(status, "PASS")
        self.assertIn("Availability is not assessed", reason)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.target = core.load_targets(policy())[0]
        self.client, self.vm, self.groups = client_fixture()

    def audit(self):
        return core.audit_target(self.client, self.target)

    def test_restricted_api_fixture_passes_with_resource_id(self):
        result = self.audit()
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.id, "vm/2/nic/0")
        self.assertEqual(result.evidence["security_group_ids"], [100])

    def test_combined_api_fixture_fails(self):
        rules = [rule(), dict(RULE_TYPE="INBOUND", PROTOCOL="ALL", SECURITY_GROUP_ID="0")]
        self.client, self.vm, self.groups = client_fixture(rules, "0,100")
        self.assertEqual(self.audit().status, "FAIL")

    def test_another_nic_group_is_not_attributed_to_target(self):
        self.vm.TEMPLATE["NIC"] = [self.vm.TEMPLATE["NIC"],
                                   {"NIC_ID": "1", "SECURITY_GROUPS": "0", "VN_MAD": "fw"}]
        self.vm.TEMPLATE["SECURITY_GROUP_RULE"].append(
            dict(RULE_TYPE="INBOUND", PROTOCOL="ALL", SECURITY_GROUP_ID="0"))
        self.assertEqual(self.audit().status, "PASS")

    def test_pyone_attributes_wrapper_and_single_rule(self):
        self.vm.TEMPLATE["SECURITY_GROUP_RULE"] = rule()
        self.groups[100].TEMPLATE["RULE"] = {k: v for k, v in rule().items()
                                             if k != "SECURITY_GROUP_ID"}
        self.vm.TEMPLATE = Obj(_attributes=self.vm.TEMPLATE)
        self.assertEqual(self.audit().status, "PASS")

    def test_propagation_states_are_manual(self):
        for state in ("OUTDATED_VMS", "UPDATING_VMS", "ERROR_VMS"):
            setattr(self.groups[100], state, Obj(ID=[2]))
            with self.subTest(state=state):
                self.assertEqual(self.audit().status, "MANUAL")
            setattr(self.groups[100], state, Obj(ID=[]))

    def test_updated_confirmation_missing_is_manual(self):
        self.groups[100].UPDATED_VMS = Obj(ID=[])
        self.assertEqual(self.audit().status, "MANUAL")

    def test_catalog_copy_inconsistency_is_manual(self):
        self.groups[100].TEMPLATE["RULE"][0]["IP"] = "172.16.100.5"
        self.assertEqual(self.audit().status, "MANUAL")

    def test_missing_copied_rules_is_manual_if_catalog_has_rules(self):
        del self.vm.TEMPLATE["SECURITY_GROUP_RULE"]
        self.assertEqual(self.audit().status, "MANUAL")

    def test_no_rule_group_has_no_inbound_permissions(self):
        self.client, self.vm, self.groups = client_fixture([], "100")
        self.assertEqual(self.audit().status, "PASS")

    def test_non_running_vm_is_manual(self):
        self.vm.LCM_STATE = 0
        self.assertEqual(self.audit().status, "MANUAL")

    def test_missing_nic_is_manual(self):
        self.vm.TEMPLATE["NIC"]["NIC_ID"] = "1"
        self.assertEqual(self.audit().status, "MANUAL")

    def test_unsupported_driver_is_manual(self):
        self.vm.TEMPLATE["NIC"]["VN_MAD"] = "ovswitch"
        self.assertEqual(self.audit().status, "MANUAL")

    def test_invalid_group_associations_are_manual(self):
        for ids in ("", "100,", "unknown"):
            self.vm.TEMPLATE["NIC"]["SECURITY_GROUPS"] = ids
            with self.subTest(ids=ids):
                self.assertEqual(self.audit().status, "MANUAL")

    def test_missing_rule_group_id_is_manual(self):
        del self.vm.TEMPLATE["SECURITY_GROUP_RULE"][0]["SECURITY_GROUP_ID"]
        self.assertEqual(self.audit().status, "MANUAL")

    def test_api_exception_is_manual_and_does_not_leak_message(self):
        def denied(_):
            raise RuntimeError("secret-token-test")
        self.client.secgroup.info = denied
        result = self.audit()
        self.assertEqual(result.status, "MANUAL")
        self.assertNotIn("secret-token-test", result.reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
