"""Policy-scoped evaluation of copied OpenNebula security group permissions."""

import json

from prowler.lib.check.models import Check, Check_Report_OpenNebula
from prowler.providers.opennebula.services.network.admin_access import (
    NotEvaluable,
    Result,
    audit_target,
    load_targets,
)
from prowler.providers.opennebula.services.network.network_client import network_client


class network_vm_admin_access_restricted(Check):
    def execute(self):
        try:
            targets = load_targets(network_client.audit_config)
        except NotEvaluable as error:
            results = [Result("policy/tfm-network-admin", "Administration policy",
                              "MANUAL", str(error))]
        else:
            results = [audit_target(network_client.client, target) for target in targets]
        findings = []
        for result in results:
            report = Check_Report_OpenNebula(metadata=self.metadata(), resource=result)
            report.status = result.status
            report.status_extended = f"{result.name}: {result.reason}"
            if result.evidence:
                report.status_extended += " Evidence: " + json.dumps(
                    result.evidence, sort_keys=True, ensure_ascii=True)
            report.resource_details = json.dumps(result.evidence, sort_keys=True)
            findings.append(report)
        return findings
