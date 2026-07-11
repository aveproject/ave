# What: Section 6.2 draft pass — fills provenance_vector, trifecta_profile, and
#       mitigation for all 51 records, replacing the null placeholders from Section 5
# Why:  these three objects describe the vulnerability's runtime shape and abstract
#       defense class; a human reviewer needs a grounded first draft to confirm rather
#       than a blank page, especially for the bawbel-gate/PiranhaDB priority records
# How:  hand-classified per record from its attack_class, detection_layer, and
#       behavioral_fingerprint (LLM draft pass per the migration brief); some records
#       correctly omit trifecta_profile entirely (e.g. 00014, pure social engineering
#       with no tool-call path) rather than forcing a poor fit; validates against the
#       schema before writing and never touches behavioral_vector or example_patterns
import json
from pathlib import Path

import jsonschema

RECORDS_DIR = Path("records")
SCHEMA_PATH = Path("schema/ave-record-1.1.0.schema.json")

# ave_id -> (provenance_vector | None, trifecta_profile | None, mitigation | None)
ENRICHMENT = {
    "AVE-2026-00001": (
        {"entry_class": "content", "payload_surface": "skill instruction body: fetch()/curl/wget directive", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content", "external_comms"], "amplifies": ["private_data"]},
        {"strategy": ["pin_integrity", "sever_egress"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_external_comms"},
    ),
    "AVE-2026-00002": (
        {"entry_class": "tool_schema", "payload_surface": "MCP tool.description field", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "sanitize_output"], "enforcement_point": "server_card_fetch", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00003": (
        {"entry_class": "content", "payload_surface": "skill instruction body: environment/credential read + external send", "escalation": "instruction_to_capability"},
        {"requires": ["private_data", "external_comms"]},
        {"strategy": ["least_privilege", "sever_egress"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_external_comms"},
    ),
    "AVE-2026-00004": (
        {"entry_class": "content", "payload_surface": "skill instruction body: curl|bash / wget|sh directive", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content", "external_comms"]},
        {"strategy": ["deny_by_default", "isolate_scope"], "enforcement_point": "agent_framework", "trifecta_control": "break_external_comms"},
    ),
    "AVE-2026-00005": (
        {"entry_class": "content", "payload_surface": "skill instruction body: recursive delete command", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["require_human_approval", "least_privilege"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00006": (
        {"entry_class": "content", "payload_surface": "skill instruction body: fund-transfer / allowance-approval directive", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content", "external_comms"]},
        {"strategy": ["require_human_approval", "least_privilege"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00007": (
        {"entry_class": "content", "payload_surface": "skill instruction body: instruction-override language", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "deny_by_default"], "enforcement_point": "static_scan", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00008": (
        {"entry_class": "content", "payload_surface": "skill instruction body: startup-script / cron-registration directive", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["least_privilege", "isolate_scope"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00009": (
        {"entry_class": "content", "payload_surface": "skill instruction body: persona-override / unrestricted-mode directive", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "deny_by_default"], "enforcement_point": "static_scan", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00010": (
        {"entry_class": "content", "payload_surface": "skill instruction body: secrecy directive", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "provenance_label"], "enforcement_point": "static_scan", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00011": (
        {"entry_class": "content", "payload_surface": "skill instruction body: explicit tool-call directive with parameters", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["require_human_approval", "least_privilege"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00012": (
        {"entry_class": "content", "payload_surface": "skill instruction body: false permission-grant claim", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["verify_identity", "deny_by_default"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00013": (
        {"entry_class": "content", "payload_surface": "skill instruction body: PII-collection + transmission directive", "escalation": "instruction_to_capability"},
        {"requires": ["private_data", "external_comms"]},
        {"strategy": ["least_privilege", "sever_egress"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_external_comms"},
    ),
    "AVE-2026-00014": (
        {"entry_class": "content", "payload_surface": "skill instruction body: false-authority framing"},
        None,
        {"strategy": ["verify_identity", "deny_by_default"], "enforcement_point": "static_scan", "trifecta_control": "not_applicable"},
    ),
    "AVE-2026-00015": (
        {"entry_class": "content", "payload_surface": "skill instruction body: system-prompt interrogation directive"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "sanitize_output"], "enforcement_point": "static_scan", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00016": (
        {"entry_class": "retrieved_document", "payload_surface": "RAG-indexed document body", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"], "amplifies": ["private_data"]},
        {"strategy": ["sanitize_output", "validate_input"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00017": (
        {"entry_class": "registry_metadata", "payload_surface": "MCP registry listing / server manifest identity claims", "escalation": "capability_to_identity"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["verify_identity", "pin_integrity"], "enforcement_point": "server_card_fetch", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00018": (
        {"entry_class": "tool_response", "payload_surface": "tool call result payload", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "provenance_label"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00019": (
        {"entry_class": "memory", "payload_surface": "persistent memory store write", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"], "amplifies": ["private_data"]},
        {"strategy": ["validate_input", "isolate_scope"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00020": (
        {"entry_class": "runtime", "payload_surface": "agent-to-agent message payload", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "isolate_scope"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00021": (
        {"entry_class": "content", "payload_surface": "skill instruction body: no-confirmation directive", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["require_human_approval", "deny_by_default"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00022": (
        {"entry_class": "content", "payload_surface": "skill instruction body: undeclared-resource-access directive", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["least_privilege", "isolate_scope"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00023": (
        {"entry_class": "runtime", "payload_surface": "tool/skill output volume flooding the context window"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "isolate_scope"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00024": (
        {"entry_class": "skill_file", "payload_surface": "skill file bytes vs. declared extension", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "deny_by_default"], "enforcement_point": "static_scan", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00025": (
        {"entry_class": "content", "payload_surface": "fabricated prior-turn content injected into context", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "provenance_label"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00026": (
        {"entry_class": "content", "payload_surface": "tool call parameters/return values carrying encoded payload", "escalation": "instruction_to_capability"},
        {"requires": ["private_data", "external_comms"]},
        {"strategy": ["sanitize_output", "sever_egress"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_external_comms"},
    ),
    "AVE-2026-00027": (
        {"entry_class": "content", "payload_surface": "instruction directing retention across turns/sessions", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["isolate_scope", "validate_input"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00028": (
        {"entry_class": "user_input", "payload_surface": "user-supplied file/document body", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "isolate_scope"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00029": (
        {"entry_class": "content", "payload_surface": "text content containing homoglyph, zero-width, or bidi control characters"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "sanitize_output"], "enforcement_point": "static_scan", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00030": (
        {"entry_class": "content", "payload_surface": "skill instruction body: role-claim trust rule", "escalation": "capability_to_identity"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["verify_identity", "deny_by_default"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00031": (
        {"entry_class": "content", "payload_surface": "agent-generated output targeting a training/RLHF feedback pipeline"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "isolate_scope"], "enforcement_point": "downstream_system", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00032": (
        {"entry_class": "content", "payload_surface": "skill instruction body: network/port-scan directive", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["least_privilege", "isolate_scope"], "enforcement_point": "network_layer", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00033": (
        {"entry_class": "content", "payload_surface": "skill instruction body: eval/pickle/yaml.load of untrusted data", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "isolate_scope"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00034": (
        {"entry_class": "content", "payload_surface": "skill instruction body: dynamic-import-from-URL directive", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content", "external_comms"]},
        {"strategy": ["pin_integrity", "deny_by_default"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_external_comms"},
    ),
    "AVE-2026-00035": (
        {"entry_class": "tool_response", "payload_surface": "sensor/environment tool-response payload", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "provenance_label"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00036": (
        {"entry_class": "content", "payload_surface": "skill instruction body: pivot-to-other-systems directive", "escalation": "capability_to_identity"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["least_privilege", "isolate_scope"], "enforcement_point": "network_layer", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00037": (
        {"entry_class": "user_input", "payload_surface": "image/screenshot pixel content", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "sanitize_output"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00038": (
        {"entry_class": "content", "payload_surface": "skill instruction body: unlimited-tool-use / sub-agent-spawn grant", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["least_privilege", "require_human_approval"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00039": (
        {"entry_class": "content", "payload_surface": "output text carrying steganographic/covert encoding", "escalation": "instruction_to_capability"},
        {"requires": ["private_data", "external_comms"]},
        {"strategy": ["sanitize_output", "sever_egress"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_external_comms"},
    ),
    "AVE-2026-00040": (
        {"entry_class": "content", "payload_surface": "agent output passed unescaped to a downstream interpreter (SQL/HTML/shell)", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["sanitize_output", "validate_input"], "enforcement_point": "downstream_system", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00041": (
        {"entry_class": "tool_schema", "payload_surface": "MCP server-card tool.description field", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"], "amplifies": ["external_comms", "private_data"]},
        {"strategy": ["validate_input", "pin_integrity"], "enforcement_point": "server_card_fetch", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00042": (
        {"entry_class": "tool_response", "payload_surface": "tool result content passed into eval()/exec()/dynamic code string", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"], "amplifies": ["external_comms"]},
        {"strategy": ["deny_by_default", "validate_input", "isolate_scope"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00043": (
        {"entry_class": "tool_response", "payload_surface": "rich UI payload (canvas/artifact/SVG/HTML) non-rendered elements", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["sanitize_output", "validate_input"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00044": (
        {"entry_class": "tool_response", "payload_surface": "async task/webhook/polling result payload", "escalation": "data_to_instruction"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["validate_input", "isolate_scope"], "enforcement_point": "runtime_proxy", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00045": (
        {"entry_class": "tool_response", "payload_surface": "low-trust MCP server tool description/result referencing a co-connected high-trust server", "escalation": "capability_to_identity"},
        {"requires": ["untrusted_content"], "amplifies": ["private_data", "external_comms"]},
        {"strategy": ["isolate_scope", "verify_identity", "least_privilege"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00046": (
        {"entry_class": "server_card_document", "payload_surface": "skill-declared hook/callback registration targeting the tool dispatch layer", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content", "external_comms"], "amplifies": ["private_data"]},
        {"strategy": ["deny_by_default", "isolate_scope"], "enforcement_point": "agent_framework", "trifecta_control": "break_external_comms"},
    ),
    "AVE-2026-00047": (
        {"entry_class": "skill_file", "payload_surface": "literal credential string in skill file body"},
        {"requires": ["private_data"]},
        {"strategy": ["validate_input", "provenance_label"], "enforcement_point": "static_scan", "trifecta_control": "break_private_data"},
    ),
    "AVE-2026-00048": (
        {"entry_class": "content", "payload_surface": "skill instruction body: sub-agent delegation with full-access/inherit-permissions language", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"]},
        {"strategy": ["least_privilege", "isolate_scope"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00049": (
        {"entry_class": "transport", "payload_surface": "outbound HTTP Host / X-Forwarded-Host / Forwarded header", "escalation": "instruction_to_capability"},
        {"requires": ["external_comms"]},
        {"strategy": ["validate_input", "sever_egress"], "enforcement_point": "network_layer", "trifecta_control": "break_external_comms"},
    ),
    "AVE-2026-00050": (
        {"entry_class": "runtime", "payload_surface": "tool registry / hook-dispatch registration call at session init", "escalation": "instruction_to_capability"},
        {"requires": ["untrusted_content"], "amplifies": ["private_data", "external_comms"]},
        {"strategy": ["deny_by_default", "isolate_scope"], "enforcement_point": "agent_framework", "trifecta_control": "break_untrusted_content"},
    ),
    "AVE-2026-00051": (
        {"entry_class": "registry_metadata", "payload_surface": "OAuth discovery document (authorization_endpoint/token_endpoint/jwks_uri)", "escalation": "capability_to_identity"},
        {"requires": ["external_comms"]},
        {"strategy": ["verify_identity", "pin_integrity"], "enforcement_point": "server_card_fetch", "trifecta_control": "break_external_comms"},
    ),
}


def enrich_record(record: dict) -> dict:
    rid = record["ave_id"]
    if rid not in ENRICHMENT:
        raise ValueError(f"{rid}: no enrichment drafted for this record")
    provenance_vector, trifecta_profile, mitigation = ENRICHMENT[rid]

    # keys already exist as null placeholders from the Section 5 migration script;
    # plain assignment overwrites the value in place without reordering keys
    record["provenance_vector"] = provenance_vector
    if trifecta_profile is not None:
        record["trifecta_profile"] = trifecta_profile
    else:
        record.pop("trifecta_profile", None)
    record["mitigation"] = mitigation
    return record


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = jsonschema.Draft202012Validator(schema)

    paths = sorted(RECORDS_DIR.glob("AVE-*.json"))
    missing = set(ENRICHMENT) - {json.loads(p.read_text())["ave_id"] for p in paths}
    if missing:
        raise SystemExit(f"Enrichment drafted for records not found in records/: {missing}")

    changed_count = 0
    for path in paths:
        record = json.loads(path.read_text())
        rid = record["ave_id"]
        before = json.dumps(record, sort_keys=True)
        enriched = enrich_record(record)
        after = json.dumps(enriched, sort_keys=True)

        errors = list(validator.iter_errors(enriched))
        if errors:
            print(f"ABORT {rid}: fails schema after enrichment:")
            for e in errors:
                print(f"  {e.message} (at {'/'.join(str(p) for p in e.path) or '<root>'})")
            return 1

        if before != after:
            path.write_text(json.dumps(enriched, indent=2) + "\n")
            changed_count += 1

    print(f"Enriched {changed_count} of {len(paths)} records.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
