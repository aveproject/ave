# What: fixes the Section 4.2 behavioral_vector misuse and populates example_patterns
# Why:  behavioral_vector is documented as short attack-path tags but records 00041-00051
#       repurposed it to hold full example payloads, and records 00004-00015 left it empty;
#       the new example_patterns field is where illustrative payloads belong instead
# How:  for 00041-00051, move the existing payload array verbatim into example_patterns,
#       then overwrite behavioral_vector with hand-drafted short tags grounded in each
#       record's attack_class/title/behavioral_fingerprint; for 00004-00015, only draft tags
#       (LLM draft pass per the migration brief; a human should spot-check a sample before merge)
import json
from pathlib import Path

RECORDS_DIR = Path("records")

# Records 00004-00015: behavioral_vector is empty, draft fresh short tags.
NEW_TAGS_EMPTY = {
    "AVE-2026-00004": ["shell-pipe", "remote-exec", "tool-abuse"],
    "AVE-2026-00005": ["destructive-command", "filesystem-wipe", "tool-abuse"],
    "AVE-2026-00006": ["wallet-drain", "unlimited-approval", "fund-transfer"],
    "AVE-2026-00007": ["instruction-override", "goal-hijack", "prompt-injection"],
    "AVE-2026-00008": ["self-replication", "persistence", "startup-hook"],
    "AVE-2026-00009": ["persona-override", "jailbreak", "prompt-injection"],
    "AVE-2026-00010": ["secrecy-directive", "hidden-instruction", "prompt-injection"],
    "AVE-2026-00011": ["forced-tool-call", "parameter-injection", "tool-abuse"],
    "AVE-2026-00012": ["false-permission-grant", "privilege-escalation", "authority-claim"],
    "AVE-2026-00013": ["pii-collection", "data-exfil", "covert-transmission"],
    "AVE-2026-00014": ["authority-impersonation", "trust-escalation", "social-engineering"],
    "AVE-2026-00015": ["prompt-extraction", "system-prompt-leak", "information-disclosure"],
}

# Records 00041-00051: behavioral_vector currently holds full payloads; replace with tags
# and move the payloads verbatim into example_patterns.
NEW_TAGS_REPURPOSED = {
    "AVE-2026-00041": ["server-card-injection", "tool-description-poison", "pre-call-injection"],
    "AVE-2026-00042": ["code-mode-injection", "eval-exec", "tool-result-poison"],
    "AVE-2026-00043": ["ui-payload-injection", "hidden-element", "rich-ui-abuse"],
    "AVE-2026-00044": ["async-result-poison", "webhook-injection", "deferred-context-injection"],
    "AVE-2026-00045": ["cross-app-pivot", "confused-deputy", "trust-boundary-cross"],
    "AVE-2026-00046": ["hook-hijack", "tool-interception", "callback-redirect"],
    "AVE-2026-00047": ["hardcoded-credential", "secret-exposure", "high-entropy-string"],
    "AVE-2026-00048": ["unsafe-delegation", "permission-inheritance", "sub-agent-spawn"],
    "AVE-2026-00049": ["host-header-injection", "request-routing-abuse", "badhost"],
    "AVE-2026-00050": ["parasitic-tool-registration", "hook-injection", "dispatch-hijack"],
    "AVE-2026-00051": ["oauth-discovery-rebind", "endpoint-mismatch", "auth-flow-hijack"],
}


def insert_after(record: dict, after_key: str, new_key: str, value) -> dict:
    new_record = {}
    for k, v in record.items():
        new_record[k] = v
        if k == after_key:
            new_record[new_key] = value
    return new_record


def migrate_record(path: Path) -> bool:
    record = json.loads(path.read_text())
    rid = record["ave_id"]
    changed = False

    if rid in NEW_TAGS_EMPTY:
        if record.get("behavioral_vector"):
            raise ValueError(f"{rid}: expected empty behavioral_vector, found content")
        record["behavioral_vector"] = NEW_TAGS_EMPTY[rid]
        changed = True

    if rid in NEW_TAGS_REPURPOSED:
        existing = record.get("behavioral_vector")
        if not existing:
            raise ValueError(f"{rid}: expected repurposed payload content, found none")
        if "example_patterns" in record:
            raise ValueError(f"{rid}: example_patterns already present, refusing to overwrite")
        record = insert_after(record, "behavioral_vector", "example_patterns", existing)
        record["behavioral_vector"] = NEW_TAGS_REPURPOSED[rid]
        changed = True

    if changed:
        path.write_text(json.dumps(record, indent=2) + "\n")
    return changed


def main() -> int:
    expected = set(NEW_TAGS_EMPTY) | set(NEW_TAGS_REPURPOSED)
    changed_count = 0
    seen = set()
    for path in sorted(RECORDS_DIR.glob("AVE-*.json")):
        record = json.loads(path.read_text())
        rid = record["ave_id"]
        if rid in expected:
            seen.add(rid)
        if migrate_record(path):
            changed_count += 1
    missing = expected - seen
    if missing:
        raise SystemExit(f"Records referenced in this script but not found in records/: {missing}")
    print(f"Updated {changed_count} records ({len(NEW_TAGS_EMPTY)} tag-drafts, {len(NEW_TAGS_REPURPOSED)} tag+example_patterns splits).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
