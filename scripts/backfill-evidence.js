// What: backfills evidence declaration fields on all 48 AVE records
// Why:  v1.1.0 requires evidence_kind_default, detection_stage, detection_layer,
//       confidence_baseline, evidence_basis_engines, derivable_into on every record
// How:  per-record mapping derived from attack_class per the derivation rules in
//       docs/migrations/v1.1.0.md; validates each record after writing

"use strict";

const fs   = require("fs");
const path = require("path");
const Ajv  = require("ajv/dist/2020");
const addFormats = require("ajv-formats");

const ajv = new Ajv({ strict: false });
addFormats(ajv);

const SCHEMA  = require("../schema/ave-record-1.0.0.schema.json");
const RECORDS = path.resolve(__dirname, "../records");
const validate = ajv.compile(SCHEMA);

// derivable_into already set for the 5 priority records — do not overwrite
const KEEP_DERIVABLE_INTO = new Set([
  "AVE-2026-00001",
  "AVE-2026-00002",
  "AVE-2026-00042",
  "AVE-2026-00045",
  "AVE-2026-00048",
]);

// Full mapping derived from attack_class using migration v1.1.0 rules.
// Fields: [evidence_kind_default, detection_stage, detection_layer,
//          confidence_baseline, evidence_basis_engines]
const EVIDENCE_MAP = {
  // content layer — static IOC in skill/prompt file body
  "AVE-2026-00001": ["multi_engine",            "static_detection", "content",           0.82, ["pattern","semgrep","yara"]],
  "AVE-2026-00002": ["tool_description_pattern", "static_detection", "content",           0.72, ["pattern","semgrep"]],
  "AVE-2026-00003": ["multi_engine",            "static_detection", "content",           0.82, ["pattern","semgrep","yara"]],
  "AVE-2026-00004": ["multi_engine",            "static_detection", "content",           0.90, ["pattern","semgrep","yara"]],
  "AVE-2026-00005": ["multi_engine",            "static_detection", "content",           0.82, ["pattern","semgrep","yara"]],
  "AVE-2026-00006": ["multi_engine",            "static_detection", "content",           0.82, ["pattern","semgrep","yara"]],
  "AVE-2026-00007": ["behavioral_pattern",      "static_detection", "content",           0.72, ["pattern","semgrep"]],
  "AVE-2026-00008": ["behavioral_pattern",      "static_detection", "content",           0.72, ["pattern","semgrep"]],
  "AVE-2026-00009": ["multi_engine",            "static_detection", "content",           0.82, ["pattern","semgrep","yara"]],
  "AVE-2026-00010": ["multi_engine",            "static_detection", "content",           0.82, ["pattern","semgrep","yara"]],
  "AVE-2026-00011": ["semantic_inference",      "static_detection", "content",           0.62, ["semgrep","llm"]],
  "AVE-2026-00012": ["behavioral_pattern",      "static_detection", "content",           0.72, ["pattern","semgrep"]],
  "AVE-2026-00013": ["multi_engine",            "static_detection", "content",           0.82, ["pattern","semgrep","yara"]],
  "AVE-2026-00014": ["semantic_inference",      "static_detection", "content",           0.50, ["semgrep","llm"]],
  "AVE-2026-00015": ["behavioral_pattern",      "static_detection", "content",           0.72, ["pattern","semgrep"]],
  "AVE-2026-00016": ["semantic_inference",      "static_detection", "content",           0.62, ["semgrep","llm"]],
  "AVE-2026-00018": ["semantic_inference",      "static_detection", "content",           0.62, ["semgrep","llm"]],
  "AVE-2026-00021": ["behavioral_pattern",      "static_detection", "content",           0.72, ["pattern","semgrep"]],
  "AVE-2026-00022": ["semantic_inference",      "static_detection", "content",           0.62, ["semgrep","llm"]],
  "AVE-2026-00023": ["behavioral_pattern",      "static_detection", "content",           0.72, ["pattern","semgrep"]],
  "AVE-2026-00025": ["behavioral_pattern",      "static_detection", "content",           0.72, ["pattern","semgrep"]],
  "AVE-2026-00026": ["multi_engine",            "static_detection", "content",           0.82, ["pattern","semgrep","yara"]],
  "AVE-2026-00027": ["semantic_inference",      "static_detection", "content",           0.62, ["semgrep","llm"]],
  "AVE-2026-00028": ["behavioral_pattern",      "static_detection", "content",           0.72, ["pattern","semgrep"]],
  "AVE-2026-00029": ["multi_engine",            "static_detection", "content",           0.90, ["pattern","semgrep","yara"]],
  "AVE-2026-00030": ["behavioral_pattern",      "static_detection", "content",           0.72, ["pattern","semgrep"]],
  "AVE-2026-00031": ["semantic_inference",      "static_detection", "content",           0.62, ["semgrep","llm"]],
  "AVE-2026-00032": ["multi_engine",            "static_detection", "content",           0.82, ["pattern","semgrep","yara"]],
  "AVE-2026-00033": ["multi_engine",            "static_detection", "content",           0.82, ["pattern","semgrep","yara"]],
  "AVE-2026-00034": ["multi_engine",            "static_detection", "content",           0.82, ["pattern","semgrep","yara"]],
  "AVE-2026-00035": ["semantic_inference",      "static_detection", "content",           0.62, ["semgrep","llm"]],
  "AVE-2026-00037": ["semantic_inference",      "static_detection", "content",           0.50, ["semgrep","llm"]],
  "AVE-2026-00038": ["semantic_inference",      "static_detection", "content",           0.62, ["semgrep","llm"]],
  "AVE-2026-00039": ["multi_engine",            "static_detection", "content",           0.82, ["pattern","semgrep","yara"]],
  "AVE-2026-00040": ["semantic_inference",      "static_detection", "content",           0.62, ["semgrep","llm"]],
  "AVE-2026-00045": ["semantic_inference",      "static_detection", "content",           0.62, ["semgrep","llm"]],
  "AVE-2026-00047": ["multi_engine",            "static_detection", "content",           0.90, ["pattern","semgrep","yara"]],
  "AVE-2026-00048": ["behavioral_pattern",      "static_detection", "content",           0.72, ["pattern","semgrep"]],

  // server_card layer — attacks MCP server-card manifest
  "AVE-2026-00017": ["config_schema",           "static_detection", "server_card",       0.62, ["semgrep","llm"]],
  "AVE-2026-00041": ["config_schema",           "static_detection", "server_card",       0.72, ["pattern","semgrep"]],
  "AVE-2026-00043": ["config_schema",           "static_detection", "server_card",       0.62, ["semgrep","llm"]],
  "AVE-2026-00046": ["config_schema",           "static_detection", "server_card",       0.62, ["semgrep","llm"]],

  // registry_metadata layer — attacks registry listing / supply chain packaging
  "AVE-2026-00024": ["file_type_mismatch",      "static_detection", "registry_metadata", 0.82, ["pattern","semgrep","magika"]],

  // runtime layer — only detectable during agent execution
  "AVE-2026-00019": ["semantic_inference",      "runtime_observed", "runtime",           0.62, ["semgrep","llm"]],
  "AVE-2026-00020": ["semantic_inference",      "runtime_observed", "runtime",           0.62, ["semgrep","llm"]],
  "AVE-2026-00036": ["semantic_inference",      "runtime_observed", "runtime",           0.62, ["semgrep","llm"]],
  "AVE-2026-00042": ["semantic_inference",      "runtime_observed", "runtime",           0.62, ["semgrep","llm"]],
  "AVE-2026-00044": ["semantic_inference",      "runtime_observed", "runtime",           0.62, ["semgrep","llm"]],
};

const files = fs.readdirSync(RECORDS)
  .filter(f => f.endsWith(".json"))
  .sort();

let failures = 0;

for (const f of files) {
  const filePath = path.join(RECORDS, f);
  const rec = JSON.parse(fs.readFileSync(filePath, "utf8"));
  const id = rec.ave_id;

  const entry = EVIDENCE_MAP[id];
  if (!entry) {
    console.log(`SKIP ${id}: no evidence mapping defined`);
    continue;
  }

  const [kind, stage, layer, baseline, engines] = entry;

  rec.evidence_kind_default    = kind;
  rec.detection_stage          = stage;
  rec.detection_layer          = layer;
  rec.confidence_baseline      = baseline;
  rec.evidence_basis_engines   = engines;

  if (!KEEP_DERIVABLE_INTO.has(id)) {
    rec.derivable_into = [];
  }

  fs.writeFileSync(filePath, JSON.stringify(rec, null, 2) + "\n", "utf8");

  if (validate(rec)) {
    console.log(`ok   ${id}`);
  } else {
    const msgs = validate.errors.map(e => `${e.instancePath} ${e.message}`).join("; ");
    console.log(`FAIL ${id}: ${msgs}`);
    failures++;
  }
}

if (failures === 0) {
  console.log(`all ${files.length} processed, 0 failures`);
} else {
  console.log(`${failures} failures`);
}
process.exit(failures > 0 ? 1 : 0);
