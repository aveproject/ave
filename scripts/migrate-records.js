// What: migrates all AVE records from schema_version 0.2.0 to 1.0.0
// Why:  0.2.0 records are missing required top-level fields; references are plain strings
// How:  reads each AVE-*.json, applies transforms in order, validates, writes in-place

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

function migrate(r) {
  // a. schema_version
  r.schema_version = "1.0.0";

  // b. severity — promote from aivss.aivss_severity if missing at top level
  if (!r.severity && r.aivss && r.aivss.aivss_severity) {
    r.severity = r.aivss.aivss_severity;
  }

  // c. aivss_score — promote from aivss.aivss_score if missing at top level
  if (r.aivss_score === undefined && r.aivss && r.aivss.aivss_score !== undefined) {
    r.aivss_score = r.aivss.aivss_score;
  }

  // d. status
  if (!r.status) r.status = "active";

  // e. published
  if (!r.published) r.published = "2026-04-14T09:00:00Z";

  // f. researcher
  if (!r.researcher) r.researcher = "Bawbel Security Research Team";

  // g. researcher_url
  if (!r.researcher_url) r.researcher_url = "https://bawbel.io";

  // h. references — convert plain strings to {tag, text, url} objects
  if (Array.isArray(r.references)) {
    r.references = r.references.map(ref => {
      if (typeof ref === "string") {
        return { tag: "Reference", text: ref, url: ref };
      }
      return ref;
    });
  }

  // i. owasp_mcp — copy from aivss.owasp_mcp_mapping if missing at top level
  if (!r.owasp_mcp && r.aivss && r.aivss.owasp_mcp_mapping) {
    r.owasp_mcp = r.aivss.owasp_mcp_mapping;
  }

  // j. normalise stale 0.2.0 component_type values
  const COMPONENT_TYPE_MAP = {
    "mcp":             "mcp_server",
    "mcp-server-card": "mcp_server",
    "rag":             "other",
    // "prompt" and "skill" are now valid enum values — keep as-is
  };
  if (r.component_type && COMPONENT_TYPE_MAP[r.component_type]) {
    r.component_type = COMPONENT_TYPE_MAP[r.component_type];
  }

  return r;
}

const files = fs.readdirSync(RECORDS)
  .filter(f => f.endsWith(".json"))
  .sort();

let failures = 0;

for (const f of files) {
  const filePath = path.join(RECORDS, f);
  let rec;
  try {
    rec = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (e) {
    console.log(`FAIL ${f.replace(".json","")}: parse error — ${e.message}`);
    failures++;
    continue;
  }

  migrate(rec);

  fs.writeFileSync(filePath, JSON.stringify(rec, null, 2) + "\n", "utf8");

  const valid = validate(rec);
  if (valid) {
    console.log(`ok   ${rec.ave_id}`);
  } else {
    const msgs = validate.errors.map(e => `${e.instancePath} ${e.message}`).join("; ");
    console.log(`FAIL ${rec.ave_id}: ${msgs}`);
    failures++;
  }
}

const total = files.length;
if (failures === 0) {
  console.log(`all ${total} valid`);
} else {
  console.log(`${failures} of ${total} failed`);
}

process.exit(failures > 0 ? 1 : 0);
