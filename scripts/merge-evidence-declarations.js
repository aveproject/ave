// What: merges authoritative evidence declarations from a JSON manifest into all 48 records
// Why:  overrides the script-derived backfill values with curated canonical values
// How:  for each of the 6 evidence fields, applies the JSON value; never touches other fields

"use strict";

const fs   = require("fs");
const path = require("path");
const Ajv  = require("ajv/dist/2020");
const addFormats = require("ajv-formats");

const ajv = new Ajv({ strict: false });
addFormats(ajv);

const SCHEMA   = require("../schema/ave-record-1.0.0.schema.json");
const RECORDS  = path.resolve(__dirname, "../records");
const MANIFEST = require("../docs/migrations/evidence-declarations-all-48.json");
const validate = ajv.compile(SCHEMA);

const EVIDENCE_FIELDS = [
  "detection_layer",
  "detection_stage",
  "evidence_basis_engines",
  "evidence_kind_default",
  "confidence_baseline",
  "derivable_into",
];

let failures = 0;
let updated  = 0;

for (const [id, declarations] of Object.entries(MANIFEST)) {
  const filePath = path.join(RECORDS, `${id}.json`);

  if (!fs.existsSync(filePath)) {
    console.log(`SKIP ${id}: file not found`);
    continue;
  }

  const rec = JSON.parse(fs.readFileSync(filePath, "utf8"));

  for (const field of EVIDENCE_FIELDS) {
    if (field in declarations) {
      rec[field] = declarations[field];
    }
  }

  fs.writeFileSync(filePath, JSON.stringify(rec, null, 2) + "\n", "utf8");

  if (validate(rec)) {
    console.log(`ok   ${id}`);
    updated++;
  } else {
    const msgs = validate.errors.map(e => `${e.instancePath} ${e.message}`).join("; ");
    console.log(`FAIL ${id}: ${msgs}`);
    failures++;
  }
}

console.log(failures === 0
  ? `all ${updated} records merged and valid`
  : `${failures} failures`);
process.exit(failures > 0 ? 1 : 0);
