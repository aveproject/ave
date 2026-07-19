#!/usr/bin/env node
/**
 * build-records.js
 *
 * Reads every AVE record from records/*.json, validates each against the
 * canonical schema, and writes a consolidated JSON array plus a companion
 * manifest. This is the one, canonical consolidation path for AVE's record
 * set -- aveproject/ave owns the data; anything mirroring it (ave-site,
 * ave-api included) should pull the generated output here, not run
 * independent consolidation logic against a second copy of records/.
 *
 * Two output artifacts, the same alias/versioned split schema/ already
 * uses (ave-record.schema.json vs ave-record-1.1.0.schema.json):
 *
 *   dist/ave-records-latest.json       always-current alias, overwritten
 *                                       on every run regardless of schema
 *                                       version. Anything that wants
 *                                       "current" and never wants to touch
 *                                       its own URL again points here.
 *   dist/ave-records-v<version>.json   frozen snapshot, written once per
 *                                       schema version and never rewritten
 *                                       after that -- if the file already
 *                                       exists on disk, this run leaves it
 *                                       alone. The first run after a schema
 *                                       bump creates the new version's
 *                                       snapshot; every run after that is a
 *                                       no-op for that specific file.
 *
 * Each gets its own companion manifest (same basename, .manifest.json).
 *
 * Usage:
 *   node scripts/build-records.js
 *   node scripts/build-records.js --include-drafts
 *   node scripts/build-records.js --dry-run
 *   node scripts/build-records.js --json-out custom.json --manifest-out custom.manifest.json
 *
 * --json-out/--manifest-out override the automatic latest+versioned pair
 * with a single explicit output location (dry-run/testing/custom pipelines);
 * when passed, only that one file is written, not the dual set above.
 *
 * Output shape: a bare JSON array, not wrapped in a window.RECORDS
 * assignment or any other JS-specific framing -- meant for curl/fetch
 * consumption by tools with no reason to run JavaScript.
 *
 * Records with status "draft" are excluded from the build unless the
 * --include-drafts flag is passed.
 *
 * Exit codes:
 *   0  success
 *   1  validation errors found (nothing is written)
 */

const fs   = require("fs");
const path = require("path");

// ── argument parsing ──────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(name);
  return i !== -1 ? args[i + 1] : fallback;
};
const has = (name) => args.includes(name);

const REPO_ROOT      = path.join(__dirname, "..");
const RECORDS_DIR    = flag("--records-dir", path.join(REPO_ROOT, "records"));
const SCHEMA_PATH    = flag("--schema",      path.join(REPO_ROOT, "schema", "ave-record-1.1.0.schema.json"));
const JSON_OUT_ARG   = flag("--json-out",    null);
const MANIFEST_OUT_ARG = flag("--manifest-out", null);
const INCLUDE_DRAFTS   = has("--include-drafts");
const DRY_RUN          = has("--dry-run");
const SKIP_VALIDATION  = has("--skip-validation");

// ── helpers ───────────────────────────────────────────────────────────────────

const log  = (...a) => console.log("[build-records]", ...a);
const warn = (...a) => console.warn("[build-records] WARN", ...a);
const fail = (...a) => { console.error("[build-records] ERROR", ...a); process.exit(1); };

// ── resolve records directory ─────────────────────────────────────────────────

const recordsDir = path.resolve(RECORDS_DIR);
if (!fs.existsSync(recordsDir)) {
  fail(
    `Records directory not found: ${recordsDir}\n` +
    `  Pass --records-dir <path> pointing to the records/ folder.`
  );
}

// ── schema validation ─────────────────────────────────────────────────────────

let validate = null;
const schemaPath = path.resolve(SCHEMA_PATH);
if (!SKIP_VALIDATION) {
  if (!fs.existsSync(schemaPath)) {
    fail(`Schema not found at ${schemaPath}. Pass --schema <path>, or --skip-validation.`);
  }
  try {
    const Ajv = require("ajv/dist/2020");
    const addFormats = require("ajv-formats");
    const ajv = new Ajv({ strict: false });
    addFormats(ajv);
    const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
    validate = ajv.compile(schema);
    log(`Schema loaded: ${schemaPath}`);
  } catch (e) {
    fail(`Could not load schema validator (${e.message}). Run: npm install ajv ajv-formats`);
  }
} else {
  log(`Schema validation SKIPPED (--skip-validation flag set).`);
}

// ── read and parse records ────────────────────────────────────────────────────

const files = fs
  .readdirSync(recordsDir)
  .filter((f) => f.match(/^AVE-\d{4}-\d{5}\.json$/))
  .sort();

if (files.length === 0) {
  fail(`No AVE record files found in: ${recordsDir}`);
}

log(`Found ${files.length} record files.`);

const records  = [];
const errors   = [];
let   skipped  = 0;

for (const file of files) {
  const filePath = path.join(recordsDir, file);
  let record;

  try {
    record = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (e) {
    errors.push(`${file}: JSON parse error — ${e.message}`);
    continue;
  }

  if (record.status === "draft" && !INCLUDE_DRAFTS) {
    log(`  skip  ${file}  (draft)`);
    skipped++;
    continue;
  }

  if (validate) {
    const valid = validate(record);
    if (!valid) {
      const messages = validate.errors
        .map((e) => `    ${e.instancePath || "/"} ${e.message}`)
        .join("\n");
      errors.push(`${file}: schema validation failed\n${messages}`);
      continue;
    }
  }

  records.push(record);
  log(`  ok    ${file}  (${record.severity})`);
}

// ── report errors ─────────────────────────────────────────────────────────────

if (errors.length > 0) {
  console.error("\n[build-records] Validation errors:\n");
  errors.forEach((e) => console.error("  ✗", e));
  console.error(`\n${errors.length} error(s). Nothing was written.`);
  process.exit(1);
}

// ── sort: CRITICAL first, then HIGH, MEDIUM, LOW; then by ave_id ─────────────

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
records.sort((a, b) => {
  const sd = (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4);
  return sd !== 0 ? sd : a.ave_id.localeCompare(b.ave_id);
});

// ── determine schema_version for the manifest ─────────────────────────────────

const schemaVersions = [...new Set(records.map((r) => r.schema_version))];
if (schemaVersions.length > 1) {
  fail(
    `Mixed schema_version values across the consolidated set: ${schemaVersions.join(", ")}\n` +
    `  The manifest needs one unambiguous version. Resolve before building.`
  );
}
const schemaVersion = schemaVersions[0] || "unknown";

// ── build one (json, manifest) output pair ────────────────────────────────────

function buildOutput() {
  const generatedAt = new Date().toISOString();
  const jsonOutput = JSON.stringify(records, null, 2) + "\n";
  const manifest = {
    schema_version: schemaVersion,
    record_count: records.length,
    generated_at: generatedAt,
    source: "https://github.com/aveproject/ave",
  };
  return { jsonOutput, manifestOutput: JSON.stringify(manifest, null, 2) + "\n" };
}

function writePair(jsonPath, manifestPath, { jsonOutput, manifestOutput }) {
  if (DRY_RUN) {
    log(`Dry run — would write ${records.length} records to ${jsonPath}`);
    log(`Dry run — would write manifest to ${manifestPath}`);
    log(`Output size: ${(jsonOutput.length / 1024).toFixed(1)} KB`);
    return;
  }
  for (const outPath of [jsonPath, manifestPath]) {
    const outDir = path.dirname(outPath);
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  }
  fs.writeFileSync(jsonPath, jsonOutput, "utf8");
  fs.writeFileSync(manifestPath, manifestOutput, "utf8");
  log(`Written: ${jsonPath}`);
  log(`Written: ${manifestPath}`);
}

// ── write ─────────────────────────────────────────────────────────────────────

if (JSON_OUT_ARG || MANIFEST_OUT_ARG) {
  // explicit override: single output pair, no latest/versioned split
  const jsonOutPath     = path.resolve(JSON_OUT_ARG     || path.join(REPO_ROOT, "dist", `ave-records-v${schemaVersion}.json`));
  const manifestOutPath = path.resolve(MANIFEST_OUT_ARG || path.join(REPO_ROOT, "dist", `ave-records-v${schemaVersion}.manifest.json`));
  writePair(jsonOutPath, manifestOutPath, buildOutput());
} else {
  const distDir = path.join(REPO_ROOT, "dist");

  // always-current alias: overwritten every run
  const latestJsonPath     = path.join(distDir, "ave-records-latest.json");
  const latestManifestPath = path.join(distDir, "ave-records-latest.manifest.json");
  writePair(latestJsonPath, latestManifestPath, buildOutput());

  // frozen versioned snapshot: written once per schema version, never again
  const versionedJsonPath     = path.join(distDir, `ave-records-v${schemaVersion}.json`);
  const versionedManifestPath = path.join(distDir, `ave-records-v${schemaVersion}.manifest.json`);
  if (fs.existsSync(versionedJsonPath)) {
    log(`Frozen snapshot already exists, left untouched: ${versionedJsonPath}`);
  } else {
    writePair(versionedJsonPath, versionedManifestPath, buildOutput());
  }
}

log(`Records: ${records.length}  |  Skipped drafts: ${skipped}`);
