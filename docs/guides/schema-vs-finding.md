# AVE Schema vs Finding Output — what issues #69-72 change

## Two different artifacts

The to_dict() you pasted is the SCANNER FINDING output — produced at scan time,
one per detection, references an AVE record by ave_id.

The AVE RECORD is the static vulnerability DEFINITION — authored once, lives in
bawbel/ave, many findings point to it. Different schema, different lifecycle.

```
AVE Record (static definition)          Finding (runtime instance)
─────────────────────────────          ──────────────────────────
authored by a human                     produced by a scan
one per vulnerability class             one per detection
lives in bawbel/ave/records/            lives in scan output JSON
referenced by ave_id                    references an AVE record
changes rarely (new research)           changes every scan
```

## What issues #69-72 mean for the Finding output (already done)

Your pasted to_dict() is correct. confidence, confidence_band, evidence_stage,
evidence_kind, evidence_basis, confidence_reason, derived are all there.
That closes #69 for the Finding.

## What issues #69-72 mean for the AVE RECORD schema (the adjustment)

The AVE record needs fields that let the scanner ASSIGN evidence metadata
correctly. The record does not carry confidence — confidence is per-detection.
But the record should declare:

### 1. evidence_kind_default (from #69)
What kind of evidence typically detects this AVE.
The scanner uses this as the default evidence_kind on findings.

```json
"evidence_kind_default": "tool_description_pattern"
```

Values: tool_description_pattern | config_schema | file_type_mismatch |
behavioral_pattern | semantic_inference | multi_engine

### 2. detection_stage (from #71 lifecycle)
The earliest lifecycle stage where this AVE can be detected.
Some AVEs are static-only. Some require runtime observation.

```json
"detection_stage": "static_detection"
```

Values: static_detection | runtime_observed | runtime_drift_detected
This tells downstream tools whether a static scan can fully assess this AVE
or whether runtime observation (Phase 4 bawbel-hook) is required.

### 3. confidence_baseline (from #69)
The base confidence a single-engine match on this AVE deserves, before
FP pipeline adjustment. Some AVEs are high-signal (a hardcoded AWS key);
some are low-signal and need corroboration (a vague instruction phrase).

```json
"confidence_baseline": 0.85
```

### 4. derivable_into (from #70 toxic flows)
Which toxic flow chains this AVE can participate in. Makes the chain
derivation explicit and testable against golden fixtures.

```json
"derivable_into": ["credential-exfiltration", "data-exfil-chain"]
```

### 5. evidence_basis_engines (from #69)
Which engines can detect this AVE. Used to populate evidence_basis and to
validate that the record has at least one working rule.

```json
"evidence_basis_engines": ["pattern", "semgrep", "yara"]
```

## What stays OUT of the AVE record

Do NOT add these to the AVE record — they are per-detection, not per-definition:
- confidence (varies per scan)
- confidence_band (derived from confidence)
- evidence_stage (the actual stage THIS finding reached)
- confidence_reason (specific to one detection)
- derived (a finding property, not a definition property)
- line, match (location of one detection)

## Trust model note (from #72)

Issue #72 is about registry/ecosystem trust as an evidence layer.
The AVE record should NOT try to model registry trust — that is runtime,
per-server, per-scan state. The AVE record is the static definition.
Registry trust vocabulary belongs in the scanner's runtime layer (Phase 4),
not in the AVE record schema.

The one AVE record addition for #72: a field declaring whether this AVE
is detectable at the registry/metadata layer vs only at the content layer.

```json
"detection_layer": "content"
```

Values: content | server_card | registry_metadata | runtime
