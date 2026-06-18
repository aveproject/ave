# ADR-0003: Records declare evidence baselines, scanner assigns actuals

Status: Accepted
Date: 2026-06-05
Issues: #69, #70, #71, #72

## Context

The PFEM review (lightrock) asked for first-class confidence/evidence
metadata. The question arose: should AVE records carry confidence?

## Decision

No. confidence is per-detection and lives only on the scanner Finding.
The AVE record declares baselines and defaults that the scanner uses to
assign per-finding values:

- confidence_baseline    → starting confidence for a Finding (#69)
- evidence_kind_default  → default Finding.evidence_kind (#69)
- detection_stage        → floor for Finding.evidence_stage (#71)
- detection_layer        → where the AVE surfaces (#72)
- evidence_basis_engines → engines that can detect it (#69)
- derivable_into         → toxic flow chains it joins (#70)

## Consequences

Positive: clean separation. The record is static; the finding is dynamic.
Positive: the scanner can adjust confidence per scan without touching records.
Negative: two schemas to keep aligned (record schema + finding output).
The alignment is enforced by golden fixtures in the scanner repo.
