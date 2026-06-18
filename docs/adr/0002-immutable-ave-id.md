# ADR-0002: ave_id is immutable

Status: Accepted
Date: 2026-04-20

## Decision

Once an AVE record is published, its ave_id never changes. A wrong or
obsolete record is deprecated (status field), never renumbered or deleted.

## Consequences

Positive: every Finding that references an ave_id stays valid forever.
Positive: PiranhaDB and the scanner can cache records safely.
Negative: mistakes are permanent in the numbering. Deprecate, do not delete.
