# GOVERNANCE.md — aveproject/ave

## Project lead

Saray CHAK (chaksaray), founder of Bawbel. Sole maintainer as of v1.1.0.

---

## Decision making

**New AVE records:** proposed via GitHub issue, reviewed by maintainer for distinct
behavioral class + citable primary source, merged only after passing schema validation
and having positive + negative detection fixtures.

**Schema changes:** discussed in issues before implementation. Breaking changes (field
removal, required field addition) require a new schema version and a migration script.
Minor additions (new optional fields) are non-breaking and can ship in a patch release.

**Deprecation:** a record is deprecated by setting `status` to `"deprecated"` with a
`deprecation_reason`. `ave_id` values are never reused or deleted.

**Crosswalk updates:** maintainer or contributors may update crosswalk JSON files to
add new tool mappings. No record changes required.

---

## Contribution process

1. Open an issue before writing JSON
2. Maintainer confirms the id and whether it is a new class or a variant
3. PR must include: record JSON, at least one detection rule (pattern/yara/semgrep),
   positive fixture, negative fixture
4. All must pass: schema validation, pytest fixtures, check_rule_coverage, check_fixtures
5. Coordinated PR in bawbel/scanner references the ave PR

See CONTRIBUTING.md for the full contributor-facing process.

---

## Governance path

AVE is moving toward neutral governance under an independent standards body. The
current path is engagement with the OWASP community and the MITRE CWE AI Working
Group. No timeline is committed. When a second maintainer from outside Bawbel is
established, this document will be updated to reflect shared decision-making.

---

## Code of conduct

AVE follows the Contributor Covenant v2.1. See CODE_OF_CONDUCT.md.
