# cfgaudit → AVE crosswalk

[cfgaudit](https://github.com/cfgaudit/cfgaudit) is a static auditor of committable AI-agent **configuration files** (Claude Code `settings.json` / `CLAUDE.md` / `.mcp.json` / hooks / plugins, and the cross-agent equivalents: Cursor, Copilot, Gemini, Codex, Devin, Zed, Continue). It does not connect to running servers or observe runtime, so it maps only to AVE's `static_detection` records.

cfgaudit emits each rule's primary AVE id in its JSON and SARIF output (`AVEID` in JSON; `properties.ave_id` in SARIF). This crosswalk is the source of truth that mapping is kept in sync with. Full write-up: [`docs/cfgaudit-to-ave.md`](https://github.com/cfgaudit/cfgaudit/blob/main/docs/cfgaudit-to-ave.md).

## Versions

| | Version |
|---|---|
| cfgaudit | 1.13.0, read at `ac9f2a5` |
| AVE record set | 80 records (AVE-2026-00001 .. 00080), read at `1d1d197` |
| Bawbel Scanner (validation, below) | 1.3.0 |

## Coverage

cfgaudit has **108 rules** in total. **64 of them map onto 27 AVE behavioral classes**, up from the 53 onto 23 this file carried at v1.11.0. It is a many-to-one mapping: several cfgaudit rules land on the same AVE class, because cfgaudit slices threats by config surface where AVE slices by behavior. For example, cfgaudit has five distinct secret-detection rules (a secret in `settings.json` env, in an MCP `env`/`headers` block, an entropy fallback, a Continue inline `apiKey`, a crypto signing key), and all five map to the single AVE class `AVE-2026-00047` (hardcoded credentials in component).

The other 44 rules have no AVE class: they check config surfaces AVE's skill and MCP-server records do not enumerate (see "Config surfaces beyond AVE's model" below).

**This revision spans two cfgaudit releases,** v1.12.0 and v1.13.0, because the v1.12.0 refresh was still open when v1.13.0 shipped. Eleven rule-to-class pairs are new and four classes are new to this file. Seven of the eleven are rules that existed all along, mapped here for the first time because `AVE-2026-00071`, `00072`, `00073` and `00076` were published after the v1.11.0 crosswalk was generated; three of those four came out of this crosswalk's own gap list ([#68](https://github.com/aveproject/ave/issues/68)). The record set has since grown to 80, but `AVE-2026-00078` through `AVE-2026-00080` are `runtime_observed` and `runtime_drift_detected`, so they give no static rule a home.

**Five rules are left unmapped on purpose.** `CFG100`, `CFG101` and `CFG102` from v1.12.0, and `CFG106` plus the other two findings of `CFG103` from v1.13.0. In each case the nearest class is wrong on a stated detail; reasons are under "Config surfaces beyond AVE's model".

**Both sides are pinned by commit**, so the counts can be re-derived. The cfgaudit tree read is the `v1.13.0` tag itself.

## Rule mapping

| cfgaudit rule(s) | AVE id | Class | Notes |
|---|---|---|---|
| CFG024 | AVE-2026-00029 | homoglyph / Unicode obfuscation | hidden Unicode control chars in instruction text |
| CFG026 | AVE-2026-00007 | goal hijack | override / persona / authority instruction |
| CFG092 | AVE-2026-00007 | goal hijack | Kimi agent file `override: true` replaces the whole system prompt |
| CFG029 | AVE-2026-00021 | autonomous action without confirmation | instruction to bypass permission prompts |
| CFG030 | AVE-2026-00010 | covert instruction concealment | "don't tell the user" / secrecy directive |
| CFG032 | AVE-2026-00025 | conversation-history / role injection | pseudo-system tags, turn-boundary injection |
| CFG035 | AVE-2026-00011 | dynamic tool-call injection | instruction to configure or trust an MCP server |
| CFG031, CFG036, CFG037, CFG038 | AVE-2026-00003 | credential exfiltration | sensitive-path read, env dump, embedded exfil shell |
| CFG033, CFG072 | AVE-2026-00039 | covert-channel exfiltration | markdown-image sink, DNS-name exfil |
| CFG056 | AVE-2026-00058 | deceptive trigger / activation-scope | broad always-on skill trigger |
| CFG057 | AVE-2026-00057 | obfuscated / encoded payload | base64 or data-URI encoded injection |
| CFG081 | AVE-2026-00027 | multi-turn instruction persistence | "survive context compaction" directive |
| CFG051, CFG085 | AVE-2026-00048 | unsafe agent delegation chain | over-broad tool grant in agent frontmatter |
| CFG090 | AVE-2026-00032 | network reconnaissance instruction | scan or enumerate an internal network (see gaps re: precision) |
| CFG008, CFG014 | AVE-2026-00004 | shell-pipe code execution | reverse shell, `curl \| sh` |
| CFG039 | AVE-2026-00005 | recursive filesystem destruction | `rm -rf` |
| CFG027, CFG028 | AVE-2026-00008 | persistence / self-replication | cron/startup persistence, writing trust files |
| CFG007, CFG050, CFG054, CFG065, CFG073, CFG097 | AVE-2026-00047 | hardcoded credentials in component | secrets in settings or MCP env/headers; CFG097 adds a literal in a Gemini remote agent's `auth` block |
| CFG052, CFG059 | AVE-2026-00017 | server impersonation / spoofing | MCP name shadowing, typosquat |
| CFG019, CFG020, CFG070 | AVE-2026-00055 | command exec via untrusted MCP launch config | inline-script, env-code, repo-relative launcher |
| CFG075 | AVE-2026-00061 | TLS verification disabled in config | `NODE_TLS_REJECT_UNAUTHORIZED=0`, `GIT_SSL_NO_VERIFY`, `--insecure` in MCP `env`/`args` |
| CFG010, CFG055, CFG074, CFG089, CFG098 | AVE-2026-00062 | unpinned dependency / supply-chain substitution | unpinned `@latest`/`:latest`, `skills-lock.json` with no integrity pin, marketplace source without a full-SHA pin; CFG098 adds a `marketplace.json` archive source with no `sha256` and an npm source at a non-default registry |
| CFG003, CFG004, CFG048, CFG053, CFG063, CFG079, CFG087, CFG091, CFG093, CFG096, CFG104, CFG105 | AVE-2026-00063 | approval gate bypassed by declarative config | `enableAllProjectMcpServers`, `defaultMode: bypassPermissions`, VS Code `chat.permissions.default`, blanket MCP-trust keys, Codex `approval_policy`/`approvals_reviewer`, `autoMode` classifier, a hook answering a permission gate, qwen `approvalMode: yolo`, Cursor allowlists, Gemini MCP `trust`, Devin `permissions.allow`, OpenCode `permission` |
| CFG047, CFG067, CFG086 | AVE-2026-00064 | zero-click project-load auto-run | `.vscode/tasks.json` `runOn: folderOpen` and Zed `create_worktree` hook tasks, committed project hooks, zero-click hook events |
| CFG082 | AVE-2026-00071 | container daemon redirected off-host | `DOCKER_HOST` in a `settings.json` or MCP `env`, or `docker -H` in a command site, naming a remote `tcp://`/`ssh://` daemon |
| CFG018 | AVE-2026-00072 | MCP server bound to every interface, no auth step | bind address `0.0.0.0` or `[::]` in an MCP server's `args`/`env`, which the record also calls NeighborJack |
| CFG005, CFG046, CFG071, CFG099 | AVE-2026-00073 | endpoint redirect via a static config value | `ANTHROPIC_BASE_URL` off Anthropic (CVE-2026-21852), `OTEL_EXPORTER_OTLP_*ENDPOINT` to a non-local collector, a model or provider base URL over cleartext `http://`, qwen top-level `proxy` |
| CFG094, CFG103 | AVE-2026-00076 | natural-language steering of an approval classifier | Cursor `.cursor/permissions.json` `autoRun.allow_instructions`; Codex `features.guardianv2.classifier_instructions`, which replaces the reviewer's prompt outright (that finding of CFG103 only) |

Mappings are class-level behavioral equivalence, not asserted identity. Where a cfgaudit rule covers more than one AVE class, only the canonical primary is emitted (matching AVE's one-`ruleId`-per-class SARIF model); the full multi-mapping is in cfgaudit's own crosswalk doc.

## Config surfaces beyond AVE's model

AVE's records enumerate behavior in skills and MCP servers. cfgaudit additionally audits config-file classes that carry no corresponding AVE behavioral class today.

Seven of the eight surfaces listed here at v1.10.0 have since been closed by AVE records: permission/approval config and the committed-hook auto-approve case by `AVE-2026-00063`, zero-click auto-run by `AVE-2026-00064`, TLS verification disabled by `AVE-2026-00061`, supply-chain pinning by `AVE-2026-00062`, container/daemon posture by `AVE-2026-00071`, MCP network posture by `AVE-2026-00072`, and telemetry/endpoint redirect by `AVE-2026-00073`. The natural-language-steering surface added in the last revision was closed by `AVE-2026-00076` in the same window. What remains:

| Config surface | Example files / keys | Example rules | Status |
|---|---|---|---|
| Sandbox weakening in config | four mechanisms, listed below | CFG022, CFG061, CFG064, CFG079, CFG095 | **the one still open** |
| Cleartext endpoint, distinct from TLS verification disabled | a committed `http://` MCP server URL, an A2A `agent_card_url` | CFG049, CFG097 | mostly closed by `AVE-2026-00073`, two fields reached only by its catch-all |
| Plugin auto-load from a committed manifest | Grok `[plugins]` `enabled` / `paths` | CFG100 | unmapped on purpose, see below |
| A guardrail that does not hold | a `deny` pattern walked past by flag reordering | CFG101 | probably outside AVE's model by construction |
| Two committed skills claiming one name | two `SKILL.md` files, load order decides | CFG102 | no class fits without stretching one |
| An **automated** security reviewer switched off or blunted | Codex `[features.guardianv2]` `enabled`, `review_threshold` | CFG103 | new gap: `AVE-2026-00063` is a bypassed **human**-approval step |
| Repository grants browser or desktop-application access | Codex `[browser_use]` `full_cdp_access`, `[computer_use]` app access | CFG106 | new gap, and not filed under `AVE-2026-00063` on purpose |

### Sandbox weakening, the one surface still open

This is the last of the eight, and the reason it is still open is that the field list was in motion when it was last picked up ([#68](https://github.com/aveproject/ave/issues/68)). **It has since settled.** CFG064 reached its current shape in v1.12.0 and nothing further is queued against it. The mechanisms, which are four rather than one:

1. **The sandbox switched off outright.** Codex `sandbox_mode = "danger-full-access"`, Cursor `type: "insecure_none"`, Claude Code `sandbox.filesystem.disabled: true`.
2. **The sandbox left on but widened.** Codex `[sandbox_workspace_write]` `network_access = true` and `writable_roots` reaching outside the workspace; Gemini `tools.sandboxAllowedPaths` exposing `/` or `~`, and `tools.sandboxNetworkAccess: true`.
3. **The confinement helpers repointed.** Claude Code `sandbox.bwrapPath` and `sandbox.socatPath` (honored only from managed settings, so anomalous anywhere else), `sandbox.excludedCommands` carrying a wildcard or a shell, `sandbox.network.allowUnixSockets` naming a privileged daemon socket such as `docker.sock`, `sandbox.filesystem.allowWrite` on `$PATH` or a shell rc file.
4. **The same posture reached without touching a sandbox key at all.** Codex's named permission profiles: `default_permissions` selects a `[permissions.<name>]` profile whose `network` block carries `enabled`, `proxy_url`, `socks_url`, `dangerously_allow_all_unix_sockets` and `dangerously_allow_non_loopback_proxy`, and whose `filesystem` block can grant `":root"` or a credential path. `extends` genuinely inherits, so a profile cannot be judged from its own table. An indicator list keyed on `sandbox_mode` misses this fourth mechanism entirely.

**Is "widened" a different class from "off"?** Earlier read was maybe. After building it: no. Both are the same check, read a declared value and compare it to the default. The difference is blast radius, not kind. Mechanism 4 is the one that is genuinely different, because it reaches the same posture through a key with no "sandbox" in the name.

**The hardening-not-weakening trap, extended.** Beyond `disableTmpWrite`, `exclude_tmpdir_env_var` and `exclude_slash_tmp`, three more instances turned up while building v1.12.0, all measured: Grok's `[plugins] disabled` (naming a plugin to discover but not activate hardens); qwen's `memory.autoSkillConfirm`, whose default is **true**, so the weakening value there is `false`, the inverse of every `disable*` key; and Codex's profile `filesystem` block, where across 69 real `.codex/config.toml` files the decisions are `deny` 177, `write` 72, `read` 53, `none` 51, so the block's presence is overwhelmingly hardening and only a granting direction on a sensitive target is a finding. One more for an `indicators_of_compromise` list: a read grant on `~/.ssh/id_ed25519.pub` is not credential exposure, and a real profile in that corpus carries exactly that.

### The two new gaps

**An automated reviewer switched off by config.** Codex's `[features.guardianv2]` decides whether its own security reviewer runs (`enabled`), at what score it escalates to a blocking review (`review_threshold`, default `0.5`, a number the reviewer's own prompt states), and what prompt it is given (`classifier_instructions`). The prompt half is `AVE-2026-00076` and is mapped above. The other two are not: `AVE-2026-00063` is explicitly a bypassed *human*-approval step, and Guardian v2 is an automated reviewer. `features` is not on Codex's project-layer denylist, so a committed `.codex/config.toml` sets all three; verified against codex `0.150.0-alpha.7` by reading the effective config back through its app server in a trusted directory, with a denylisted key and an ordinary key as controls.

**A repository granting browser or desktop access.** Codex's `[browser_use]` grants per-origin `access`, `downloads`, `uploads` and `full_cdp_access` (full Chrome DevTools Protocol, so script execution plus cookie and storage access inside the browser session), and `[computer_use]` grants control of desktop applications by bundle id, AUMID or executable. The value type is an enum of exactly `allow` and `deny`, so there is no ask state and `allow` is unambiguously the weakening direction. This is deliberately **not** filed under `AVE-2026-00063`: whether a prompt is skipped is unverified, because the value is observable in the effective config but the tools themselves live in the client app. Filing it there would assert more than the detection does.

### The three deliberately unmapped rules

- **CFG100**, Grok `[plugins]`. `AVE-2026-00064` would be the class, but it requires the loader to run plugin code at project load with no prompt. That is not verified against the shipped Grok build, so mapping it would assert a mechanism nobody measured.
- **CFG101**, a deny rule walked past by flag reordering. Claude Code matches a `Bash(...)` pattern as a literal prefix, so `Bash(rm -rf *)` never covered `rm -fr x`. Measured against Claude Code 2.1.231; about 44% of 22,016 indexed `settings.json` files with a `deny` block leave the gap open. `AVE-2026-00063` is a flag that removes a gate, `AVE-2026-00068` is composition through shell state. Neither is "the denylist misses an equivalent spelling". This is an ineffective control, not an attacker behavior, so it may be outside AVE's scope.
- **CFG102**, two committed skills claiming one name. `AVE-2026-00017` is the closest class but is explicitly MCP server identity, and `AVE-2026-00066` is registry squatting on hallucinated names. Neither covers two local files where load order decides which body runs.

These are not gaps in this crosswalk. They are config classes outside AVE's current skill/MCP scope, listed so coverage stays visible in both directions.

## Cross-implementation validation (cfgaudit vs Bawbel Scanner)

To test whether the shared ids actually interoperate, cfgaudit **1.9.0** and [Bawbel Scanner](https://github.com/bawbel/scanner) **1.3.0**, which share no code and no ruleset and only the AVE taxonomy, were run on the same `SKILL.md` files using cfgaudit's canonical trigger text unmodified (not tuned for agreement). Static engines only (`pattern`+`yara`+`semgrep`, no LLM), both reading `ave_id` from JSON.

Of the 33 AVE-mapped rules cfgaudit had at that version, **10 instruction/skill-content rules share a scan surface with Bawbel's file scan** (the other 23 read command sites or config files Bawbel's file scan does not cover). Of those 10:

**Both scanners independently emit the same `ave_id` on 5 of the 10.**

| Rule | AVE | cfgaudit | Bawbel | |
|---|---|---|---|---|
| CFG024 | 00029 | yes | yes | agree |
| CFG026 | 00007 | yes | yes (+00002) | agree |
| CFG029 | 00021 | yes | yes | agree |
| CFG030 | 00010 | yes | yes (+00003) | agree |
| CFG090 | 00032 | yes | yes | agree |
| CFG031 | 00003 | yes | no | detection differs |
| CFG035 | 00011 | yes | no | detection differs |
| CFG036 | 00003 | yes | no | detection differs |
| CFG057 | 00057 | yes | no | detection differs |
| CFG081 | 00027 | yes | no | detection differs |

The 5 agreements are cross-implementation corroboration of the mapping. The 5 divergences are detection-pattern differences, not mapping errors: Bawbel bundles a rule for each class, but its pattern did not match cfgaudit's canonical trigger. For CFG036, for instance, Bawbel reports the `curl …?d=$(cat ~/.aws/credentials)` skill CLEAN while cfgaudit flags it. A shared id makes exactly these coverage differences visible and comparable, which is the point.

## Gaps

Static `static_detection` classes cfgaudit does not map, with the reason:

| AVE id | Gap |
|---|---|
| AVE-2026-00015 | system-prompt extraction. Maps to OWASP LLM07, which cfgaudit treats as runtime; the instruction is static, but the scope boundary is undecided. |
| AVE-2026-00036 | lateral movement. cfgaudit implemented and then reverted this rule after a false-positive analysis over 422 real instruction files: the vocabulary (`lateral movement`, `pivot to other systems`) is statically indistinguishable from security-tool self-description and defensive contexts. The reverted rule used the CFG091 id, which cfgaudit has since reused for the qwen approval-mode rule (mapped to AVE-2026-00021). |
| AVE-2026-00059 | fragmented cross-description injection. Needs multi-source correlation; cfgaudit checks each file in isolation, which is the exact property this attack defeats. |
| AVE-2026-00060 | STDIO transport shell injection. A server-side implementation flaw: it needs SAST of the MCP server's source, not a read of its launch configuration. Same layer as AVE-2026-00052 and AVE-2026-00053. |
| AVE-2026-00065 | A2A agent card poisoning. cfgaudit reaches the committed pointer but not the card. A `.gemini/agents/*.md` may carry an inline `agent_card_json`, which cfgaudit recognises well enough to classify the file as a remote agent, but it does not audit the card's contents. It does flag a cleartext `agent_card_url` and a credential literal in the same file's `auth` block (CFG097). |
| AVE-2026-00069 | Image-hidden instructions in a skill package. Needs binary content analysis of a bundled image; cfgaudit reads text configuration only. Same layer as AVE-2026-00024. |
| AVE-2026-00077 | Cross-origin tool and resource declaration in one MCP manifest. New gap. cfgaudit reads MCP *launch* configuration (`command`, `args`, `env`, `url`, `headers`), not the manifest a server returns once it is running, so the two declarations this record correlates are never both in view. |
