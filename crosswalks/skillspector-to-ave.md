# SkillSpector to AVE crosswalk

**Source:** NVIDIA SkillSpector 2.13.1 (tag `v2.13.1`, commit `f3b25697d76256998ca9d42c198d256258d4c035`), read from source: 78 rules in 18 categories, plus 37 rule ids emitted outside the category map
**Target:** AVE 1.1.0, 89 records (61 `static_detection`), read at `a3661ae1541b6542a7b5094500d62efcaa54c152`
**Generated:** 2026-10-26
**Source URL:** https://github.com/NVIDIA/SkillSpector
**Pin:** the newest release tag, not the default branch: at the time of reading, the default branch HEAD (`d7338f58200a9ae2a24810cee08911ab68b107a7`) still reported version 2.12.0.

This is an independent reading of SkillSpector. It is not endorsed by or affiliated with NVIDIA. Mappings are class-level equivalence, not identity, and a hit on a `related` rule is a lead, not an instance of the AVE class. Machine-readable version: [skillspector-to-ave.json](skillspector-to-ave.json).

## What changed

Full rewrite from source. The previous revision (generated 2026-07-12, last checked against documentation on 2026-06-21) mapped 16 category names against SkillSpector 2.0.0's documentation and said it had not been re-checked against the source; SkillSpector has no v2.0.0 tag, and its earliest tag is v2.5.0. Changes: category keys are now SkillSpector's own category strings (18 instead of 16); dangerous_code_ast and taint_tracking no longer exist as categories (the AST rules are emitted outside the category map, and TT1 to TT6 sit under Data Exfiltration, Privilege Escalation and Insecure Deserialization); every rule has its own entry with a relationship; mappings to runtime_observed records (AVE-2026-00018, 00019, 00050) were dropped; 21 of the previous 41 category-to-record links did not survive and are listed under dropped_from_previous_revision; the previous conclusion that YARA matches are only known malware was reversed, because the built-in agent_skills.yar rules are behavioral; the previous gaps for trigger_abuse and mcp_least_privilege were re-stated rule by rule. The file does not round-trip through the previous formatting, so the diff is a full rewrite.

## The three counts

| | Rules | Categories |
|---|---|---|
| Code (`RULE_ID_TO_CATEGORY` at `v2.13.1`), source of truth | 78 | 18 |
| README headline | 71 | 17 |
| README tables (rows, headings) | 73 | 17 |
| Previous crosswalk (SkillSpector 2.0.0 documentation) | 64 | 16 |

The README tables give Behavioral AST (AST1 to AST9) and Taint Tracking (TT1 to TT5) headings of their own, and omit 14 in-map rules the code has (AS1, AS2, AS3, DS1, DS2, DS3, DS4, E5, SC7, SSRF1, SSRF2, SSRF3, TM4, TT6). The code groups the taint rules under Data Exfiltration, Privilege Escalation and Insecure Deserialization, and emits the AST rules without a category.

## Scope

- **Static AVE records only.** SkillSpector scans files statically. Of 89 AVE records, 61 are `static_detection` and are the only mapping targets. The 26 `runtime_observed` and 2 `runtime_drift_detected` records are listed under *Out of scope* below.
- **In-map rules (78):** the catalogue. Each appears exactly once in the category tables.
- **Rules outside the category map (37):** `AST1` to `AST10`, `BH1` to `BH4`, `RP1` to `RP3`, `PE4`, `PE5`, `AE1` to `AE7` and the LLM ids `SSD-1` to `SSD-4`, `SDI-1` to `SDI-4`, `SQP-1` to `SQP-3`. They are real findings a scan can emit, so they are mapped the same way, in their own table.
- **LLM dependence.** 12 rules need an LLM and do not fire under `--no-llm`: TP4 (inside the map) and SDI-1, SDI-2, SDI-3, SDI-4, SQP-1, SQP-2, SQP-3, SSD-1, SSD-2, SSD-3, SSD-4. SC4 is deterministic but queries OSV.dev. Every other rule is a deterministic regex, AST, filesystem or YARA check. An optional LLM meta-analysis can also filter and enrich findings; it is not modelled here.
- **Not measured.** Only what each rule is designed to match was read, not how well it does.

## How to read the relationship

- **equivalent** (13 rules): Same behavior on the same surface: the AVE record's own description and indicators cover what the rule matches.
- **narrower** (3 rules): The AVE class is a specific instance of what the rule flags: every instance of the class would trip the rule, but the rule also fires on things that are not the class.
- **broader** (0 rules): The AVE class contains what the rule flags as one instance, and more. Not used in this revision.
- **related** (64 rules): Shares one dimension (object, trigger or outcome) without either containing the other, or the surface differs. A hit is a lead, not an instance of the AVE class.
- **no_fit** (35 rules): No static AVE class matches.
- With several ave_ids the relationship is stated against the first; the others are secondary links explained in the notes.
- **detection**: static: deterministic regex, AST, filesystem or YARA check. static+network: deterministic but queries OSV.dev. llm: depends on an LLM and is absent from a scan run with --no-llm.

## Category mapping

### Prompt Injection (6 rules)

Instruction overrides, hidden directives, exfiltration commands, behavior steering, whitespace padding, harmful content in skill text. P1 is the cleanest match (AVE-2026-00007). P2 and P9 are concealment techniques that overlap AVE-2026-00029; P3 and P4 are partial; P5 has no AVE class.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| P1 | Override Instructions | static | equivalent | 00007, 00009 | Regexes over any file body for instruction-override phrasing: 'ignore previous instructions', 'override safety', 'bypass security', 'forget your instructions', 'your new instructions are', 'you are now in jailbreak/unrestricted mode', 'enable developer mode'. This is the phrasing AVE-2026-00007 lists as its indicators. The jailbreak-mode and developer-mode patterns also fall under AVE-2026-00009. |
| P2 | Hidden Instructions | static | related | 00029 | Hiding techniques: HTML and '[//]: #' comments containing instruction keywords, zero-width characters and 'data:text/plain;base64' URIs (markdown, perl and other file types only), plus Unicode Tag characters and bidirectional controls in every file type. The character-level techniques are AVE-2026-00029's mechanism. Comment-based hiding and data URIs have no AVE class: AVE-2026-00010 is a secrecy directive in plain text, not concealment by markup. |
| P3 | External Transmission Instructions | static | related | 00013, 00003 | Prose regexes for instructions to send the conversation, context, history or 'all user data' to an external destination, plus 'silently' or 'secretly' send. The object is conversation context or user data, which no AVE exfiltration record names: AVE-2026-00013 is PII fields and AVE-2026-00003 is credentials. Shares the instruct-then-transmit shape. |
| P4 | Subtle Steering | static | related | 00010 | Prose regexes for behavior steering: 'always recommend X over Y', 'subtly steer the user', 'gain the user's trust and then', 'append this to every response', and 'never mention, tell or warn the user'. Only the last pattern overlaps an AVE class (the secrecy directive of AVE-2026-00010); the rest is bias and manipulation of output, which no static AVE record describes. |
| P5 | Harmful Content | static | no_fit | none | Word lists and phrases for physical-harm content (poisons, bomb making, self-harm), severity CRITICAL. A content-safety check, not an agent behavior class. |
| P9 | Whitespace Padding | static | related | 00029 | Large blank-line blocks and long space runs that push injected text out of the visible area, in file bodies and in manifest description fields (the tool-poisoning analyzer also emits P9). Same aim as AVE-2026-00029, instructions a human reviewer cannot see but the model reads, reached by layout instead of Unicode characters. |

### System Prompt Leakage (3 rules)

Direct and indirect system prompt extraction and exfiltration by instruction. One AVE record, AVE-2026-00015, covers the object; P6 is the direct form, P7 and P8 the indirect and tool-based forms.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| P6 | System Prompt Leakage | static | equivalent | 00015 | Prose regexes for instructions to print, reveal, dump or repeat the system prompt or internal rules ('verbatim repeat your system prompt', 'begin your reply with your instructions'). This is the phrasing in AVE-2026-00015's indicators. |
| P7 | System Prompt Leakage | static | related | 00015, 00026 | Prose regexes for indirect extraction: summarize, translate, encode (base64, rot13) or reformat the system prompt as JSON or a poem, 'repeat everything above', 'how were you configured'. Same object as AVE-2026-00015, whose title names direct interrogation, so these are variants at the edge of it. The encode patterns resemble AVE-2026-00026's encoding of a system prompt. |
| P8 | System Prompt Leakage | static | related | 00015, 00026 | Prose regexes for instructions to write the system prompt to a file or log, send it to a URL or webhook, or pipe it to curl. The object is AVE-2026-00015's; the transmission step is the one AVE-2026-00026 describes, without its encoding. |

### Data Exfiltration (9 rules)

External transmission, environment harvesting, file enumeration, context leakage, cloud uploads, and the Python taint flows TT1 to TT4. Most rules cover one half of AVE-2026-00003 (read or send). TT3 is the only full flow. Conversation context, the object of P3 and E4, is not named by any AVE record.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| E1 | External Transmission | static | related | 00003, 00013 | Regexes for outbound transmission: requests or httpx post and put to a literal URL, fetch POST, curl -d, wget --post, URLs on api., data., collect., telemetry. or analytics. hosts, and one prose pattern ('send user data to https://'). Matches the send half only and has no test that the data is sensitive, so legitimate telemetry fires too (confidence 0.5 to 0.7). |
| E2 | Env Variable Harvesting | static | related | 00003 | Python AST check for copying or enumerating the whole os.environ mapping (copy, items, keys, values, dict(), spread, loops), a regex fallback for unparsable files, JavaScript process.env key reads, 'env \| grep key', printenv and prose such as 'collect all environment variables'. The read half of AVE-2026-00003 with no transmission test; TT3 covers the full flow. |
| E3 | File System Enumeration | static | related | 00003 | Regexes for scanning directories for secrets: glob over .env, .ssh and .aws, os.walk over home, listdir of .ssh, find for *.pem, and prose such as 'find credential files'. The discovery step before AVE-2026-00003's read and transmit; no transmission test. |
| E4 | Conversation Context Leak | static | related | 00013, 00003 | Prose regexes for sending, exporting or logging the conversation, chat history, session or agent memory to an external or remote destination. Conversation context is not named as the object of any AVE exfiltration record, so AVE-2026-00013 (collect and transmit user data) is the nearest by shape. |
| E5 | Cloud Storage Exfiltration | static | related | 00003 | Regexes for cloud-storage uploads: boto3 put_object and upload_file, aws s3 cp, sync and mv, gsutil, az storage blob upload. Confidence 0.55 to 0.65 because backups use the same calls. Shares the external-destination step of AVE-2026-00003 and says nothing about what is uploaded. |
| TT1 | Direct Source-to-Sink Flow | static | no_fit | none | Python data-flow from any source to any sink that is not one of the credential, file-to-network, external-to-exec or deserialization pairs, for example a file read written to another file. A generic data-flow report, not a behavior class. |
| TT2 | Variable-Mediated Taint Flow | static | no_fit | none | The same flows as TT1 passing through an intermediate variable (confidence 0.65). |
| TT3 | Credential Exfiltration Flow | static | equivalent | 00003 | Python AST data-flow (same file, across direct calls): os.environ, os.getenv to a network sink (requests, httpx, urlopen, socket send). Credential read followed by external transmission is AVE-2026-00003's behavior, and its indicators list os.environ access. Differs: the flow is in bundled Python code rather than an instruction to the agent, and any environment variable counts as a credential. |
| TT4 | File Data Exfiltration Flow | static | related | 00003 | Python data-flow from open(), read_text() or read_bytes() to a network sink. File contents need not be credentials, so it is wider than AVE-2026-00003 on the object and narrower on the surface (bundled Python only). |

### Privilege Escalation (4 rules)

Excessive permission requests, sudo and root use, credential file access, and the external-input-to-exec taint flow TT5. PE3 is the read half of AVE-2026-00003. TT5 maps to AVE-2026-00033 for eval and exec; its shell sinks are best fit by AVE-2026-00052, pending deprecation.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| PE1 | Excessive Permissions | static | related | 00038, 00012 | Flags 'permissions: *', several dangerous permissions listed together, and prose asking for or taking 'full access', 'escalate my privileges' or 'bypass permission checks' (severity LOW). The wildcard grant is the shape of AVE-2026-00038; the escalate-and-bypass prose is near AVE-2026-00012's claimed grant. Neither is a full match. |
| PE2 | Sudo/Root Invocation | static | no_fit | none | sudo, doas, pkexec, setuid chmod and 'run as root'. Elevated execution is a capability use, not a behavior class in AVE. |
| PE3 | Credential File Access | static | related | 00003 | Path references to credential stores (.ssh keys, .aws/credentials, gcloud, .kube/config, .git-credentials, .netrc, /etc/shadow, .env, keychains, browser cookie and login databases) and prose such as 'read the ssh key'. The read half of AVE-2026-00003; no transmission test. |
| TT5 | External Input to Execution Flow | static | related | 00033 | Python data-flow from network or user input to exec, eval, compile, os.system, os.popen or subprocess. The exec and eval sinks match AVE-2026-00033 (its indicators include eval(user_input)). The shell sinks are command injection, whose best-fit record is AVE-2026-00052, proposed for deprecation in discussion 234 and so not recorded as a mapping. |

### Supply Chain (10 rules)

Unpinned and vulnerable dependencies, remote execution, obfuscation, shipped bytecode, concealed executables, dependency source redirection. SC1 to SC3 match AVE-2026-00062, 00004 and 00057. SC8 is a presence check and AVE-2026-00075 is the narrower case that also needs divergence from source. SC10 has no AVE counterpart.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| SC1 | Unpinned Dependencies | static | equivalent | 00062 | Requirements lines with no version or '>=' only, '*' or 'latest' in package.json, '^' ranges (confidence 0.4), and prose such as 'install the latest' or 'do not pin'. Mutable version specifiers are AVE-2026-00062's mechanism. |
| SC2 | Remote Code Execution | static | equivalent | 00004, 00001 | Regexes for curl or wget piped to sh, bash, python, node, ruby or perl, download-then-run, exec or eval of requests, urllib or fetch output, and 'download and run the script'. The curl-to-bash and eval(requests.get(...)) forms are AVE-2026-00004's own examples. Fetching code to execute at runtime is also the payload step of AVE-2026-00001. |
| SC3 | Obfuscated Code | static | equivalent | 00057 | exec or eval of base64, hex, zlib or marshal-decoded data, atob, obfuscator-style _0x names, long hex or base64 literals (confidence 0.5 to 0.6) and shell decode-to-execute chains. Encoded content decoded and executed at runtime is AVE-2026-00057. Differs: AVE-2026-00057 also covers keyword fragments joined by string concatenation, which SC3 does not test. |
| SC4 | Known Vulnerable Dependency | static+network | no_fit | none | Dependency CVE lookup: a live query to OSV.dev with a static fallback list, the only rule that needs the network. AVE enumerates behavior classes, not known-vulnerable versions. |
| SC5 | Abandoned Dependency | static | no_fit | none | Dependency named in a built-in list of abandoned or archived packages. The nearest record, AVE-2026-00074, is a dangling external anchor verified live against GitHub, a registry, RDAP or a cloud provider; a fixed list of abandoned names is a different test for a different risk. |
| SC6 | Typosquatting Dependency | static | no_fit | none | Dependency name within a small edit distance of a popular package. The nearest records are identity claims (AVE-2026-00017 for MCP servers) and squatting on hallucinated skill names (AVE-2026-00066, runtime_observed, out of scope). No static AVE class covers typosquatted package dependencies. |
| SC7 | Untrusted Container Image | static | related | 00061 | Container pulls with verification off: --disable-content-trust, DOCKER_CONTENT_TRUST=0, --insecure-registry. Only the registry TLS case overlaps AVE-2026-00061; image signature checking is a different control. |
| SC8 | Shipped Python Bytecode | static | narrower | 00075 | Filesystem walk that flags any __pycache__ directory or .pyc or .pyo file (confidence 0.95, HIGH). It never opens the bytecode or compares it with a sibling .py: its own docstring says presence alone is the signal and disassembly can come later. Every AVE-2026-00075 instance ships a .pyc, so SC8 fires on it, but SC8 also fires on benign bytecode and does not test divergence from the source, so a hit is a lead and not a 00075 instance. |
| SC9 | Concealed Executable Artifact | static | related | 00024 | Executables nested in docx, xlsx, pptx or zip containers or in hidden or disguised artifacts (confidence 1.0). Same outcome as AVE-2026-00024, executable content a reviewer misses because of its wrapper, with a different carrier: nesting and hiding instead of a wrong extension. SC9 also reports coverage limits (an excluded or referenced artifact that was not inspected), which are not a behavior. |
| SC10 | Dependency Source Redirection | static | no_fit | none | Deterministic check for package-manager source changes (npm, Yarn, pip, Poetry, Maven, Cargo): a registry or index added or replaced in config files, commands and environment variables, reported HIGH, with unresolved destinations reported as such. No AVE record covers it. AVE-2026-00073 is the same shape (a static value redirects traffic) but its object is where the agent sends telemetry or model traffic. AVE-2026-00062 is about the absence of a pin, which does not help when the registry itself is swapped. Listed as an AVE-side gap. |

### Excessive Agency (5 rules)

Unrestricted tool access, autonomous decisions, scope creep, unbounded resources, external model selection. EA2 matches AVE-2026-00021. EA1 and EA3 are partial. EA4 and EA5 are resource and cost checks.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| EA1 | Unrestricted Tool Access | static | related | 00038 | Flags 'tools: *' and 'permissions: *', and prose such as 'grant access to all tools', 'no tool restrictions', 'execute arbitrary commands', 'allowlist is empty'. Matches the unlimited-tool-authority clause of AVE-2026-00038. AVE-2026-00038 also covers unbounded sub-agent spawning and recursive capability expansion, which EA1 does not test. |
| EA2 | Autonomous Decision Making | static | equivalent | 00021, 00063 | Prose such as 'without asking for confirmation', 'skip confirmation', 'do not ask the user before', 'assume consent', and the tokens auto_approve, auto-confirm and --no-confirm in any file. The prose is AVE-2026-00021's indicators. The tokens also overlap AVE-2026-00063 (a declared flag that removes approval), but EA2 does not require the flag to sit in a configuration file. |
| EA3 | Scope Creep | static | related | 00022 | Generic scope-expansion prose: 'also perform any other', 'beyond the scope', 'handle everything', 'act as a general-purpose'. No comparison with a manifest. Shares AVE-2026-00022's idea of acting beyond declared purpose but not its test. |
| EA4 | Unbounded Resource Access | static | no_fit | none | Unbounded retries, timeouts or 'no rate limit' language. Resource exhaustion, not an AVE behavior class. |
| EA5 | External Model or Provider Selection | static | no_fit | none | Pinned model or provider keys and coding-CLI shell-outs that can switch the billing account. A cost-control check with no AVE class. |

### Output Handling (3 rules)

Unvalidated model output reaching interpreters, cross-context output, unbounded output. OH1 matches AVE-2026-00040. OH2 and OH3 have no static AVE class.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| OH1 | Unvalidated Output Injection | static | equivalent | 00040 | Model output (variables named response, output, result, completion and similar) passed to exec, eval, os.system, subprocess, innerHTML, document.write or a SQL string, plus prose such as 'pipe the output directly to the shell'. This is AVE-2026-00040's payload surface, agent output reaching an interpreter unescaped. |
| OH2 | Cross-Context Output | static | no_fit | none | Prose about passing output across contexts, agents or sessions, or injecting output into the system prompt. The static AVE records do not cover it; the nearest, AVE-2026-00018 and AVE-2026-00020, are runtime_observed and out of scope. |
| OH3 | Unbounded Output | static | no_fit | none | max_tokens=None, 'no output limit', 'flood the console'. Resource exhaustion with no AVE class. |

### Memory Poisoning (3 rules)

Persistent context injection, context window stuffing, memory manipulation. MP1 matches AVE-2026-00027. MP2 and the runtime memory records (AVE-2026-00019, 00023) are runtime_observed and out of scope.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| MP1 | Persistent Context Injection | static | equivalent | 00027 | Prose such as 'remember this for all future interactions', 'from now on always', 'store this in your memory', 'treat this as a permanent rule'. These are AVE-2026-00027's indicators (instruction persistence across turns and sessions). |
| MP2 | Context Window Stuffing | static | no_fit | none | A repeated token run or prose such as 'fill the context window'. The matching AVE class, AVE-2026-00023, is runtime_observed and out of scope. |
| MP3 | Memory Manipulation | static | related | 00025, 00009 | Prose for clearing, overwriting or tampering with memory, 'forget all previous instructions', 'rewrite your personality', 'inject fake memories', 'pretend your previous conversation included...', and sentences adopting a reset state as the conversation state. The fabricated-history patterns are AVE-2026-00025; the identity-rewrite patterns are near AVE-2026-00009. AVE-2026-00019 (memory poisoning) is runtime_observed and out of scope. |

### Tool Misuse (4 rules)

Dangerous tool parameters, chained commands, unsafe defaults, privileged Kubernetes workloads. Grab-bag regex rules. The only clean AVE overlap is TLS verification disabled (AVE-2026-00061) inside TM3.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| TM1 | Tool Parameter Abuse | static | related | 00005, 00061 | A grab bag of dangerous parameters: shell=True (with AST resolution of variables), rm -rf on / or ~, --force, --no-verify, chmod 777, git push --force and reset --hard, curl -k and --insecure, SQL built by f-string. Only rm -rf on broad paths overlaps AVE-2026-00005 and only the curl and wget certificate flags overlap AVE-2026-00061. |
| TM2 | Chaining Abuse | static | related | 00004 | Chained commands: '&& rm -', '&& curl ... \| sh', '\| sudo', a trailing '\| sh', and prose such as 'chain these tools to bypass the safety check'. The curl-to-shell chain is AVE-2026-00004. AVE-2026-00068 (command composition through shared shell state) is runtime_observed and out of scope. |
| TM3 | Unsafe Defaults | static | narrower | 00061 | Unsafe defaults: verify=False, VERIFY_SSL=False, NODE_TLS_REJECT_UNAUTHORIZED=0, auth=None, allow_anonymous, CORS *, mode 777, debug mode, sandbox=False and 'disable security'. TLS verification disabled is one instance in that list and is AVE-2026-00061; the other settings have no static AVE class. |
| TM4 | Privileged Kubernetes Workload | static | no_fit | none | Privileged Kubernetes workloads: privileged: true, hostPath, host PID, network or IPC, kubectl run --privileged. A cluster takeover primitive with no AVE class. |

### Rogue Agent (2 rules)

Self-modification and session persistence. RA2 matches AVE-2026-00008. The previous revision mapped this category to AVE-2026-00048, 00036 and 00050; none of the rules reads like those records.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| RA1 | Self-Modification | static | related | 00001 | Writes to the skill's own file or SKILL.md, self-modify and self-update names, and prose such as 'rewrite the current code' and 'disable the safety check'. Shares one outcome with AVE-2026-00001, a component whose instructions change after review, but there is no remote fetch, which is the trigger in AVE-2026-00001. |
| RA2 | Session Persistence | static | equivalent | 00008 | Crontab, systemctl or launchctl enable, startup-file appends (.bashrc and similar), hidden directories in home, registry and plist writes, nohup, disown and setsid, and prose such as 'schedule a recurring task'. The cron and startup-file cases are AVE-2026-00008's fingerprint. RA2 also fires on nohup and hidden-directory writes, which AVE-2026-00008 does not name. |

### Trigger Abuse (3 rules)

Over-broad, shadowing and baiting triggers in the skill manifest. Manifest word-list checks. They overlap AVE-2026-00058 on broad activation but do not test the mismatch with the skill's real function.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| TR1 | Overly Broad Trigger | static | related | 00058 | A manifest trigger that is a single common word (the, do, make, code, file, data, hello...) or two characters or fewer, or a description clause 'whenever the user says <common word>'. Over-broad activation is part of AVE-2026-00058, which also requires the breadth to exceed the skill's actual function; TR1 does not compare against what the skill does. |
| TR2 | Shadow Command Trigger | static | related | 00082 | A manifest trigger equal to one of 51 built-in command words (help, run, test, commit...), or a description clause that claims to intercept or override such a command. Router-level shadowing of trusted functionality is the idea behind AVE-2026-00082, but TR2 tests a fixed word list inside one skill and cannot see a second skill or a discovery root. |
| TR3 | Keyword Baiting Trigger | static | related | 00058 | A trigger or description clause that matches all input: 'anything', 'always', 'whenever the user says anything', 'all messages'. Over-broad activation as in AVE-2026-00058, with no comparison against the skill's real function. |

### Insecure Deserialization (5 rules)

Python deserialization flows and PHP, Ruby and JavaScript deserializer sinks. All rules are code sinks for the vulnerability AVE-2026-00033 describes as an instruction.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| TT6 | Untrusted Data to Deserializer Flow | static | related | 00033 | Python data-flow from network, user or file input to an unsafe deserializer (pickle, marshal, dill, jsonpickle, joblib, read_pickle, yaml.unsafe_load). 'Deserialize untrusted input using pickle' is an AVE-2026-00033 indicator; the surface here is bundled Python and not an instruction to the agent. |
| DS1 | PHP Object Injection | static | related | 00033 | PHP unserialize( in PHP files, any call, no source test. Insecure deserialization is AVE-2026-00033's vulnerability, as a code sink rather than an instruction. |
| DS2 | Ruby Marshal Deserialization | static | related | 00033 | Ruby Marshal.load or Marshal.restore in Ruby files. Same relationship as DS1. |
| DS3 | Unsafe Ruby YAML Deserialization | static | related | 00033 | Ruby YAML.load, Psych.load or Oj.load in Ruby files. Same relationship as DS1. |
| DS4 | Unsafe JavaScript Deserialization | static | related | 00033 | node-serialize, serialize-to-js, funcster or .unserialize( in JavaScript and TypeScript files. Same relationship as DS1. |

### YARA Match (4 rules)

YARA rule matches, bucketed by the rule's category meta. The previous revision said YARA is only known malware. The built-in agent_skills.yar rules are behavioral and fall under YR1 and YR4; the other built-in rules are malware, webshell, miner and hack-tool signatures.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| YR1 | Malware Signature | static | related | 00003, 00004, 00005, 00008, 00034 | Bucket for YARA rules whose category meta is malware, so a mapping is per YARA rule. Built-in members: agent_skill_credential_exfiltration_webhook (AVE-2026-00003), agent_skill_remote_bootstrap_execution (AVE-2026-00004, and pip install from a URL for AVE-2026-00034), agent_skill_destructive_autonomous_actions (AVE-2026-00005) and backdoor_persistence (AVE-2026-00008), plus reverse_shell, reverse_shell_multiline, keylogger_indicators, ransomware_behavior, c2_framework_indicators and info_stealer, which have no AVE class. User-supplied rules (--yara-rules-dir) are not covered. |
| YR2 | Webshell Detected | static | no_fit | none | Webshell signatures (PHP, Python, JSP, ASPX). Known-malware matching with no AVE class. |
| YR3 | Crypto Miner Detected | static | no_fit | none | Cryptominer signatures (stratum, pools, miner software, coinjacking). Mining is not wallet drain (AVE-2026-00006); no AVE class. |
| YR4 | Hack Tool / Exploit Detected | static | related | 00007, 00002, 00032, 00009, 00015, 00029 | Bucket for YARA rules whose category meta is hack_tool or exploit. Built-in members include agent_skill_prompt_injection_hidden_instructions (override, reveal-prompt and persona-bypass phrasing: AVE-2026-00007, 00015 and 00009), agent_skill_mcp_tool_poisoning_metadata (AVE-2026-00002, with zero-width and bidi bytes for AVE-2026-00029) and network_reconnaissance (masscan, arp-scan, enum4linux: AVE-2026-00032). The remaining members (offensive tool references, privilege escalation tools, exploit frameworks, phishing kits) have no AVE class. |

### MCP Least Privilege (4 rules)

Manifest permissions compared with code capabilities. Pure static. LP1 and LP3 compare declared scope with actual behavior, the idea in AVE-2026-00022.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| LP1 | Underdeclared Capability | static | related | 00022 | Pure static check: code capability categories (shell, network, file read, file write, environment, MCP) found in executable files but not covered by the manifest's permissions or allowed-tools. It compares declared scope with actual behavior, the idea in AVE-2026-00022, but at the level of six capability categories rather than the files, APIs or systems an instruction directs the agent to touch. |
| LP2 | Wildcard Permission | static | related | 00038 | A wildcard in the declared permissions (*, all, full, any). A blanket grant like AVE-2026-00038's unlimited tool authority, expressed in the manifest instead of an instruction. |
| LP3 | Missing Permission Declaration | static | related | 00022 | No tool scope declared at all while the code has capabilities. The declared scope that AVE-2026-00022 compares against is missing, so the comparison cannot be made; SkillSpector reports the absence. |
| LP4 | Overdeclared Permission | static | no_fit | none | Permission declared but no matching code capability found (overdeclaration). The previous revision recorded this as a gap and it still is: no AVE record describes over-declared scope. |

### MCP Tool Poisoning (4 rules)

Hidden content, Unicode deception and injection in skill and tool metadata, plus an LLM description-behavior check. TP3 matches AVE-2026-00002. TP4 is the only LLM-dependent rule inside the category map.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| TP1 | Hidden Instructions | static | related | 00002, 00029 | Static check of manifest metadata fields (name, description, triggers, parameter text) for HTML and markdown comments (confidence 0.95 when they hold SYSTEM or IGNORE keywords), zero-width characters, data URIs and long base64 blobs. Hidden content in the description field is the surface of AVE-2026-00002; the zero-width characters are AVE-2026-00029's. The concealment technique, not directive content, is what TP1 tests. |
| TP2 | Unicode Deception | static | related | 00029 | Unicode deception in identifiers: Cyrillic and Greek homoglyphs, right-to-left and directional overrides, invisible formatting, mixed scripts. The technique is AVE-2026-00029's; the target is a name (for example read_file with a Cyrillic letter) rather than instruction text a reviewer is meant to miss. |
| TP3 | Parameter Description Injection | static | equivalent | 00002, 00041 | Static check of parameter descriptions and defaults: override phrases, SYSTEM or [INST] tokens, exfiltration verbs, descriptions over 500 characters, and defaults that are external URLs or shell commands. These are the indicators of AVE-2026-00002 (override phrases, descriptions far longer than needed), and AVE-2026-00041 names parameter descriptions as an injection surface. |
| TP4 | Description-Behavior Mismatch | llm | related | 00058 | LLM check (skipped with --no-llm) that the manifest description matches what the code does, emitted at LLM confidence 0.5 or more. Matches AVE-2026-00058's case of a generic description over a narrow sensitive implementation, but the test is a model's judgement and not a deterministic comparison. |

### Agent Snooping (3 rules)

Reads of agent config directories, MCP config and peer skills. Access to resources a skill has no need for. Related to AVE-2026-00022 but the rules do not check a manifest.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| AS1 | Agent Config Directory Access | static | related | 00022 | Reads of .claude, .codex, .gemini or .continue directories and their config files, in code and prose. Access to a resource the skill has no need for (AVE-2026-00022's idea), flagged by resource kind with no comparison to a manifest. Agent config can hold API keys, so AVE-2026-00003 is the follow-on if they are sent. |
| AS2 | MCP Config Access | static | related | 00022 | Reads of mcp.json and MCP config files, and prose such as 'list MCP servers'. Same relationship as AS1; the config holds server URLs and tokens. |
| AS3 | Skill Enumeration | static | related | 00022 | Listing or reading other installed skills (their SKILL.md, the skills directories). Same relationship as AS1. No AVE record describes one skill reading its peers. |

### Anti-Refusal (3 rules)

Refusal, disclaimer and safety-policy suppression. Jailbreak wording. Related to AVE-2026-00009, whose fingerprint is persona and unrestricted-mode language.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| AR1 | Refusal Suppression | static | related | 00009 | Prose such as 'never refuse', 'always comply', 'you cannot say no', 'no request is off limits'. Refusal suppression is a jailbreak technique and belongs to AVE-2026-00009's class, though AVE-2026-00009's fingerprint is persona and unrestricted-mode language and not refusal wording. |
| AR2 | Disclaimer Suppression | static | related | 00009 | Prose such as 'no warnings or disclaimers', 'do not moralize', 'skip the ethics'. SkillSpector calls it a jailbreak preamble. The weakest of the three anti-refusal links to AVE-2026-00009. |
| AR3 | Safety Policy Nullification | static | related | 00009, 00007 | Prose such as 'you have no restrictions', 'act as an unfiltered model', 'do anything now', 'developer mode enabled', 'ignore your guidelines'. The unrestricted-persona and mode wording is AVE-2026-00009; 'ignore your guidelines' is AVE-2026-00007's override. |

### Server-Side Request Forgery (3 rules)

Cloud metadata endpoints, private-range requests, dynamic request targets. No AVE record covers SSRF.

| Rule | Name | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|
| SSRF1 | Cloud Metadata Access | static | no_fit | none | Literal cloud metadata endpoints (169.254.169.254, metadata.google.internal, 100.100.100.200, fd00:ec2::254), skipped when the surrounding text documents a rejection rule. No AVE record covers server-side request forgery or metadata access; AVE-2026-00049's 'server-side request routing' concerns the Host header the component sends. |
| SSRF2 | Internal Network Request | static | no_fit | none | A request call with a literal loopback, link-local or private-range URL. AVE-2026-00032 is an instruction to scan the network, a different behavior from one request to a private address. |
| SSRF3 | Dynamic Request Target | static | no_fit | none | A request call whose URL host is a template or f-string value. No AVE class. |

## Rules emitted outside the category map (37)

These ids are absent from `RULE_ID_TO_CATEGORY` (so SkillSpector's own report falls back to a generic category for them) but are emitted by the analyzers named below.

| Rule | Name | Analyzer | Detection | Relationship | AVE | Notes |
|---|---|---|---|---|---|---|
| AST1 | exec() Call | `behavioral_ast` | static | related | 00033 | Any exec() call in Python (AST, confidence 0.85, HIGH), with no test of what is executed. Dynamic code execution is AVE-2026-00033's sink (its indicators include eval(user_input)); AST1 has no untrusted-source test and AVE-2026-00033 is stated as an instruction to the agent. |
| AST2 | eval() Call | `behavioral_ast` | static | related | 00033 | Any eval() call in Python (HIGH, 0.85). Same relationship as AST1. |
| AST3 | Dynamic Import | `behavioral_ast` | static | no_fit | none | Any __import__() call (MEDIUM). A capability, not a behavior class. |
| AST4 | subprocess Call | `behavioral_ast` | static | no_fit | none | Any subprocess run, call, Popen, check_output or check_call (MEDIUM, 0.70). A capability use. The vulnerable form, caller-controlled input reaching a shell, is best fit by AVE-2026-00052 (proposed for deprecation, discussion 234), which is not recorded as a mapping. |
| AST5 | os.system / exec-family | `behavioral_ast` | static | no_fit | none | Any os.system, os.popen or os exec-family call (HIGH, 0.85). Same as AST4. |
| AST6 | compile() Call | `behavioral_ast` | static | no_fit | none | Any compile() call (MEDIUM). A capability, not a behavior class. |
| AST7 | Dynamic getattr() | `behavioral_ast` | static | no_fit | none | getattr() with a non-literal name, or a module __dict__ subscript with a non-literal key (LOW, 0.5). A capability signal with no AVE class. |
| AST8 | Dangerous Execution Chain | `behavioral_ast` | static | related | 00004, 00057 | exec, eval or compile whose first argument nests a compile, __import__, subprocess, os, base64, codecs, marshal, urllib, requests or httpx call (CRITICAL, 0.95). Structural nesting, not data flow. eval(requests.get(...)) is one of AVE-2026-00004's own examples and exec of decoded data is AVE-2026-00057; the rule fires on both and on other nestings. |
| AST9 | Reflective getattr() Sink | `behavioral_ast` | static | related | 00057 | getattr(os, 'system') and module __dict__['exec'] with a literal sink name (HIGH). SkillSpector calls it a deliberate evasion of name-based detection, which is the aim of AVE-2026-00057 (evading static scanners) reached by reflection instead of encoding. |
| AST10 | Insecure Deserialization | `behavioral_ast` | static | related | 00033 | pickle, marshal, dill, jsonpickle, read_pickle, joblib.load and yaml.unsafe_load unconditionally; yaml.load without a safe loader; torch.load without weights_only (MEDIUM). The same sink family as AVE-2026-00033, with no untrusted-source test. AST10 is named in PATTERN_NAMES and DEFAULT_EXPLANATIONS but not in RULE_ID_TO_CATEGORY. |
| BH1 | Bundled lifecycle hooks | `bundled_execution_surface` | static | related | 00064 | Reads hooks/hooks.json, .claude/settings.json, .claude/settings.local.json and the hooks field of .claude-plugin/plugin.json and reports that bundled lifecycle hooks can run on matching events, with severity set by reach and handler type (confidence 0.95, activation conditional). A committed auto-run surface in the sense of AVE-2026-00064; BH1 does not test the 'no user confirmation' condition. It remembers hook identities between the two settings files of one scan, not between versions, so it cannot see AVE-2026-00084's update-time rebinding. |
| BH2 | Bundled hook sends content remotely | `bundled_execution_surface` | static | related | 00046, 00003 | A bundled hook proven to send event or file content to a non-loopback host: an http handler on a sensitive event (UserPromptSubmit, PreToolUse, PostToolUse and similar), or a curl, wget, scp or rsync command uploading event input or a sensitive path (CRITICAL, 0.99). A hook that routes tool-call events to an external URL is AVE-2026-00046's behavior; the content sent is not limited to credentials (AVE-2026-00003). |
| BH3 | Bundled permission surface | `bundled_execution_surface` | static | equivalent | 00063 | Settings permissions: whole-tool or broad allow grants (Bash, Bash(*), Read, Edit, Write, root-wide paths) and defaultMode values such as bypassPermissions; modes ignored on a surface are reported with activation ignored_by_surface. A declarative setting that removes the approval step is AVE-2026-00063 (the cfgaudit crosswalk maps bypassPermissions and allowlists to it the same way). |
| BH4 | Bundled settings commands | `bundled_execution_surface` | static | related | 00064 | Settings keys that run shell commands: apiKeyHelper, awsAuthRefresh, otelHeadersHelper, statusLine, fileSuggestion (MEDIUM, 0.95). A project-level setting that makes the agent run a command, as in AVE-2026-00064, but the keys run only after settings activation and the rule does not test for a confirmation step. |
| RP1 | Unpinned MCP/package reference | `mcp_rug_pull` | static | equivalent | 00062 | Static mode: npx, uvx, pip install or docker pull references with no version, tag or digest, in code or manifest. A mutable dependency reference, AVE-2026-00062. The same id is reused in diff mode for added permissions, but diff mode needs previous_manifest, which build_context.py hard-codes to None, so a normal scan never runs it. |
| RP2 | Permission pre-staging | `mcp_rug_pull` | static | no_fit | none | Static mode: any '"permissions": [...]' array (0.6) or 'request additional permissions' prose (0.7) in the manifest, labelled pre-staging. Fires on ordinary permission lists; no AVE class. In diff mode the same id means changed trigger phrases, which a normal scan never reaches. |
| RP3 | Unpinned skill version | `mcp_rug_pull` | static | related | 00062 | Static mode: manifest version '*', 'latest', 'any' or a '>=' or '^' constraint. An unpinned version of the skill itself; AVE-2026-00062 is about a dependency reference, so it is the nearest. In diff mode the same id means a changed parameter schema, which a normal scan never reaches. |
| PE4 | Docker Socket Access | `static_patterns_privilege_escalation` | static | no_fit | none | docker.sock paths, docker.from_env() and DockerClient( (HIGH). Local container-daemon access; AVE-2026-00071 is a redirect of the daemon to a remote host, a different mechanism. |
| PE5 | Privileged Container / Container Escape | `static_patterns_privilege_escalation` | static | no_fit | none | --privileged, a root bind mount, --cap-add SYS_ADMIN, host namespaces, nsenter, release_agent. Container escape primitives with no AVE class (sandbox weakening is an open surface in the cfgaudit crosswalk too). |
| AE1 | Incomplete referenced artifact analysis | `finalize_inspection_ledger` | static | no_fit | none | Coverage finding: a referenced artifact was not completely inspected (HIGH, 1.0). It says what the scan did not see, not a behavior. |
| AE2 | Artifact content does not match extension | `artifact_integrity` | static | narrower | 00024 | Content kind disagrees with the file extension: a binary suffix on text content or a text suffix on binary bytes (MEDIUM, 0.9). Decided by byte classification (text versus binary), not by an ML file-type model. AVE-2026-00024 is the specific case of an executable disguised as a skill file; AE2 also fires on non-executable mismatches. |
| AE3 | Embedded NUL bytes in text artifact | `artifact_integrity` | static | related | 00024 | A text artifact that contains NUL bytes (HIGH, 0.9). Binary content under a text file; near AVE-2026-00024 but does not test for an executable. |
| AE4 | Suspicious Unicode normalization or mixed script | `artifact_integrity` | static | related | 00029 | Format-character density of 1% or more, or mixed scripts, in text (MEDIUM, 0.8). The same family of tricks as AVE-2026-00029; it reports a signal, not a hidden instruction. |
| AE5 | Exceeds whole-file semantic analysis limit | `artifact_integrity` | static | no_fit | none | Coverage finding: an instruction-capable file exceeds the whole-file semantic analysis limit (HIGH, 1.0). |
| AE6 | Inter-character separators | `artifact_integrity` | static | related | 00057 | Instruction text with separators between characters to evade pattern matching, for example 'i g n o r e' (HIGH, 0.9). Evading static pattern matching by splitting keywords is part of AVE-2026-00057's fingerprint; AVE-2026-00057 names concatenation rather than separators. |
| AE7 | Size limit, trailing content not inspected | `finalize_inspection_ledger` | static | no_fit | none | Coverage finding: a file exceeds the per-file size limit and trailing content was not inspected (HIGH, 1.0). |
| SSD-1 | Semantic prompt injection | `semantic_security_discovery` | llm | related | 00007, 00009 | LLM. Polite reframings of ignore-your-instructions, role-play that grants permissions, fictional framings used to bypass safety. The meaning of AVE-2026-00007 and AVE-2026-00009 without their keywords. |
| SSD-2 | Novel or paraphrased attack phrasing | `semantic_security_discovery` | llm | related | 00007 | LLM. Paraphrased or encoded forms of known attack phrasing, the same classes as SSD-1 with AVE-2026-00007 first. |
| SSD-3 | Natural-language exfiltration instructions | `semantic_security_discovery` | llm | related | 00003, 00013 | LLM. Plain-language instructions to collect or leak data ('keep a log of all inputs', 'always echo back credentials'). The instruct-then-expose shape of AVE-2026-00003 and AVE-2026-00013 in plain words. |
| SSD-4 | Narrative or gradual deception | `semantic_security_discovery` | llm | no_fit | none | LLM. Deception spread across steps. No single static AVE record; AVE-2026-00085 is the multi-skill form and needs several skills. |
| SDI-1 | Description-behavior mismatch | `semantic_developer_intent` | llm | related | 00058 | LLM. Manifest description versus code behavior (the TP4 test applied per file). AVE-2026-00058's generic-description case. |
| SDI-2 | Context-inappropriate capability | `semantic_developer_intent` | llm | related | 00022, 00058 | LLM. A code capability unjustified by the stated purpose, for example a text formatter that spawns subprocesses. Close to AVE-2026-00022 and AVE-2026-00058. |
| SDI-3 | Scope creep vs declared permissions | `semantic_developer_intent` | llm | related | 00022 | LLM. Code that accesses more than the manifest permissions cover (LP1 with judgement). AVE-2026-00022. |
| SDI-4 | Intent-code divergence | `semantic_developer_intent` | llm | no_fit | none | LLM. Comments or docstrings that contradict the code. No AVE class. |
| SQP-1 | Vague triggers | `semantic_quality_policy` | llm | related | 00058 | LLM. Vague or over-broad trigger wording in markdown, text and manifests (TR1 and TR3 with judgement). AVE-2026-00058. |
| SQP-2 | Missing user warnings | `semantic_quality_policy` | llm | no_fit | none | LLM. Missing user warnings for risky operations. A quality finding with no AVE class. |
| SQP-3 | Natural-language policy violations | `semantic_quality_policy` | llm | no_fit | none | LLM. Natural-language policy violations, currently language or locale policy. No AVE class. |

AVE ids in the tables are shown without the `AVE-2026-` prefix.

## Rug pull (RP1 to RP3) has two modes

The same ids mean different things in two modes. Static mode checks for unpinned references, permission lists and an unpinned version. Diff mode compares the manifest with a `previous_manifest` (permissions added, trigger phrases changed, parameter schema changed). `previous_manifest` is set to `None` in `src/skillspector/nodes/build_context.py` and nothing else sets it outside the tests, so a normal scan only runs the static mode.

## Checked and rejected

Candidate links read in full and not recorded as mappings.

| Rule | AVE | Why not |
|---|---|---|
| SC10 | 00073 | Same shape (a static configuration value redirects traffic) but a different object: where a package manager resolves dependencies versus where the agent sends telemetry or model traffic. |
| SC10 | 00062 | AVE-2026-00062 is the absence of a pin. A pinned name still resolves from an attacker's registry, so pinning is not the control SC10 tests; AVE-2026-00074 makes the same point for changed target identity. |
| SC8 | 00075 | Recorded as narrower, not related: every 00075 instance ships a .pyc so SC8 fires, but SC8 never opens the bytecode and AVE-2026-00075 requires divergence from the sibling source. |
| TR2 | 00058 | AVE-2026-00058 needs activation scope broader than the skill's function; TR2 only tests a trigger against a fixed list of built-in command names. |
| TT5 | 00052 | Best fit for the shell sinks, but AVE-2026-00052 is proposed for deprecation (discussion 234, CWE-78), so it is noted and not recorded as a mapping. |
| AST4 | 00052 | Same as TT5: noted, not mapped, while AVE-2026-00052 is pending deprecation. |
| SC6 | 00017 | AVE-2026-00017 is a false claim of official MCP server identity; a typosquatted package name in a dependency list is a different object. |
| SC5 | 00074 | AVE-2026-00074 is verified live against the owning authority; SC5 matches a fixed list of abandoned names. |
| SSRF2 | 00032 | AVE-2026-00032 is an instruction to probe and map a network; SSRF2 flags one request call to a literal private address. |
| PE4 | 00071 | AVE-2026-00071 redirects the daemon to a remote host; PE4 flags local socket use. |
| TM3 | 00072 | Auth settings set to none are not a wildcard bind address; AVE-2026-00072 needs the 0.0.0.0 or [::] bind. |
| BH1 | 00084 | AVE-2026-00084 is detected by a diff against the last reviewed version; BH1 reads one snapshot. |
| RP1 | 00084 | RP's diff mode would be near AVE-2026-00084 (an update changes a trusted surface) but compares permissions, triggers and parameters rather than hook bindings, and is never run by a normal scan. |
| AS2 | 00003 | Reading MCP config is only the read half of AVE-2026-00003 and carries no transmission; recorded against AVE-2026-00022 instead. |
| MP2 | 00023 | AVE-2026-00023 is runtime_observed; out of scope. |
| OH2 | 00018 | AVE-2026-00018 and AVE-2026-00020 are runtime_observed; out of scope. |
| TP2 | 00017 | A homoglyph tool name spoofs an identifier but makes no claim of verified server identity, which is AVE-2026-00017's fingerprint. |

## Gaps

### SkillSpector rules with no AVE class

| Category | Rules | Reason |
|---|---|---|
| Prompt Injection | P5 | Content safety (physical-harm content), not an agent behavior class. |
| Data Exfiltration | TT1, TT2 | Generic data-flow reports between any source and sink, not a behavior class. |
| Privilege Escalation | PE2 | Elevated execution is a capability use, not a behavior class. |
| Supply Chain | SC4, SC5, SC6 | Known-vulnerable, abandoned and typosquatted dependencies are reputation and CVE checks. AVE enumerates behavior classes; the nearest records (AVE-2026-00074, 00017, 00066) test different things. |
| Supply Chain | SC10 | Package-manager dependency source redirection. A genuine gap on the AVE side with SC10 as its source: no AVE record's fingerprint or text covers it (all 89 records searched). The two nearest records, AVE-2026-00073 and 00062, are listed under checked_and_rejected. |
| Excessive Agency | EA4, EA5 | Resource exhaustion and billing-account switching. No AVE class. |
| Output Handling | OH2, OH3 | Cross-context output flow has only runtime AVE counterparts (out of scope); unbounded output is resource exhaustion. |
| Memory Poisoning | MP2 | Context window stuffing has only a runtime AVE counterpart, AVE-2026-00023 (out of scope). |
| Tool Misuse | TM4 | Privileged Kubernetes workload. Cluster takeover primitive with no AVE class. |
| YARA Match | YR2, YR3 | Webshell and cryptominer signatures. Known-malware matching with no AVE class. |
| MCP Least Privilege | LP4 | Over-declared permissions. Carried over from the previous revision's gap on server-card over-declaration; still no AVE record. |
| Server-Side Request Forgery | SSRF1, SSRF2, SSRF3 | No AVE record covers SSRF or cloud metadata access. |
| (emitted outside RULE_ID_TO_CATEGORY) | AST3, AST4, AST5, AST6, AST7 | Python capability signals (dynamic import, subprocess, os.system, compile, dynamic getattr). AST4 and AST5 are best fit by AVE-2026-00052, pending deprecation. |
| (emitted outside RULE_ID_TO_CATEGORY) | RP2 | Fires on ordinary permission lists; no AVE class. |
| (emitted outside RULE_ID_TO_CATEGORY) | PE4, PE5 | Container socket and escape primitives. No AVE class. |
| (emitted outside RULE_ID_TO_CATEGORY) | AE1, AE5, AE7 | Coverage findings: they report what the scan could not inspect, not a behavior. |
| (emitted outside RULE_ID_TO_CATEGORY) | SSD-4, SDI-4, SQP-2, SQP-3 | LLM-only findings with no AVE class (narrative deception, comment-code divergence, missing warnings, language policy). |

### Static AVE records no SkillSpector rule maps to (27 of 61)

| AVE | Reason |
|---|---|
| 00006 | Crypto wallet drain by fund-transfer instruction. No SkillSpector rule looks for transfers, allowance approvals or transaction signing. YR1's info_stealer names wallet.dat (theft of a wallet file) and YR3 matches miners; neither is a transfer instruction. |
| 00011 | Explicit tool-call directives with parameters. No rule detects an instruction that dictates a tool invocation; EA1, LP2 and PE1 concern how broad tool access is, not a directed call. |
| 00014 | False authority claims (text said to come from a model vendor or operator). No rule or YARA string looks for authority claims; P1 and AR3 match override and no-restriction phrasing only. |
| 00017 | MCP server impersonation. TP2 flags homoglyph and mixed-script identifiers, but no rule reads a claim of official or verified status or compares a name with a registry. |
| 00030 | Elevated privileges granted to anyone who claims a role. No rule tests for conditional privilege grants based on a claimed role. |
| 00036 | Lateral movement instructions. No rule has lateral-movement or pivot language; 'pivot' appears only inside the SSRF2 explanation text. |
| 00039 | Steganographic and covert-channel exfiltration. No rule looks for first-letter, whitespace or timing encodings of output. P7's acrostic and encode-the-prompt patterns touch the system-prompt case only. |
| 00045 | Cross-app-access escalation between MCP servers in one session. No rule tests for text in one server's tool description that tells the agent to use another server's tools. |
| 00047 | Hardcoded credentials. SkillSpector has no rule, static or LLM, that flags literal secret strings in files; PE3 flags paths to credential files and E2 flags bulk environment reads. Its report redaction hides secrets in output but does not report them. |
| 00048 | Unsafe agent delegation chain. No rule has sub-agent or delegation language; the only 'Subagent' strings in the analyzers are hook event names. |
| 00049 | Host header injection on agent-initiated requests. No rule inspects Host, X-Forwarded-Host or Forwarded headers. |
| 00051 | OAuth discovery rebinding. No rule reads OAuth discovery metadata; the OAuth wording in PE3 only decides when a token noun is benign. |
| 00052 | Command injection in MCP server implementation code. Proposed for deprecation in discussion 234 (CWE-78). The nearest checks (TT5, AST4, AST5) are not recorded as mappings. |
| 00053 | Path traversal in MCP resource handlers. Proposed for deprecation in discussion 234 (CWE-22). SkillSpector has no path-traversal rule. |
| 00055 | Command execution through an untrusted MCP launch configuration. No rule reads MCP server command and args fields; BH4 covers Claude Code settings keys such as apiKeyHelper, a different configuration surface. |
| 00059 | Fragmented cross-description injection. TP1 to TP3 inspect each metadata field on its own (docs/B.3.2), so a payload split across descriptions is not reassembled. |
| 00060 | STDIO transport shell injection in server code. Proposed for deprecation in discussion 234 (CWE-78). The nearest checks (TT5, AST4, AST5) are not recorded as mappings. |
| 00065 | A2A agent card poisoning. No rule or YARA string mentions agent cards or the A2A protocol. |
| 00069 | Image-hidden instructions. SkillSpector's image handling validates PNG and JPEG structure and, by its own documentation, does not inspect rendered content or perform OCR (docs/passive-documentation-images.md). |
| 00071 | DOCKER_HOST daemon redirect. No rule mentions DOCKER_HOST or the -H and --host flags; PE4 and PE5 cover local socket and privileged-container primitives. |
| 00072 | MCP server bound to all interfaces. No rule inspects bind addresses; SSRF2 matches request targets, not listeners. |
| 00073 | Endpoint redirect through a static configuration value. SC10 is the same shape for package managers only. No rule checks telemetry, model-provider or MCP server URLs. |
| 00074 | Dead external anchor reclamation. It needs live lookups against GitHub, registries, RDAP or cloud providers. SC4 queries OSV.dev and SC5 and SC6 use fixed lists; none checks that a referenced owner, package or domain is still claimed. |
| 00076 | Natural-language steering of an approval classifier. No rule reads allow_instructions or block_instructions entries; BH3 reads Claude settings permissions only. |
| 00077 | Cross-origin tool and resource declarations in one MCP manifest. No rule compares the root domains or schemes of URLs declared in a manifest. |
| 00084 | Lifecycle hook trust decoupling on plugin update. Detection needs a diff against the last reviewed version. BH1 sees one snapshot (it only carries hook identities between the two settings files of one scan), and RP's diff mode needs previous_manifest, which build_context.py sets to None and which compares permissions, triggers and parameters, not hook bindings. |
| 00085 | Collusive cross-skill composition. Every rule evaluates one artifact or one skill; the multi-skill module only discovers skill directories under --recursive and does not correlate them. |

## Out of scope: runtime AVE records

SkillSpector is a static scanner. These records are detected from runtime behavior or drift, so they are listed and not mapped.

- `runtime_observed` (26): 00016, 00018, 00019, 00020, 00023, 00028, 00031, 00035, 00037, 00042, 00043, 00044, 00050, 00054, 00056, 00066, 00067, 00068, 00078, 00080, 00081, 00083, 00086, 00087, 00088, 00089
- `runtime_drift_detected` (2): 00070, 00079

## Dropped from the previous revision

The previous revision linked 41 category-to-record pairs; 20 survive in some form and 21 do not.

| Previous category | AVE | Why dropped |
|---|---|---|
| prompt_injection | 00002 | Prompt Injection rules read file bodies, not tool-description metadata; the tool-description link now sits on the MCP Tool Poisoning rules (TP1, TP3). |
| data_exfiltration | 00026 | No Data Exfiltration rule encodes data into tool output. AVE-2026-00026 now appears only as a secondary link on P7 and P8 (system prompt encoding and transmission). |
| data_exfiltration | 00039 | No rule looks for steganographic or covert-channel output; see ave_gaps. |
| privilege_escalation | 00022 | The Privilege Escalation rules (PE1 to PE3, TT5) do not compare declared scope. AVE-2026-00022 now appears under Excessive Agency, MCP Least Privilege and Agent Snooping. |
| privilege_escalation | 00045 | No rule covers cross-app-access escalation; see ave_gaps. |
| supply_chain | 00034 | No Supply Chain rule covers dynamic third-party skill import. It appears only through the YARA rule agent_skill_remote_bootstrap_execution (YR1). |
| supply_chain | 00049 | No rule inspects HTTP Host headers; the old link was by analogy with the 'supply chain' attack_class label, not by mechanism. |
| supply_chain | 00051 | No rule reads OAuth discovery metadata; the old link was by analogy with the attack_class label. |
| excessive_agency | 00048 | No rule has delegation or sub-agent language; the old link was by category name. |
| memory_poisoning | 00019 | AVE-2026-00019 is runtime_observed; out of scope for a static scanner. |
| tool_misuse | 00011 | No Tool Misuse rule detects an instruction that dictates a tool call with parameters. |
| tool_misuse | 00018 | AVE-2026-00018 is runtime_observed; out of scope. |
| rogue_agent | 00048 | Neither RA1 nor RA2 concerns delegation; the old link was by category name. |
| rogue_agent | 00036 | Neither RA1 nor RA2 concerns lateral movement. |
| rogue_agent | 00050 | AVE-2026-00050 is runtime_observed; out of scope. |
| trigger_abuse | 00001 | Remote fetch is detected by SC2, not by the Trigger Abuse rules, which are manifest word-list checks. |
| trigger_abuse | 00027 | Instruction persistence is detected by MP1 (Memory Poisoning), not by the Trigger Abuse rules. |
| taint_tracking | 00026 | No taint rule models encoding into tool output. |
| taint_tracking | 00049 | No rule inspects HTTP Host headers; the old link rested on a 'textbook taint-tracking target' argument, not on a SkillSpector rule. |
| mcp_least_privilege | 00002 | LP1 to LP4 compare permissions with code capabilities; none reads description text for directives. |
| mcp_least_privilege | 00050 | AVE-2026-00050 is runtime_observed; out of scope. |

## Coverage summary

| | |
|---|---|
| SkillSpector in-map rules | 78 in 18 categories |
| In-map rules mapped to an AVE class | 58 |
| In-map rules with no AVE class | 20 |
| Categories with at least one mapped rule | 17 of 18 |
| Rules outside the category map | 37 (22 mapped, 15 no fit) |
| Relationships, in-map rules | equivalent 11, narrower 2, broader 0, related 45, no_fit 20 |
| Relationships, outside the map | equivalent 2, narrower 1, broader 0, related 19, no_fit 15 |
| Static AVE records referenced | 34 of 61 |
| Static AVE records not referenced | 27 |
| Runtime AVE records out of scope | 28 |

**Not claimed:** No claim that SkillSpector emits AVE ids, that either project endorses the mapping, or that a hit on a related rule is an instance of the AVE class. Detection quality (precision, recall) was not measured; only what each rule is designed to match was read. Rules were read at the pinned tag and will drift as SkillSpector changes.

*Machine-readable version: [skillspector-to-ave.json](skillspector-to-ave.json)*
