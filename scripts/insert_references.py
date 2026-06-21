"""
What: Insert real citable references into all 51 AVE records.
Why:  Existing records have placeholder "Reference" tags pointing to internal API; defenders need citable primary sources.
How:  Dict keyed by ave_id → list of {tag, text, url} objects; script loads each JSON, replaces references[], writes back.
"""
import json
import glob
import os

REFS = {
    "AVE-2026-00001": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "MITRE ATLAS AML.T0010",
            "text": "MITRE ATLAS — ML Supply Chain Compromise (AML.T0010)",
            "url": "https://atlas.mitre.org/techniques/AML.T0010",
        },
        {
            "tag": "CWE-494",
            "text": "CWE-494: Download of Code Without Integrity Check — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/494.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00001 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00001",
        },
    ],
    "AVE-2026-00002": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "Perez 2022",
            "text": "Perez & Ribeiro — Ignore Previous Prompt: Attack Techniques For Language Models (arXiv 2211.09527)",
            "url": "https://arxiv.org/abs/2211.09527",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00002 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00002",
        },
    ],
    "AVE-2026-00003": [
        {
            "tag": "CWE-522",
            "text": "CWE-522: Insufficiently Protected Credentials — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/522.html",
        },
        {
            "tag": "MITRE ATT&CK T1552",
            "text": "MITRE ATT&CK — T1552: Unsecured Credentials",
            "url": "https://attack.mitre.org/techniques/T1552/",
        },
        {
            "tag": "OWASP LLM Sensitive Info",
            "text": "OWASP Top 10 for LLM Applications — Sensitive Information Disclosure",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00003 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00003",
        },
    ],
    "AVE-2026-00004": [
        {
            "tag": "CWE-78",
            "text": "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "url": "https://cwe.mitre.org/data/definitions/78.html",
        },
        {
            "tag": "OWASP A03:2021",
            "text": "OWASP Top 10:2021 — A03: Injection",
            "url": "https://owasp.org/Top10/A03_2021-Injection/",
        },
        {
            "tag": "CWE-77",
            "text": "CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')",
            "url": "https://cwe.mitre.org/data/definitions/77.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00004 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00004",
        },
    ],
    "AVE-2026-00005": [
        {
            "tag": "CWE-78",
            "text": "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "url": "https://cwe.mitre.org/data/definitions/78.html",
        },
        {
            "tag": "OWASP LLM Excessive Agency",
            "text": "OWASP Top 10 for LLM Applications — Excessive Agency",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "CWE-20",
            "text": "CWE-20: Improper Input Validation — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/20.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00005 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00005",
        },
    ],
    "AVE-2026-00006": [
        {
            "tag": "MITRE ATT&CK T1657",
            "text": "MITRE ATT&CK — T1657: Financial Theft",
            "url": "https://attack.mitre.org/techniques/T1657/",
        },
        {
            "tag": "CWE-284",
            "text": "CWE-284: Improper Access Control — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/284.html",
        },
        {
            "tag": "OWASP LLM Excessive Agency",
            "text": "OWASP Top 10 for LLM Applications — Excessive Agency",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00006 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00006",
        },
    ],
    "AVE-2026-00007": [
        {
            "tag": "Perez 2022",
            "text": "Perez & Ribeiro — Ignore Previous Prompt: Attack Techniques For Language Models (arXiv 2211.09527)",
            "url": "https://arxiv.org/abs/2211.09527",
        },
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00007 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00007",
        },
    ],
    "AVE-2026-00008": [
        {
            "tag": "Cohen 2024",
            "text": "Cohen et al. — Here Comes The AI Worm: Unleashing Zero-click Worms that Target GenAI-Powered Applications (arXiv 2403.02817)",
            "url": "https://arxiv.org/abs/2403.02817",
        },
        {
            "tag": "MITRE ATLAS AML.T0010",
            "text": "MITRE ATLAS — ML Supply Chain Compromise (AML.T0010)",
            "url": "https://atlas.mitre.org/techniques/AML.T0010",
        },
        {
            "tag": "CWE-494",
            "text": "CWE-494: Download of Code Without Integrity Check — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/494.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00008 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00008",
        },
    ],
    "AVE-2026-00009": [
        {
            "tag": "Wei 2023",
            "text": "Wei et al. — Jailbroken: How Does LLM Safety Training Fail? (arXiv 2307.02483)",
            "url": "https://arxiv.org/abs/2307.02483",
        },
        {
            "tag": "Zou 2023",
            "text": "Zou et al. — Universal and Transferable Adversarial Attacks on Aligned Language Models (arXiv 2307.15043)",
            "url": "https://arxiv.org/abs/2307.15043",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00009 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00009",
        },
    ],
    "AVE-2026-00010": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "Perez 2022",
            "text": "Perez & Ribeiro — Ignore Previous Prompt: Attack Techniques For Language Models (arXiv 2211.09527)",
            "url": "https://arxiv.org/abs/2211.09527",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00010 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00010",
        },
    ],
    "AVE-2026-00011": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "CWE-20",
            "text": "CWE-20: Improper Input Validation — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/20.html",
        },
        {
            "tag": "OWASP LLM Excessive Agency",
            "text": "OWASP Top 10 for LLM Applications — Excessive Agency",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00011 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00011",
        },
    ],
    "AVE-2026-00012": [
        {
            "tag": "CWE-269",
            "text": "CWE-269: Improper Privilege Management — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/269.html",
        },
        {
            "tag": "MITRE ATT&CK T1548",
            "text": "MITRE ATT&CK — T1548: Abuse Elevation Control Mechanism",
            "url": "https://attack.mitre.org/techniques/T1548/",
        },
        {
            "tag": "OWASP LLM Excessive Agency",
            "text": "OWASP Top 10 for LLM Applications — Excessive Agency",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00012 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00012",
        },
    ],
    "AVE-2026-00013": [
        {
            "tag": "CWE-359",
            "text": "CWE-359: Exposure of Private Personal Information to an Unauthorized Actor — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/359.html",
        },
        {
            "tag": "CWE-200",
            "text": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
            "url": "https://cwe.mitre.org/data/definitions/200.html",
        },
        {
            "tag": "OWASP LLM Sensitive Info",
            "text": "OWASP Top 10 for LLM Applications — Sensitive Information Disclosure",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00013 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00013",
        },
    ],
    "AVE-2026-00014": [
        {
            "tag": "CWE-290",
            "text": "CWE-290: Authentication Bypass by Spoofing — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/290.html",
        },
        {
            "tag": "MITRE ATT&CK T1656",
            "text": "MITRE ATT&CK — T1656: Impersonation",
            "url": "https://attack.mitre.org/techniques/T1656/",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00014 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00014",
        },
    ],
    "AVE-2026-00015": [
        {
            "tag": "Perez 2022",
            "text": "Perez & Ribeiro — Ignore Previous Prompt: Attack Techniques For Language Models (arXiv 2211.09527)",
            "url": "https://arxiv.org/abs/2211.09527",
        },
        {
            "tag": "CWE-200",
            "text": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
            "url": "https://cwe.mitre.org/data/definitions/200.html",
        },
        {
            "tag": "OWASP LLM System Prompt Leakage",
            "text": "OWASP Top 10 for LLM Applications — System Prompt Leakage",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00015 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00015",
        },
    ],
    "AVE-2026-00016": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "Zou 2024",
            "text": "Zou et al. — PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models (arXiv 2402.07867)",
            "url": "https://arxiv.org/abs/2402.07867",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00016 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00016",
        },
    ],
    "AVE-2026-00017": [
        {
            "tag": "CWE-290",
            "text": "CWE-290: Authentication Bypass by Spoofing — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/290.html",
        },
        {
            "tag": "MITRE ATLAS AML.T0010",
            "text": "MITRE ATLAS — ML Supply Chain Compromise (AML.T0010)",
            "url": "https://atlas.mitre.org/techniques/AML.T0010",
        },
        {
            "tag": "OWASP MCP Top 10",
            "text": "OWASP MCP Security Top 10 — Tool Poisoning and Server Impersonation",
            "url": "https://owasp.org/www-project-mcp-security-top-10/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00017 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00017",
        },
    ],
    "AVE-2026-00018": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "OWASP LLM Insecure Output",
            "text": "OWASP Top 10 for LLM Applications — Insecure Output Handling",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "CWE-20",
            "text": "CWE-20: Improper Input Validation — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/20.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00018 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00018",
        },
    ],
    "AVE-2026-00019": [
        {
            "tag": "Cohen 2024",
            "text": "Cohen et al. — Here Comes The AI Worm: Unleashing Zero-click Worms that Target GenAI-Powered Applications (arXiv 2403.02817)",
            "url": "https://arxiv.org/abs/2403.02817",
        },
        {
            "tag": "Zou 2024",
            "text": "Zou et al. — PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models (arXiv 2402.07867)",
            "url": "https://arxiv.org/abs/2402.07867",
        },
        {
            "tag": "MITRE ATLAS AML.T0020",
            "text": "MITRE ATLAS — Poison Training Data (AML.T0020)",
            "url": "https://atlas.mitre.org/techniques/AML.T0020",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00019 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00019",
        },
    ],
    "AVE-2026-00020": [
        {
            "tag": "Cohen 2024",
            "text": "Cohen et al. — Here Comes The AI Worm: Unleashing Zero-click Worms that Target GenAI-Powered Applications (arXiv 2403.02817)",
            "url": "https://arxiv.org/abs/2403.02817",
        },
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00020 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00020",
        },
    ],
    "AVE-2026-00021": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "OWASP LLM Excessive Agency",
            "text": "OWASP Top 10 for LLM Applications — Excessive Agency",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "CWE-284",
            "text": "CWE-284: Improper Access Control — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/284.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00021 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00021",
        },
    ],
    "AVE-2026-00022": [
        {
            "tag": "CWE-269",
            "text": "CWE-269: Improper Privilege Management — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/269.html",
        },
        {
            "tag": "OWASP LLM Excessive Agency",
            "text": "OWASP Top 10 for LLM Applications — Excessive Agency",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "MITRE ATT&CK T1548",
            "text": "MITRE ATT&CK — T1548: Abuse Elevation Control Mechanism",
            "url": "https://attack.mitre.org/techniques/T1548/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00022 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00022",
        },
    ],
    "AVE-2026-00023": [
        {
            "tag": "Perez 2022",
            "text": "Perez & Ribeiro — Ignore Previous Prompt: Attack Techniques For Language Models (arXiv 2211.09527)",
            "url": "https://arxiv.org/abs/2211.09527",
        },
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00023 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00023",
        },
    ],
    "AVE-2026-00024": [
        {
            "tag": "CWE-434",
            "text": "CWE-434: Unrestricted Upload of File with Dangerous Type — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/434.html",
        },
        {
            "tag": "MITRE ATLAS AML.T0010",
            "text": "MITRE ATLAS — ML Supply Chain Compromise (AML.T0010)",
            "url": "https://atlas.mitre.org/techniques/AML.T0010",
        },
        {
            "tag": "CWE-20",
            "text": "CWE-20: Improper Input Validation — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/20.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00024 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00024",
        },
    ],
    "AVE-2026-00025": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "Perez 2022",
            "text": "Perez & Ribeiro — Ignore Previous Prompt: Attack Techniques For Language Models (arXiv 2211.09527)",
            "url": "https://arxiv.org/abs/2211.09527",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00025 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00025",
        },
    ],
    "AVE-2026-00026": [
        {
            "tag": "CWE-116",
            "text": "CWE-116: Improper Encoding or Escaping of Output — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/116.html",
        },
        {
            "tag": "CWE-514",
            "text": "CWE-514: Covert Channel — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/514.html",
        },
        {
            "tag": "OWASP LLM Sensitive Info",
            "text": "OWASP Top 10 for LLM Applications — Sensitive Information Disclosure",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00026 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00026",
        },
    ],
    "AVE-2026-00027": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "Perez 2022",
            "text": "Perez & Ribeiro — Ignore Previous Prompt: Attack Techniques For Language Models (arXiv 2211.09527)",
            "url": "https://arxiv.org/abs/2211.09527",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00027 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00027",
        },
    ],
    "AVE-2026-00028": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "Perez 2022",
            "text": "Perez & Ribeiro — Ignore Previous Prompt: Attack Techniques For Language Models (arXiv 2211.09527)",
            "url": "https://arxiv.org/abs/2211.09527",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00028 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00028",
        },
    ],
    "AVE-2026-00029": [
        {
            "tag": "Boucher 2021",
            "text": "Boucher et al. — Trojan Source: Invisible Vulnerabilities (arXiv 2111.00169)",
            "url": "https://arxiv.org/abs/2111.00169",
        },
        {
            "tag": "CVE-2021-42574",
            "text": "CVE-2021-42574 — Trojan Source: Bidirectional Unicode text control character injection in source code",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42574",
        },
        {
            "tag": "CWE-116",
            "text": "CWE-116: Improper Encoding or Escaping of Output — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/116.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00029 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00029",
        },
    ],
    "AVE-2026-00030": [
        {
            "tag": "CWE-290",
            "text": "CWE-290: Authentication Bypass by Spoofing — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/290.html",
        },
        {
            "tag": "CWE-269",
            "text": "CWE-269: Improper Privilege Management — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/269.html",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00030 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00030",
        },
    ],
    "AVE-2026-00031": [
        {
            "tag": "Wan 2023",
            "text": "Wan et al. — Poisoning Language Models During Instruction Tuning (arXiv 2305.00944)",
            "url": "https://arxiv.org/abs/2305.00944",
        },
        {
            "tag": "MITRE ATLAS AML.T0020",
            "text": "MITRE ATLAS — Poison Training Data (AML.T0020)",
            "url": "https://atlas.mitre.org/techniques/AML.T0020",
        },
        {
            "tag": "CWE-20",
            "text": "CWE-20: Improper Input Validation — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/20.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00031 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00031",
        },
    ],
    "AVE-2026-00032": [
        {
            "tag": "CWE-918",
            "text": "CWE-918: Server-Side Request Forgery (SSRF) — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/918.html",
        },
        {
            "tag": "MITRE ATT&CK T1595",
            "text": "MITRE ATT&CK — T1595: Active Scanning",
            "url": "https://attack.mitre.org/techniques/T1595/",
        },
        {
            "tag": "OWASP A10:2021",
            "text": "OWASP Top 10:2021 — A10: Server-Side Request Forgery (SSRF)",
            "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00032 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00032",
        },
    ],
    "AVE-2026-00033": [
        {
            "tag": "CWE-502",
            "text": "CWE-502: Deserialization of Untrusted Data — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/502.html",
        },
        {
            "tag": "CWE-94",
            "text": "CWE-94: Improper Control of Generation of Code ('Code Injection')",
            "url": "https://cwe.mitre.org/data/definitions/94.html",
        },
        {
            "tag": "OWASP A08:2021",
            "text": "OWASP Top 10:2021 — A08: Software and Data Integrity Failures",
            "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00033 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00033",
        },
    ],
    "AVE-2026-00034": [
        {
            "tag": "CWE-829",
            "text": "CWE-829: Inclusion of Functionality from Untrusted Control Sphere — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/829.html",
        },
        {
            "tag": "MITRE ATLAS AML.T0010",
            "text": "MITRE ATLAS — ML Supply Chain Compromise (AML.T0010)",
            "url": "https://atlas.mitre.org/techniques/AML.T0010",
        },
        {
            "tag": "CWE-494",
            "text": "CWE-494: Download of Code Without Integrity Check — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/494.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00034 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00034",
        },
    ],
    "AVE-2026-00035": [
        {
            "tag": "MITRE ATLAS AML.T0020",
            "text": "MITRE ATLAS — Poison Training Data (AML.T0020)",
            "url": "https://atlas.mitre.org/techniques/AML.T0020",
        },
        {
            "tag": "Koh 2017",
            "text": "Koh & Liang — Understanding Black-box Predictions via Influence Functions (arXiv 1703.04730, ICML 2017)",
            "url": "https://arxiv.org/abs/1703.04730",
        },
        {
            "tag": "CWE-20",
            "text": "CWE-20: Improper Input Validation — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/20.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00035 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00035",
        },
    ],
    "AVE-2026-00036": [
        {
            "tag": "MITRE ATT&CK T1021",
            "text": "MITRE ATT&CK — T1021: Remote Services (Lateral Movement)",
            "url": "https://attack.mitre.org/techniques/T1021/",
        },
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "CWE-284",
            "text": "CWE-284: Improper Access Control — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/284.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00036 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00036",
        },
    ],
    "AVE-2026-00037": [
        {
            "tag": "Qi 2023",
            "text": "Qi et al. — Visual Adversarial Examples Jailbreak Aligned Large Language Models (arXiv 2306.13213)",
            "url": "https://arxiv.org/abs/2306.13213",
        },
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00037 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00037",
        },
    ],
    "AVE-2026-00038": [
        {
            "tag": "CWE-400",
            "text": "CWE-400: Uncontrolled Resource Consumption — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/400.html",
        },
        {
            "tag": "OWASP LLM Excessive Agency",
            "text": "OWASP Top 10 for LLM Applications — Excessive Agency",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "Cohen 2024",
            "text": "Cohen et al. — Here Comes The AI Worm: Unleashing Zero-click Worms that Target GenAI-Powered Applications (arXiv 2403.02817)",
            "url": "https://arxiv.org/abs/2403.02817",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00038 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00038",
        },
    ],
    "AVE-2026-00039": [
        {
            "tag": "CWE-514",
            "text": "CWE-514: Covert Channel — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/514.html",
        },
        {
            "tag": "CWE-385",
            "text": "CWE-385: Covert Timing Channel — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/385.html",
        },
        {
            "tag": "OWASP LLM Sensitive Info",
            "text": "OWASP Top 10 for LLM Applications — Sensitive Information Disclosure",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00039 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00039",
        },
    ],
    "AVE-2026-00040": [
        {
            "tag": "OWASP LLM Insecure Output",
            "text": "OWASP Top 10 for LLM Applications — Insecure Output Handling",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "CWE-116",
            "text": "CWE-116: Improper Encoding or Escaping of Output — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/116.html",
        },
        {
            "tag": "CWE-79",
            "text": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "url": "https://cwe.mitre.org/data/definitions/79.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00040 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00040",
        },
    ],
    "AVE-2026-00041": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "MCP Security Best Practices",
            "text": "Model Context Protocol — Security Best Practices (specification)",
            "url": "https://spec.modelcontextprotocol.io/specification/security_best_practices/",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "OWASP MCP Top 10",
            "text": "OWASP MCP Security Top 10 — Tool Poisoning",
            "url": "https://owasp.org/www-project-mcp-security-top-10/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00041 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00041",
        },
    ],
    "AVE-2026-00042": [
        {
            "tag": "CWE-94",
            "text": "CWE-94: Improper Control of Generation of Code ('Code Injection')",
            "url": "https://cwe.mitre.org/data/definitions/94.html",
        },
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "OWASP LLM Insecure Output",
            "text": "OWASP Top 10 for LLM Applications — Insecure Output Handling",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00042 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00042",
        },
    ],
    "AVE-2026-00043": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "CWE-79",
            "text": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "url": "https://cwe.mitre.org/data/definitions/79.html",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00043 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00043",
        },
    ],
    "AVE-2026-00044": [
        {
            "tag": "Greshake 2023",
            "text": "Greshake et al. — Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections (arXiv 2302.12173)",
            "url": "https://arxiv.org/abs/2302.12173",
        },
        {
            "tag": "CWE-20",
            "text": "CWE-20: Improper Input Validation — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/20.html",
        },
        {
            "tag": "OWASP LLM01",
            "text": "OWASP Top 10 for LLM Applications — LLM01: Prompt Injection",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00044 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00044",
        },
    ],
    "AVE-2026-00045": [
        {
            "tag": "CWE-269",
            "text": "CWE-269: Improper Privilege Management — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/269.html",
        },
        {
            "tag": "OWASP LLM Excessive Agency",
            "text": "OWASP Top 10 for LLM Applications — Excessive Agency",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "OWASP MCP Top 10",
            "text": "OWASP MCP Security Top 10 — Insufficient Access Controls",
            "url": "https://owasp.org/www-project-mcp-security-top-10/",
        },
        {
            "tag": "MCP Authorization Spec",
            "text": "Model Context Protocol — Authorization specification",
            "url": "https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00045 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00045",
        },
    ],
    "AVE-2026-00046": [
        {
            "tag": "CWE-601",
            "text": "CWE-601: URL Redirection to Untrusted Site ('Open Redirect') — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/601.html",
        },
        {
            "tag": "CWE-918",
            "text": "CWE-918: Server-Side Request Forgery (SSRF) — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/918.html",
        },
        {
            "tag": "MCP Security Best Practices",
            "text": "Model Context Protocol — Security Best Practices (specification)",
            "url": "https://spec.modelcontextprotocol.io/specification/security_best_practices/",
        },
        {
            "tag": "OWASP MCP Top 10",
            "text": "OWASP MCP Security Top 10 — Tool Poisoning",
            "url": "https://owasp.org/www-project-mcp-security-top-10/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00046 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00046",
        },
    ],
    "AVE-2026-00047": [
        {
            "tag": "CWE-798",
            "text": "CWE-798: Use of Hard-coded Credentials — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/798.html",
        },
        {
            "tag": "CWE-259",
            "text": "CWE-259: Use of Hard-coded Password — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/259.html",
        },
        {
            "tag": "Meli 2019",
            "text": "Meli et al. — How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories (NDSS 2019)",
            "url": "https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/",
        },
        {
            "tag": "OWASP LLM Sensitive Info",
            "text": "OWASP Top 10 for LLM Applications — Sensitive Information Disclosure",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00047 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00047",
        },
    ],
    "AVE-2026-00048": [
        {
            "tag": "CWE-269",
            "text": "CWE-269: Improper Privilege Management — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/269.html",
        },
        {
            "tag": "OWASP LLM Excessive Agency",
            "text": "OWASP Top 10 for LLM Applications — Excessive Agency",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "tag": "Cohen 2024",
            "text": "Cohen et al. — Here Comes The AI Worm: Unleashing Zero-click Worms that Target GenAI-Powered Applications (arXiv 2403.02817)",
            "url": "https://arxiv.org/abs/2403.02817",
        },
        {
            "tag": "CWE-284",
            "text": "CWE-284: Improper Access Control — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/284.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00048 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00048",
        },
    ],
    "AVE-2026-00049": [
        {
            "tag": "OWASP Host Header Testing",
            "text": "OWASP Web Security Testing Guide — Testing for Host Header Injection (WSTG-INPV-17)",
            "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection",
        },
        {
            "tag": "CWE-644",
            "text": "CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax",
            "url": "https://cwe.mitre.org/data/definitions/644.html",
        },
        {
            "tag": "CWE-20",
            "text": "CWE-20: Improper Input Validation — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/20.html",
        },
        {
            "tag": "PortSwigger",
            "text": "PortSwigger Web Security Academy — HTTP Host header attacks",
            "url": "https://portswigger.net/web-security/host-header",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00049 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00049",
        },
    ],
    "AVE-2026-00050": [
        {
            "tag": "CWE-114",
            "text": "CWE-114: Process Control — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/114.html",
        },
        {
            "tag": "CWE-284",
            "text": "CWE-284: Improper Access Control — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/284.html",
        },
        {
            "tag": "MCP Security Best Practices",
            "text": "Model Context Protocol — Security Best Practices (specification)",
            "url": "https://spec.modelcontextprotocol.io/specification/security_best_practices/",
        },
        {
            "tag": "OWASP MCP Top 10",
            "text": "OWASP MCP Security Top 10 — Tool Poisoning and Unauthorized Tool Registration",
            "url": "https://owasp.org/www-project-mcp-security-top-10/",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00050 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00050",
        },
    ],
    "AVE-2026-00051": [
        {
            "tag": "RFC 8414",
            "text": "RFC 8414 — OAuth 2.0 Authorization Server Metadata (IETF)",
            "url": "https://datatracker.ietf.org/doc/html/rfc8414",
        },
        {
            "tag": "RFC 7636",
            "text": "RFC 7636 — Proof Key for Code Exchange by OAuth Public Clients (PKCE)",
            "url": "https://datatracker.ietf.org/doc/html/rfc7636",
        },
        {
            "tag": "MCP OAuth Spec",
            "text": "Model Context Protocol — Authorization specification (OAuth 2.0 flow)",
            "url": "https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/",
        },
        {
            "tag": "CWE-601",
            "text": "CWE-601: URL Redirection to Untrusted Site ('Open Redirect') — MITRE Common Weakness Enumeration",
            "url": "https://cwe.mitre.org/data/definitions/601.html",
        },
        {
            "tag": "AVE Registry",
            "text": "AVE-2026-00051 — AVE behavioral vulnerability registry",
            "url": "https://api.piranha.bawbel.io/records/AVE-2026-00051",
        },
    ],
}

records_dir = os.path.join(os.path.dirname(__file__), "..", "records")
updated = 0
errors = []

for ave_id, new_refs in REFS.items():
    path = os.path.join(records_dir, f"{ave_id}.json")
    if not os.path.exists(path):
        errors.append(f"NOT FOUND: {path}")
        continue
    with open(path) as f:
        record = json.load(f)
    record["references"] = new_refs
    with open(path, "w") as f:
        json.dump(record, f, indent=2)
        f.write("\n")
    updated += 1

print(f"Updated {updated} records. Errors: {len(errors)}")
for e in errors:
    print(" ", e)
