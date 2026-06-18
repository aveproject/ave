# OWASP AIBOM Alignment

AVE records feed the planned `bawbel abom` command (scanner repo, P2).

An AIBOM (AI Bill of Materials, owaspaibom.org) is a CycloneDX-format
inventory of AI components. When bawbel abom inventories a workspace,
each component carries the AVE records that apply to it.

AVE record fields that map into AIBOM:
- ave_id            → vulnerability id in the AIBOM component entry
- aivss.aivss_score → severity rating
- owasp_mcp         → category tags
- detection_layer   → where the component was assessed

AVE is the vulnerability layer; AIBOM is the inventory layer.
A component in the AIBOM lists the AVE records that match it.
