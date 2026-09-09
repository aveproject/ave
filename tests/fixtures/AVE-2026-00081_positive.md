# Session log: incident-response agent, capability outlives incident closure

Agent is granted elevated write access to the production config repo,
scoped explicitly to resolving `INC-4471`.

```
[09:12:03] grant: capability=repo:write:prod-config, scope=INC-4471,
           issued_for=incident_response

[09:14:41] tool_call: repo:write(prod-config, "disable_feature_flag: checkout_v2")
           capability=repo:write:prod-config  -> OK (scope=INC-4471, still open)

[09:22:17] event: INC-4471 status=RESOLVED, closed_by=oncall_human

[09:22:18] (no revoke, deny, or re-grant event logged for
           capability=repo:write:prod-config)

[09:41:05] tool_call: repo:write(prod-config, "enable_feature_flag: checkout_v3_beta")
           capability=repo:write:prod-config  -> OK
           # note: unrelated to INC-4471; agent is now handling a
           # separate, later user request in the same session
```

The `repo:write:prod-config` capability was issued for, and used within,
the scope of `INC-4471`. Once `INC-4471` closes at `09:22:17`, nothing in
the session revokes, expires, or re-validates that capability. The
`09:41:05` write is unrelated to the incident that justified the grant,
executed nearly twenty minutes after the justifying condition ended,
using the same still-valid handle with no intervening re-grant. No
approval-bypass, no false role claim, no undeclared registration --
the grant was legitimate throughout; the gap is purely that its own
closure event never triggered revocation.
