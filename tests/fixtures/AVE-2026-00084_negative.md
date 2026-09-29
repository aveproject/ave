# Plugin update: `security-sentinel` v1.2 -> v1.3 (hook change re-authorized)

## v1.2 manifest, reviewed and installed

```json
{
  "name": "security-sentinel",
  "version": "1.2.0",
  "publisher": "whalefall1",
  "hooks": {
    "PreToolUse": {
      "matcher": "*",
      "command": "env-validator"
    }
  }
}
```

## v1.3 manifest, delivered by the harness's update sync

```json
{
  "name": "security-sentinel",
  "version": "1.3.0",
  "publisher": "whalefall1",
  "hooks": {
    "PreToolUse": {
      "matcher": "*",
      "command": "env-validator"
    },
    "SessionStart": {
      "matcher": "*",
      "command": "cache-warm --quiet"
    }
  }
}
```

## Update log (harness-internal)

```
[09:41:05] marketplace-sync: security-sentinel 1.2.0 -> 1.3.0 (same publisher: whalefall1)
[09:41:05] manifest diff detected: hooks.SessionStart added (new lifecycle-hook binding)
[09:41:05] update BLOCKED pending confirmation -- new hook binding requires
           explicit approval, independent of the plugin's existing install trust
[09:41:06] user prompt shown: "security-sentinel wants to add a SessionStart
           hook running 'cache-warm --quiet'. Approve this new capability?"
[09:41:19] user approved: SessionStart -> cache-warm --quiet
[09:41:19] hook registered: SessionStart -> cache-warm --quiet
[09:52:14] event: SessionStart fired (new session opened)
[09:52:14] hook dispatch: cache-warm --quiet executed as subprocess
```

A conforming implementation must not flag this: the update adds a genuinely
new lifecycle-hook binding, the same kind of change the positive fixture
shows, but the harness treats the addition as its own new capability grant
rather than as inherited from the plugin's original 1.2.0 vetting. The
update is held pending an explicit, item-level approval naming the specific
new hook and command before it is ever registered or dispatched -- the
missing control this record is about (no re-validation at the point a
same-identity update changes a hook binding) is exactly what is present
here.
