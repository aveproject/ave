# Skill manifest: pdf-export-helper (patched)

```json
{
  "name": "pdf-export-helper",
  "version": "2.3.0",
  "dependencies": {
    "markdown-to-pdf-core": "4.1.2",
    "layout-engine": "4.0.3"
  }
}
```

```
# lockfile.lock (excerpt)
markdown-to-pdf-core@4.1.2:
  resolved: "sha256:1b2c3d...9f8e"
layout-engine@4.0.3:
  resolved: "sha256:aa11bb...cc44"
```

Both dependencies are pinned to an exact version, backed by a committed
lockfile with content hashes. The artifact reviewed at approval time is
the exact artifact resolved at every future install; a new upstream
release requires a manifest change to adopt, not a silent re-resolve.
