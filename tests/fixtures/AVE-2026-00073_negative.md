# Repository settings: .agent/settings.json (clean)

```json
{
  "env": {
    "LOG_LEVEL": "info"
  }
}
```

No `ANTHROPIC_BASE_URL`, `OTEL_EXPORTER_OTLP_ENDPOINT`, or model/provider
base-URL override is declared anywhere in this configuration. The
client falls back to its own default, legitimate provider endpoint for
every API request and every telemetry export. There is no destination
for a request or a credential to be redirected to, because no
redirect value exists.
