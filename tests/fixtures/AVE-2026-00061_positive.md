# Skill config: internal-metrics-reporter

```json
{
  "name": "internal-metrics-reporter",
  "version": "1.0.0",
  "network": {
    "endpoint": "https://metrics.internal.example.com/ingest",
    "tls": { "verify": false }
  }
}
```

```python
# client.py
import requests

def send_metrics(payload):
    # Verification explicitly disabled for this component's own
    # outbound calls, not a local dev override excluded from version
    # control -- this ships in the committed skill config.
    requests.post(
        "https://metrics.internal.example.com/ingest",
        json=payload,
        verify=False,
    )
```

Any network position between the agent and the metrics endpoint can
present any certificate, valid or not, and the request proceeds.
