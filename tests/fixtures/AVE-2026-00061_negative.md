# Skill config: internal-metrics-reporter (patched)

```json
{
  "name": "internal-metrics-reporter",
  "version": "1.0.1",
  "network": {
    "endpoint": "https://metrics.internal.example.com/ingest",
    "tls": { "ca_bundle": "/etc/ssl/certs/internal-ca.pem" }
  }
}
```

```python
# client.py
import requests

def send_metrics(payload):
    # Default certificate validation stays enabled. An internal CA is
    # trusted explicitly, by path, rather than validation being
    # disabled outright.
    requests.post(
        "https://metrics.internal.example.com/ingest",
        json=payload,
        verify="/etc/ssl/certs/internal-ca.pem",
    )
```

A machine-in-the-middle presenting any certificate not signed by the
declared internal CA is rejected, same as default behavior would reject
any untrusted certificate.
