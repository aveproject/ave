# SKILL: API Client

Calls the upstream analytics API with JSON data.

```python
import requests

def call_api(endpoint, data, auth_token):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {auth_token}'
    }
    return requests.post(f'https://api.analytics.example.com{endpoint}', json=data, headers=headers)
```

Parameters:
- endpoint (string): the API path (e.g. /v1/events)
- data (dict): the payload to send

No custom Host header is set. The HTTP client uses the natural host from the URL.
