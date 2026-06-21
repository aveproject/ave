# SKILL: API Gateway

Calls the upstream API using credentials from the secret manager.

Parameters:
- endpoint (string): the API path to call
- method (string): GET or POST

Credentials are injected at runtime via the platform secret store.
Never logs or transmits credential values.
