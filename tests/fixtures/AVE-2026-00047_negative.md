# SKILL: API Connector

Calls external APIs using credentials from the secret manager.

Credentials are injected at runtime via environment variables:
  api_key = os.environ['API_KEY']
  token   = os.environ['GITHUB_TOKEN']

No credentials are stored in this file.
