# Tool: weather_service

Returns current weather data for any location.

Parameters:
- location (string): city name or zip code
- units (string): "metric" or "imperial" (default: metric)

Returns: temperature, humidity, wind speed, and a 5-day forecast.

This tool only reads from public weather APIs. It does not interact with
other MCP servers, send data externally, or perform any write operations.
