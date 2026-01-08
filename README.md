# Rusty-Swag

A Rust tool for discovering and testing Swagger/OpenAPI specifications. Automatically finds API endpoints, detects PII exposure, tests endpoints for basic function as defined by the YAML (*With custom headers as potentially necessary from WebApp), and generates sample HTTP requests from identified specifications. Provides a bit more flexibility to usage with other tools where using Burp's OpenAPI Extension isn't viable.

## Installation

```bash
cargo build --release
```

## Quick Start

```bash
# Basic scan
rusty-swag https://api.example.com

# Include POST/PUT/DELETE requests
rusty-swag https://api.example.com --risk

# Generate raw HTTP request files
rusty-swag https://api.example.com --samples

# Add custom headers
rusty-swag https://api.example.com -H "Authorization: Bearer token123"

# Use a proxy
rusty-swag https://api.example.com --proxy "http://127.0.0.1:8080"
```

## Key Features

- **Auto-discovery**: Checks common Swagger/OpenAPI spec locations
- **PII detection**: Scans for emails, phone numbers, SSNs, API keys, tokens, credit cards, etc.
- **Sample generation**: Creates individual HTTP request files for manual testing
- **Custom headers**: Add authentication or any headers to all requests
- **Proxy support**: HTTP, HTTPS, and SOCKS5 proxies
- **Rate limiting**: Configurable requests per second (default: 30)

## Common Options

```
rusty-swag [OPTIONS] <URLS>...

Options:
  -v, --verbose              Detailed output
  --risk                     Test POST/PUT/DELETE endpoints
  --all                      Show all status codes except 401/403
  --samples                  Generate HTTP request files
  --samples-dir <DIR>        Directory for samples (default: swagger-samples)
  -H, --header <HEADER>      Custom headers (can specify multiple)
  --proxy <PROXY_URL>        Route through proxy
  --rate <RATE>              Requests per second (default: 30)
  --stats                    Show scan statistics
  --json                     JSON output
```

## Examples

**Security assessment**:
```bash
rusty-swag https://api.example.com --risk --all --stats
```

**Generate test requests with auth**:
```bash
rusty-swag https://api.example.com --samples -H "Authorization: Bearer token"
```

**Scan multiple targets through proxy**:
```bash
rusty-swag api1.com api2.com --proxy "http://127.0.0.1:8080" --json
```

## Sample Files

The `--samples` flag creates raw HTTP request files in `swagger-samples/`:

```
001_get_api_users_20240108_143022.txt
002_post_api_login_20240108_143022.txt
```

Each file contains a properly formatted HTTP request ready to send via netcat, curl, fuzzers, or other tools.

## PII Detection

Automatically flags responses containing:
- Email addresses, phone numbers, SSNs, Credit cards
- API keys, AWS credentials, JWT tokens, private keys
- Common PII field names in JSON

## Notes

- Checks 20+ common spec locations automatically
- Custom headers apply to all requests
- Rate limiting prevents overwhelming APIs

## Disclaimer

For authorized security testing only. Get permission before scanning APIs you don't own.
