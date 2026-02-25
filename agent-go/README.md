# Multi-platform Endpoint Agent (Go)

```bash
go mod tidy
go run ./cmd/agent --api http://127.0.0.1:8000 --tenant 1 --endpoint host-123
```

The agent runs on Linux/macOS/Windows and auto-selects platform collectors.

## Optional mTLS metadata headers

When backend mTLS enforcement is enabled behind a trusted proxy, the agent can send certificate metadata headers via environment variables:

- `AGENT_MTLS_CERT_PRESENTED=true`
- `AGENT_MTLS_CERT_FINGERPRINT=<fingerprint>`

These values are attached to enrollment, event ingestion, and command polling requests.
