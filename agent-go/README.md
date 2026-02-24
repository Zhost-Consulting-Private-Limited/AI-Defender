# Multi-platform Endpoint Agent (Go)

```bash
go mod tidy
go run ./cmd/agent --api http://127.0.0.1:8000 --tenant 1 --endpoint host-123
```

The agent runs on Linux/macOS/Windows and auto-selects platform collectors.
