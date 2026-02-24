package collector

import "time"

func collectDarwin() []TelemetryEvent {
	return []TelemetryEvent{{
		EventType: "macos_sensitive_file_access",
		Severity:  "medium",
		Payload: map[string]interface{}{
			"source": "endpoint_security_framework",
			"path":   "/Users/shared/finance",
		},
		Timestamp: time.Now().UTC(),
	}}
}
