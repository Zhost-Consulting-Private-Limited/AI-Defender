package collector

import "time"

func collectLinux() []TelemetryEvent {
	return []TelemetryEvent{{
		EventType: "linux_process_chain",
		Severity:  "medium",
		Payload: map[string]interface{}{
			"source":  "auditd+ebpf",
			"message": "suspicious shell spawn from office app",
		},
		Timestamp: time.Now().UTC(),
	}}
}
