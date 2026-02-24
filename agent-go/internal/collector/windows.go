package collector

import "time"

func collectWindows() []TelemetryEvent {
	return []TelemetryEvent{{
		EventType: "windows_privilege_escalation",
		Severity:  "high",
		Payload: map[string]interface{}{
			"source": "etw+wmi",
			"event":  "new local admin membership",
		},
		Timestamp: time.Now().UTC(),
	}}
}
