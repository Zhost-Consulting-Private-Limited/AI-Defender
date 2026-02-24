package collector

import (
	"runtime"
	"time"
)

type TelemetryEvent struct {
	EventType string                 `json:"event_type"`
	Severity  string                 `json:"severity"`
	Payload   map[string]interface{} `json:"payload"`
	Timestamp time.Time              `json:"timestamp"`
}

func CollectPlatformEvents() []TelemetryEvent {
	switch runtime.GOOS {
	case "windows":
		return collectWindows()
	case "darwin":
		return collectDarwin()
	default:
		return collectLinux()
	}
}
