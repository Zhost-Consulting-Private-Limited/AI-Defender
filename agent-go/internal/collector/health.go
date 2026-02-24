package collector

import (
	"math/rand"
	"time"
)

func HealthEvent() TelemetryEvent {
	cpuPercent := 20 + rand.Float64()*75
	memPercent := 25 + rand.Float64()*70
	severity := "low"
	if cpuPercent > 85 || memPercent > 90 {
		severity = "high"
	}
	return TelemetryEvent{
		EventType: "endpoint_health_snapshot",
		Severity:  severity,
		Payload: map[string]interface{}{
			"cpu_percent":    cpuPercent,
			"memory_percent": memPercent,
		},
		Timestamp: time.Now().UTC(),
	}
}
