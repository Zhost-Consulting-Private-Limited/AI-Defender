package collector

import (
	"runtime"
	"runtime/metrics"
	"time"
)

func HealthEvent() TelemetryEvent {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	samples := []metrics.Sample{{Name: "/sched/goroutines:goroutines"}, {Name: "/memory/classes/heap/free:bytes"}, {Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(samples)

	goroutines := uint64(runtime.NumGoroutine())
	heapFree := uint64(0)
	heapObjects := uint64(0)
	if len(samples) == 3 {
		if v := samples[0].Value; v.Kind() == metrics.KindUint64 {
			goroutines = v.Uint64()
		}
		if v := samples[1].Value; v.Kind() == metrics.KindUint64 {
			heapFree = v.Uint64()
		}
		if v := samples[2].Value; v.Kind() == metrics.KindUint64 {
			heapObjects = v.Uint64()
		}
	}

	severity := "low"
	if m.HeapAlloc > 512*1024*1024 || goroutines > 2000 {
		severity = "medium"
	}
	if m.HeapAlloc > 1024*1024*1024 || goroutines > 5000 {
		severity = "high"
	}

	return TelemetryEvent{
		EventType: "endpoint_health_snapshot",
		Severity:  severity,
		Payload: map[string]interface{}{
			"collector_mode":        "runtime_metrics",
			"go_routines":           goroutines,
			"go_heap_alloc_bytes":   m.HeapAlloc,
			"go_heap_sys_bytes":     m.HeapSys,
			"go_heap_free_bytes":    heapFree,
			"go_heap_objects_bytes": heapObjects,
			"go_gc_cycles":          m.NumGC,
			"go_cpu_count":          runtime.NumCPU(),
		},
		Timestamp: time.Now().UTC(),
	}
}
