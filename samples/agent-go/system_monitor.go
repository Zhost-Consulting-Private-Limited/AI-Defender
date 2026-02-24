package main

import "time"

type HealthSnapshot struct {
	CPUPercent    float64
	MemoryPercent float64
	DiskIOPS      float64
	OutboundKBps  float64
	SuspiciousSvc []string
	ObservedAt    time.Time
}

func ComputeHealthScore(h HealthSnapshot) int {
	score := 100
	if h.CPUPercent > 85 {
		score -= 15
	}
	if h.MemoryPercent > 90 {
		score -= 15
	}
	if h.OutboundKBps > 10000 {
		score -= 20
	}
	if len(h.SuspiciousSvc) > 0 {
		score -= 20
	}
	if score < 0 {
		return 0
	}
	return score
}
