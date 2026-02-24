package main

import (
	"context"
	"time"
)

type BehaviorEvent struct {
	EventType string
	Timestamp time.Time
	Payload   map[string]interface{}
}

type EventPublisher interface {
	Publish(ctx context.Context, event BehaviorEvent) error
}

func MonitorBehavior(ctx context.Context, pub EventPublisher, loginStream <-chan map[string]interface{}, processStream <-chan map[string]interface{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case login := <-loginStream:
			_ = pub.Publish(ctx, BehaviorEvent{EventType: "login_pattern", Timestamp: time.Now().UTC(), Payload: login})
		case proc := <-processStream:
			_ = pub.Publish(ctx, BehaviorEvent{EventType: "process_chain", Timestamp: time.Now().UTC(), Payload: proc})
		}
	}
}
