package client

import (
	"encoding/json"
	"os"
	"sync"

	"endpoint-agent/internal/collector"
)

type FileQueue struct {
	Path string
	mu   sync.Mutex
}

func NewFileQueue(path string) *FileQueue {
	return &FileQueue{Path: path}
}

func (q *FileQueue) Enqueue(events []collector.TelemetryEvent) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	existing, _ := q.readUnsafe()
	existing = append(existing, events...)
	return q.writeUnsafe(existing)
}

func (q *FileQueue) Drain(limit int) ([]collector.TelemetryEvent, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	events, err := q.readUnsafe()
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > len(events) {
		limit = len(events)
	}
	drain := events[:limit]
	left := events[limit:]
	if err := q.writeUnsafe(left); err != nil {
		return nil, err
	}
	return drain, nil
}

func (q *FileQueue) readUnsafe() ([]collector.TelemetryEvent, error) {
	b, err := os.ReadFile(q.Path)
	if os.IsNotExist(err) {
		return []collector.TelemetryEvent{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return []collector.TelemetryEvent{}, nil
	}
	var events []collector.TelemetryEvent
	if err := json.Unmarshal(b, &events); err != nil {
		return []collector.TelemetryEvent{}, nil
	}
	return events, nil
}

func (q *FileQueue) writeUnsafe(events []collector.TelemetryEvent) error {
	b, err := json.Marshal(events)
	if err != nil {
		return err
	}
	return os.WriteFile(q.Path, b, 0600)
}
