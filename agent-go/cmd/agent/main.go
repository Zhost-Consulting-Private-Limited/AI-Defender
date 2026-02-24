package main

import (
	"flag"
	"log"
	"os"
<<<<<<< codex/design-enterprise-behavioral-security-platform
	"path/filepath"
=======
>>>>>>> main
	"runtime"
	"time"

	"endpoint-agent/internal/client"
	"endpoint-agent/internal/collector"
)

func main() {
	apiURL := flag.String("api", "http://127.0.0.1:8000", "API URL")
	tenantID := flag.Int("tenant", 1, "Tenant ID")
	endpointID := flag.String("endpoint", "endpoint-local", "Endpoint identifier")
	interval := flag.Duration("interval", 30*time.Second, "Collection interval")
	flag.Parse()

	hostname, _ := os.Hostname()
<<<<<<< codex/design-enterprise-behavioral-security-platform
	queuePath := filepath.Join(os.TempDir(), "agent_event_queue.json")
	queue := client.NewFileQueue(queuePath)
	cli := client.New(*apiURL, *tenantID, *endpointID)
	if err := cli.Enroll(hostname, runtime.GOOS, "2.1.0"); err != nil {
		log.Printf("enrollment failed, continue offline mode: %v", err)
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for {
		batch := collector.CollectPlatformEvents()
		batch = append(batch, collector.HealthEvent())
		if err := queue.Enqueue(batch); err != nil {
			log.Printf("queue enqueue failed: %v", err)
		}

		pending, err := queue.Drain(100)
		if err == nil && len(pending) > 0 {
			if err := cli.SendEvents(pending); err != nil {
				_ = queue.Enqueue(pending)
				log.Printf("send failed, queued for retry: %v", err)
			}
		}

=======
	cli := client.New(*apiURL, *tenantID, *endpointID)
	if err := cli.Enroll(hostname, runtime.GOOS, "2.0.0"); err != nil {
		log.Fatalf("enrollment failed: %v", err)
	}

	ticker := time.NewTicker(*interval)
	for {
		events := collector.CollectPlatformEvents()
		events = append(events, collector.HealthEvent())
		if err := cli.SendEvents(events); err != nil {
			log.Printf("send failed: %v", err)
		}
>>>>>>> main
		cmds, err := cli.PollCommands()
		if err == nil && len(cmds) > 0 {
			log.Printf("received %d command(s)", len(cmds))
		}
<<<<<<< codex/design-enterprise-behavioral-security-platform

=======
>>>>>>> main
		<-ticker.C
	}
}
