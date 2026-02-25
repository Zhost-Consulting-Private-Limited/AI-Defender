package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
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
	queuePath := filepath.Join(os.TempDir(), "agent_event_queue.json")
	queue := client.NewFileQueue(queuePath)
	cli := client.New(*apiURL, *tenantID, *endpointID)

	if err := cli.Enroll(hostname, runtime.GOOS, "2.2.0"); err != nil {
		log.Printf("enrollment failed, continuing in offline mode: %v", err)
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
		if err != nil {
			log.Printf("queue drain failed: %v", err)
		} else if len(pending) > 0 {
			if err := cli.SendEvents(pending); err != nil {
				_ = queue.Enqueue(pending)
				log.Printf("send failed, queued for retry: %v", err)
			}
		}

		if cmds, err := cli.PollCommands(); err == nil && len(cmds) > 0 {
			log.Printf("received %d command(s)", len(cmds))
		}

		<-ticker.C
	}
}
