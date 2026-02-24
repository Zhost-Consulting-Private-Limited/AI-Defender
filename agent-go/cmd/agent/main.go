package main

import (
	"flag"
	"log"
	"os"
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
		cmds, err := cli.PollCommands()
		if err == nil && len(cmds) > 0 {
			log.Printf("received %d command(s)", len(cmds))
		}
		<-ticker.C
	}
}
