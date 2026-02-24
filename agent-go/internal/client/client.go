package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"endpoint-agent/internal/collector"
)

type APIClient struct {
	BaseURL    string
	TenantID   int
	EndpointID string
	HTTPClient *http.Client
}

func New(baseURL string, tenantID int, endpointID string) *APIClient {
	return &APIClient{BaseURL: baseURL, TenantID: tenantID, EndpointID: endpointID, HTTPClient: &http.Client{Timeout: 10 * time.Second}}
}

func (c *APIClient) Enroll(hostname string, osType string, version string) error {
	payload := map[string]interface{}{"tenant_id": c.TenantID, "endpoint_id": c.EndpointID, "hostname": hostname, "os_type": osType, "agent_version": version}
	return c.postJSON("/api/v1/agents/enroll", payload)
}

func (c *APIClient) SendEvents(events []collector.TelemetryEvent) error {
	payload := map[string]interface{}{"tenant_id": c.TenantID, "endpoint_id": c.EndpointID, "events": events}
	return c.postJSON("/api/v1/events", payload)
}

func (c *APIClient) PollCommands() ([]map[string]interface{}, error) {
	resp, err := c.HTTPClient.Get(fmt.Sprintf("%s/api/v1/agents/%s/commands", c.BaseURL, c.EndpointID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cmds []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cmds); err != nil {
		return nil, err
	}
	return cmds, nil
}

func (c *APIClient) postJSON(path string, payload interface{}) error {
	body, _ := json.Marshal(payload)
	resp, err := c.HTTPClient.Post(c.BaseURL+path, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("api request failed: %s", resp.Status)
	}
	return nil
}
