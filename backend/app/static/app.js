function headers() {
  return { 'X-API-Key': document.getElementById('api_key').value };
}

function selectedIncidentIds() {
  const checked = document.querySelectorAll('.incident-selector:checked');
  return Array.from(checked).map((input) => Number(input.value));
}

function currentIncidentFilters() {
  return {
    status: document.getElementById('incident_filter_status').value,
    severity: document.getElementById('incident_filter_severity').value,
    endpointId: document.getElementById('incident_filter_endpoint').value.trim(),
  };
}

async function fetchSummary(tenant) {
  const response = await fetch(`/api/v1/dashboard/summary?tenant_id=${tenant}`, { headers: headers() });
  if (!response.ok) {
    throw new Error(`summary request failed with ${response.status}`);
  }
  return response.json();
}

async function fetchIncidents(tenant) {
  const filters = currentIncidentFilters();
  const params = new URLSearchParams({ tenant_id: tenant });
  if (filters.status) params.set('status', filters.status);
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.endpointId) params.set('endpoint_id', filters.endpointId);

  const response = await fetch(`/api/v1/incidents?${params.toString()}`, { headers: headers() });
  if (!response.ok) {
    throw new Error(`incidents request failed with ${response.status}`);
  }
  return response.json();
}

function renderSummary(summary) {
  document.getElementById('agent_count').innerText = summary.agent_count ?? '-';
  document.getElementById('open_incidents').innerText = summary.open_incidents ?? '-';
  document.getElementById('avg_risk').innerText = summary.avg_risk ?? '-';

  const rt = document.querySelector('#risks tbody');
  rt.innerHTML = '';
  for (const r of (summary.top_risks || [])) {
    rt.innerHTML += `<tr><td>${r.endpoint_id}</td><td>${r.score}</td><td>${r.reason}</td><td>${r.at}</td></tr>`;
  }
}

function renderIncidents(incidents) {
  const it = document.querySelector('#incidents tbody');
  it.innerHTML = '';

  for (const i of incidents) {
    it.innerHTML += `
      <tr>
        <td><input type="checkbox" class="incident-selector" value="${i.id}" /></td>
        <td>${i.id}</td>
        <td>${i.title}</td>
        <td>${i.endpoint_id}</td>
        <td>${i.severity}</td>
        <td>${i.status}</td>
        <td>
          <button onclick="setIncidentStatus(${i.id}, 'in_progress')">Investigate</button>
          <button onclick="setIncidentStatus(${i.id}, 'closed')">Close</button>
          <button onclick="setIncidentStatus(${i.id}, 'open')">Reopen</button>
        </td>
      </tr>
    `;
  }
}

async function refreshAll() {
  try {
    const tenant = document.getElementById('tenant').value;
    const [summary, incidents] = await Promise.all([fetchSummary(tenant), fetchIncidents(tenant)]);
    renderSummary(summary);
    renderIncidents(incidents);
    document.getElementById('errors').innerText = '';
  } catch (err) {
    document.getElementById('errors').innerText = `Failed to refresh dashboard: ${err.message}`;
  }
}

async function setIncidentStatus(id, status) {
  await fetch(`/api/v1/incidents/${id}/status`, {
    method: 'PATCH',
    headers: { ...headers(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  refreshAll();
}

async function bulkSetIncidentStatus() {
  const tenant = Number(document.getElementById('tenant').value);
  const status = document.getElementById('bulk_status').value;
  const incidentIds = selectedIncidentIds();

  if (incidentIds.length === 0) {
    alert('Select at least one incident before applying bulk status updates.');
    return;
  }

  const response = await fetch('/api/v1/incidents/bulk-status', {
    method: 'POST',
    headers: { ...headers(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenant_id: tenant, incident_ids: incidentIds, status }),
  });

  if (!response.ok) {
    alert(`Bulk update failed with status ${response.status}`);
    return;
  }

  const result = await response.json();
  alert(`Updated ${result.updated} incidents to ${result.target_status}.`);
  refreshAll();
}

async function generateReport() {
  const tenant = document.getElementById('tenant').value;
  const result = await fetch(`/api/v1/reports/hourly?tenant_id=${tenant}`, {
    method: 'POST',
    headers: headers(),
  }).then((r) => r.json());
  alert(`Report generated with ${result.anomalies ?? 0} anomalies`);
}

refreshAll();
setInterval(refreshAll, 15000);
