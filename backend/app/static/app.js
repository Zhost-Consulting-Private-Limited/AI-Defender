function headers() {
  return { 'X-API-Key': document.getElementById('api_key').value };
}

async function refreshAll() {
  const tenant = document.getElementById('tenant').value;
  const summary = await fetch(`/api/v1/dashboard/summary?tenant_id=${tenant}`, { headers: headers() }).then(r=>r.json());
  document.getElementById('agent_count').innerText = summary.agent_count ?? '-';
  document.getElementById('open_incidents').innerText = summary.open_incidents ?? '-';
  document.getElementById('avg_risk').innerText = summary.avg_risk ?? '-';

  const rt = document.querySelector('#risks tbody');
  rt.innerHTML = '';
  for (const r of (summary.top_risks || [])) {
    rt.innerHTML += `<tr><td>${r.endpoint_id}</td><td>${r.score}</td><td>${r.reason}</td><td>${r.at}</td></tr>`;
  }

  const incidents = await fetch(`/api/v1/incidents?tenant_id=${tenant}`, { headers: headers() }).then(r=>r.json());
  const it = document.querySelector('#incidents tbody');
  it.innerHTML = '';
  for (const i of incidents) {
    it.innerHTML += `<tr><td>${i.id}</td><td>${i.title}</td><td>${i.severity}</td><td>${i.status}</td><td><button onclick="closeIncident(${i.id})">Close</button></td></tr>`;
  }
}

async function closeIncident(id) {
  await fetch(`/api/v1/incidents/${id}/status?status=closed`, { method: 'PATCH', headers: headers() });
  refreshAll();
}

async function generateReport() {
  const tenant = document.getElementById('tenant').value;
  const result = await fetch(`/api/v1/reports/hourly?tenant_id=${tenant}`, { method: 'POST', headers: headers() }).then(r => r.json());
  alert(`Report generated with ${result.anomalies ?? 0} anomalies`);
}

refreshAll();
setInterval(refreshAll, 15000);
