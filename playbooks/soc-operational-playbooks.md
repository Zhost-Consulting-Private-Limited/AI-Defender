# SOC Operational Playbooks

## Playbook 1: Abnormal Privilege Escalation

1. Validate user identity and recent IAM changes.
2. Review process chain and endpoint posture.
3. Correlate with sensitive file access in prior 24h.
4. Contain endpoint via EDR integration if risk > 85.
5. Open incident in ServiceNow/Jira with MITRE mapping.

## Playbook 2: Potential Ransomware Behavior

1. Trigger from mass rename + encryption pattern + CPU spike.
2. Isolate endpoint network access.
3. Capture volatile artifacts and process dump.
4. Block hash/domain indicators in SIEM/SOAR.
5. Initiate recovery and restoration workflow.

## Playbook 3: Data Exfiltration Anomaly

1. Confirm outbound spike and destination reputation.
2. Check USB/external storage activities.
3. Review archive creation and unusual working-hour activity.
4. Apply risk-based access constraints through IAM.
5. Escalate to insider threat investigation if repeated.

## Hourly Report Triage

- Review user/endpoint risk delta top 20.
- Confirm new MITRE techniques detected.
- Execute recommended action list within SLA windows.
