# Data Flow Diagram (Textual)

1. **Collection**: Endpoint collectors gather login/process/file/network/system-health signals.
2. **Normalization**: Agent converts platform-native events to a shared schema and tags tenant/device/user IDs.
3. **Protection**: Events are encrypted in transit (TLS 1.3 mTLS), signed, and queued locally if offline.
4. **Ingestion**: API validates cert, checks replay nonce, writes to Kafka topic partitions.
5. **Processing**: Stream processors enrich with IAM, threat intel, and peer-group metadata.
6. **Analytics**: UEBA and anomaly models generate risk deltas and explainability metadata.
7. **Storage**: Scores and policy states to PostgreSQL; event/search analytics to Elasticsearch.
8. **Reporting**: Hourly report service compiles risk changes, MITRE mapping, recommended actions.
9. **Distribution**: Dashboard, email, SIEM forwarding, and webhook push.
10. **Governance**: All admin actions and policy changes logged immutably for audit evidence.
