# AI/ML Model Design

## Objectives

- Detect insider threats and anomalous endpoint behavior in near real time.
- Produce explainable risk scores (0–100) and insider threat probability.

## Feature Families

- Temporal: login hour entropy, weekday/weekend variance.
- Access: sensitive directory touch frequency, privilege elevation rate.
- Process: parent-child novelty score, script interpreter abuse.
- Network: outbound volume z-score, beacon periodicity confidence.
- Endpoint health: CPU/memory anomalies, service persistence indicators.
- Peer-group: deviation from role-based centroid.

## Models

1. **Isolation Forest** for unsupervised outlier detection.
2. **Sequence Autoencoder** for time-window reconstruction error.
3. **Bayesian Risk Fusion** to combine model and rules outputs.
4. **Graph Embedding + Link Prediction** for user-device-lateral movement anomalies.

## Training and Retraining

- Initial baseline: 14–30 days per user and role cohort.
- Hourly incremental updates for online features.
- Daily retrain window for unsupervised models.
- Weekly drift detection on KL divergence + feature PSI.

## Explainability

- SHAP for tree-based model feature attributions.
- LIME fallback for local anomaly explanations.
- Analyst-facing rationale: top-5 contributing behaviors with confidence bands.

## Model Governance

- Model registry with version, checksum, training data scope.
- Signed model artifacts before deployment.
- Canary rollout to subset tenants.
- Automated rollback on precision/recall degradation thresholds.
