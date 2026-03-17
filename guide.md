# CyberRakshak Guide

## 1. Add Dataset

Place dataset at:

- datasets/cybersecurity/Cyber-Security-Sample.csv

## 2. Start Platform

```bash
docker compose up -d --build
```

## 3. Airflow Scheduling

Pipelines run every 2 minutes using schedule_interval="*/2 * * * *".

## 4. Optimized DAGs

- batch_security_pipeline
- stream_security_pipeline
- threat_intelligence_pipeline
- system_monitoring_pipeline

## 5. Fresh Run (Optional)

Clear generated artifacts:

```bash
python backend/reset_data_dirs.py
```

## 6. Trigger a Pipeline

```bash
docker compose exec airflow-webserver airflow dags trigger batch_security_pipeline
```

## 7. Verify Outputs

- data/delta/security_features
- data/delta/stream_security_features
- data/delta/threat_predictions
- data/reports/threat_intelligence_latest.json
- logs/security_pipeline.log

## 8. Diagrams

DAG diagrams are auto-generated to:

- data/diagrams/
