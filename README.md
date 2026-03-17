# CyberRakshak: Real-Time AI Cybersecurity Platform

CyberRakshak is a SOC-style, Dockerized cybersecurity analytics platform that combines:

- Airflow orchestration
- Spark-style batch/stream processing outputs
- AI/ML threat scoring and prediction reporting
- Multi-agent reasoning and consensus messages
- Live dashboard updates (near real-time)

The project is designed for demos, local development, and rapid iteration of threat analytics pipelines.

## What Is Implemented Now

Latest platform changes include:

- Real-time dashboard tabs with 1-second refresh behavior
- Dedicated "Live Agent Convo" tab for multi-agent conversation and reasoning
- Server-Sent Events endpoint for continuous agent message stream
- Dataset upload endpoint (CSV/JSON/Parquet)
- Dataset discovery + active dataset switching from `data/raw`
- Recalculation of ML/model/report artifacts based on selected active dataset
- Live metrics endpoint for continuously changing system/threat KPIs
- Split logs endpoints for Airflow, Spark, and Agent reasoning

## High-Level Flow

1. Dataset enters via upload API or selection from `data/raw`
2. Active dataset is normalized and stored as `data/raw/active_dataset_normalized.csv`
3. Batch/security artifacts are regenerated into `data/reports`
4. ML model report and threat predictions are recalculated
5. Agent decisions and live reasoning messages are refreshed
6. Frontend dashboard tabs poll and render new values automatically

## Tech Stack

- Backend: FastAPI
- Frontend: React + Vite
- Orchestration: Apache Airflow
- Processing: Spark containers + file-based report simulation
- Messaging: Kafka + Zookeeper
- Reverse proxy: NGINX
- Runtime: Docker Compose

## Main Dashboard Tabs

- System Overview
- Airflow Monitoring
- Spark Processing
- Dataset Processing
- ML Training
- Live Agent Convo
- Threat Intelligence
- System Logs

## Project Structure (Important Paths)

- `backend/` FastAPI APIs and runtime logic
- `frontend/` React dashboard
- `dags/` Airflow DAG definitions
- `ai_engine/` AI service endpoints
- `data/raw/` raw datasets and active normalized dataset
- `data/reports/` generated reports and ML outputs
- `data/delta/` delta-style processed outputs
- `logs/` service and pipeline logs

## Prerequisites

- Docker Desktop (Windows/Mac) or Docker Engine + Compose (Linux)
- At least 8 GB RAM recommended
- Ports available: `8088`, `15173`, `18000`, `18001`, `18081`, `18080`, `19092`, `12181`

## How To Run The Project

### 1. Clone and enter project

```bash
git clone <your-repo-url>
cd Cyberrakshak
```

### 2. Start all services

```bash
docker compose up -d --build
```

### 3. Check running services

```bash
docker compose ps
```

### 4. Open the dashboard

Preferred direct frontend URL:

- `http://localhost:15173/`

Optional gateway URL (via nginx):

- `http://localhost:8088/`

## Service URLs

- Frontend dashboard: `http://localhost:15173/`
- Backend health: `http://localhost:18000/health`
- Backend API root: `http://localhost:18000/api`
- AI engine health: `http://localhost:18001/health`
- Airflow UI: `http://localhost:18081/airflow/`
- Spark master UI: `http://localhost:18080/`

## Dataset Operations

### Upload new dataset

- Endpoint: `POST /api/upload-dataset`
- Supported formats: CSV, JSON, Parquet

### List discovered datasets

- Endpoint: `GET /api/datasets`

### Switch active dataset

- Endpoint: `POST /api/datasets/select`
- Body:

```json
{
	"path": "data/raw/security_input.csv"
}
```

Switching dataset triggers recalculation for reports and ML outputs.

## Core API Endpoints Used By Dashboard

- `GET /api/system/status`
- `GET /api/live-metrics`
- `GET /api/airflow/dags`
- `GET /api/airflow/runs`
- `GET /api/spark/jobs`
- `GET /api/dataset/stats`
- `GET /api/ml/models`
- `GET /api/ml/predictions`
- `GET /api/agents/status`
- `GET /api/agent-stream`
- `GET /api/threat/intelligence`
- `GET /api/system/logs`
- `GET /api/logs/airflow`
- `GET /api/logs/spark`
- `GET /api/logs/agents`

## Generated Outputs

- `data/reports/latest_batch_report.json`
- `data/reports/ml_model_report.json`
- `data/reports/threat_intelligence_latest.json`
- `data/reports/agent_decisions_latest.json`
- `data/processed/latest_processed_preview.csv`
- `data/stream_output/reports/latest_stream_report_security.json`

## Common Commands

Restart specific services:

```bash
docker compose restart backend-api frontend nginx
```

View live logs:

```bash
docker compose logs -f backend-api frontend airflow-webserver
```

Stop stack:

```bash
docker compose down
```

## Troubleshooting

If dashboard is blank:

1. Verify backend responds: `http://localhost:18000/health`
2. Verify frontend responds: `http://localhost:15173/`
3. Restart services: `docker compose restart backend-api frontend nginx`
4. If needed, rebuild frontend: `docker compose up -d --build frontend`

If ML tab shows stale values:

1. Check active dataset via `GET /api/datasets`
2. Switch dataset with `POST /api/datasets/select`
3. Re-open ML tab and confirm updated model metadata/source

## Notes For GitHub

- Do not commit generated data, logs, checkpoints, or local env files
- Keep only source code, config, and placeholder `.gitkeep` files under tracked artifact directories
