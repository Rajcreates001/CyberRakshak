# CyberRakshak Free-Tier Deployment (No Credit Card)

This setup deploys a judge-facing demo on a single frontend URL while keeping Airflow and Spark local for demonstrations.

## Architecture

- Frontend: Vercel
- Backend API: Render (Docker)
- AI Engine: Render (Docker)
- Database: Supabase PostgreSQL free tier
- Airflow + Spark + Kafka: Local-only runtime (metrics/log snapshots exposed by backend APIs)

## Required API Endpoints

The backend now exposes:

- /api/system/status
- /api/pipeline/airflow
- /api/analytics/spark
- /api/ai/predictions

Plus supporting endpoints used by the dashboard tabs:

- /api/airflow/dags
- /api/airflow/runs
- /api/spark/jobs
- /api/dataset/stats
- /api/ml/models
- /api/ml/predictions
- /api/agents/status
- /api/threat/intelligence

## Step 1: Create Supabase Database

1. Create a free Supabase project.
2. Copy the Postgres connection string.
3. Store it as SUPABASE_DB_URL in Render backend env vars.

## Step 2: Deploy Backend + AI Engine on Render

1. Push repository to GitHub.
2. In Render, create Blueprint deployment using render.yaml.
3. Set backend environment variables:
   - SUPABASE_DB_URL
   - AI_ENGINE_BASE_URL (your Render AI service URL)
4. Deploy both services.

Files used:

- render.yaml
- backend/Dockerfile.render
- ai_engine/Dockerfile.render

## Step 3: Deploy Frontend on Vercel

1. Import repository in Vercel.
2. Select frontend directory as project root.
3. Add environment variables:
   - VITE_API_BASE_URL=https://<your-backend>.onrender.com/api
   - VITE_WS_URL=wss://<your-backend>.onrender.com/api/ws/stream
4. Deploy.

File used:

- frontend/vercel.json

## Step 4: Local Demo Pipelines (Airflow + Spark)

Airflow and Spark remain local. Backend exposes their latest metrics/log snapshots to the deployed frontend via:

- /api/pipeline/airflow
- /api/analytics/spark

If local services are unavailable, backend serves fallback dataset-derived telemetry so dashboard cards remain populated for judges.

## Judge Access

Share only the Vercel frontend URL. The dashboard includes:

- AI threat detection
- Pipeline monitoring
- Spark analytics
- Airflow DAG run state and diagrams
- Kafka event statistics
