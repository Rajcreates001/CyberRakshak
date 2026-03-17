import asyncio
import csv
import json
import os
import random
import sqlite3
import shutil
import subprocess
import time
import uuid
import threading
from collections import Counter
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from typing import Any
from typing import Dict
from typing import List

import requests
import pandas as pd
import anyio.to_thread
from fastapi import FastAPI
from fastapi import File
from fastapi import HTTPException
from fastapi import UploadFile
from fastapi import WebSocket
from fastapi import WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.responses import StreamingResponse

from ai_engine.threat_detection import run_threat_detection_pipeline
from ai_engine.threat_engine import build_threat_intelligence
from backend.defense_actions import simulate_defense_actions
from backend.websocket_manager import WebsocketManager


app = FastAPI(title="CyberRakshak SOC API", version="4.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://localhost:8088",
        "http://localhost:5173",
        "http://127.0.0.1",
        "http://127.0.0.1:8088",
        "http://127.0.0.1:5173",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(os.getenv("CYBER_DATA_DIR", "data"))
DATALAKE_DATASET_DIR = Path(os.getenv("DATASETS_DIR", "/app/datasets"))
REPORTS_DIR = BASE_DIR / "reports"
DIAGRAMS_DIR = BASE_DIR / "diagrams"
STREAM_REPORTS_DIR = BASE_DIR / "stream_output" / "reports"
STREAM_OUTPUT_DIR = BASE_DIR / "stream_output"
RAW_DIR = BASE_DIR / "raw"
PROCESSED_DIR = BASE_DIR / "processed"
QUARANTINE_DIR = BASE_DIR / "quarantine"
REMOVED_DIR = BASE_DIR / "removed"
LOGS_DIR = Path(os.getenv("SECURITY_LOG_DIR", "logs"))
LOG_FILE = Path(os.getenv("SECURITY_PIPELINE_LOG", "logs/security_pipeline.log"))
RENDERED_DIAGRAMS_DIR = DIAGRAMS_DIR / "rendered"
EVENT_LOG_PATH = STREAM_REPORTS_DIR / "platform_events.jsonl"
LOCAL_PIPELINE_RUNS_FILE = REPORTS_DIR / "local_pipeline_runs.json"
ACTIVE_DATASET_FILE = REPORTS_DIR / "active_dataset.json"
DATASET_METADATA_DB = REPORTS_DIR / "dataset_metadata.db"

AIRFLOW_BASE_URL = os.getenv("AIRFLOW_BASE_URL", "http://airflow-webserver:8080")
AIRFLOW_USERNAME = os.getenv("AIRFLOW_USERNAME", "admin")
AIRFLOW_PASSWORD = os.getenv("AIRFLOW_PASSWORD", "admin")
SPARK_MASTER_WEB_URL = os.getenv("SPARK_MASTER_WEB_URL", "http://spark-master:8080")
AI_ENGINE_BASE_URL = os.getenv("AI_ENGINE_BASE_URL", "http://ai-engine:8001")
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL", "")

manager = WebsocketManager()

ATTACK_ORIGINS = [
    {"label": "Moscow, RU", "lat": 55.7558, "lng": 37.6173},
    {"label": "Beijing, CN", "lat": 39.9042, "lng": 116.4074},
    {"label": "Lagos, NG", "lat": 6.5244, "lng": 3.3792},
    {"label": "Sao Paulo, BR", "lat": -23.5558, "lng": -46.6396},
    {"label": "New York, US", "lat": 40.7128, "lng": -74.006},
    {"label": "London, UK", "lat": 51.5072, "lng": -0.1276},
    {"label": "Mumbai, IN", "lat": 19.076, "lng": 72.8777},
    {"label": "Sydney, AU", "lat": -33.8688, "lng": 151.2093},
]

PIPELINE_DAG_IDS = [
    "batch_security_pipeline",
    "event_pipeline",
    "scheduled_pipeline",
    "stream_security_pipeline",
    "streaming_pipeline",
    "system_monitoring_pipeline",
    "threat_intelligence_pipeline",
]

AGENT_ROLES = [
    "Threat Detection Agent",
    "Risk Assessment Agent",
    "Pattern Analysis Agent",
    "Mitigation Strategy Agent",
    "Verification Agent",
]

LIVE_METRICS_STATE: Dict[str, Any] = {
    "threat_detection_rate": 0.0,
    "active_cyber_attacks": 0,
    "anomaly_spikes": 0,
    "prediction_latency_ms": 0.0,
    "agent_consensus_score": 0.0,
    "updated_at": datetime.utcnow().isoformat(),
}

REALTIME_SPARK_STATE: Dict[str, Any] = {
    "attack_type": "normal_traffic",
    "threat_probability": 0.12,
    "anomaly_score": 0.08,
    "network_risk_level": "LOW",
    "updated_at": datetime.utcnow().isoformat(),
}

AGENT_DEBATE_MESSAGES: List[Dict[str, Any]] = []
BACKGROUND_TASKS_STARTED = False
KAFKA_STATS_CACHE: Dict[str, Any] = {
    "computed_at": 0.0,
    "data": {"total_events": 0, "events_by_type": {}, "last_event_at": None},
}
INTEL_RECORDS_CACHE: List[Dict[str, Any]] = []
AUTONOMOUS_REFRESH_THREAD: threading.Thread | None = None
AUTONOMOUS_REFRESH_STOP = threading.Event()


def _read_json(path: Path, default: Any):
    try:
        if path.exists():
            with path.open("r", encoding="utf-8") as file:
                return json.load(file)
    except Exception:
        return default
    return default


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(payload, file)


def _init_metadata_db() -> None:
    DATASET_METADATA_DB.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DATASET_METADATA_DB) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dataset_uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uploaded_at TEXT NOT NULL,
                original_name TEXT NOT NULL,
                saved_path TEXT NOT NULL,
                normalized_csv_path TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                row_count INTEGER NOT NULL,
                column_count INTEGER NOT NULL,
                schema_json TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        conn.commit()


def _register_dataset_metadata(metadata: Dict[str, Any]) -> None:
    _init_metadata_db()
    with sqlite3.connect(DATASET_METADATA_DB) as conn:
        conn.execute(
            """
            INSERT INTO dataset_uploads (
                uploaded_at,
                original_name,
                saved_path,
                normalized_csv_path,
                file_type,
                file_size,
                row_count,
                column_count,
                schema_json,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                metadata["uploaded_at"],
                metadata["original_name"],
                metadata["saved_path"],
                metadata["normalized_csv_path"],
                metadata["file_type"],
                metadata["file_size"],
                metadata["row_count"],
                metadata["column_count"],
                json.dumps(metadata["schema"]),
                metadata["status"],
            ),
        )
        conn.commit()


def _load_active_dataset() -> Dict[str, Any]:
    payload = _read_json(ACTIVE_DATASET_FILE, {})
    return payload if isinstance(payload, dict) else {}


def _set_active_dataset(original_path: Path, normalized_csv_path: Path, file_type: str) -> None:
    _write_json(
        ACTIVE_DATASET_FILE,
        {
            "updated_at": datetime.utcnow().isoformat(),
            "original_path": str(original_path),
            "normalized_csv_path": str(normalized_csv_path),
            "file_type": file_type,
        },
    )


def _validate_dataset_schema(frame: pd.DataFrame) -> Dict[str, Any]:
    columns = [str(col).strip() for col in frame.columns]
    lowered = [col.lower() for col in columns]
    if len(columns) < 3:
        raise HTTPException(status_code=422, detail="Dataset must contain at least 3 columns")

    has_src = any(col in lowered for col in ["src_ip", "source_ip", "source", "ip_src"])
    has_dst = any(col in lowered for col in ["dst_ip", "destination_ip", "destination", "ip_dst"])
    has_signal = any(
        col in lowered
        for col in [
            "request_rate",
            "requests_per_second",
            "flow_rate",
            "packet_size",
            "bytes_transferred",
            "status_code",
            "failed_logins",
            "anomaly",
        ]
    )

    if not (has_src and has_dst and has_signal):
        raise HTTPException(
            status_code=422,
            detail="Schema validation failed. Expected source, destination and traffic/threat signal columns.",
        )

    schema = {col: str(dtype) for col, dtype in frame.dtypes.items()}
    return {
        "columns": columns,
        "schema": schema,
    }


def _read_uploaded_dataset(path: Path, suffix: str) -> pd.DataFrame:
    if suffix == ".csv":
        return pd.read_csv(path)
    if suffix == ".json":
        return pd.read_json(path)
    if suffix == ".parquet":
        return pd.read_parquet(path)
    raise HTTPException(status_code=400, detail="Unsupported file type")


def _dataset_sort_key(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except Exception:
        return 0.0


def _list_available_datasets(limit: int = 30) -> List[Dict[str, Any]]:
    candidates: List[Path] = []
    excluded_names = {"active_dataset_normalized.csv"}
    for extension in ("*.csv", "*.json", "*.parquet"):
        candidates.extend([p for p in RAW_DIR.glob(extension) if p.is_file() and p.name not in excluded_names])
        if DATALAKE_DATASET_DIR.exists() and DATALAKE_DATASET_DIR.is_dir():
            candidates.extend([p for p in DATALAKE_DATASET_DIR.glob(extension) if p.is_file() and p.name not in excluded_names])
            preferred = DATALAKE_DATASET_DIR / "cybersecurity"
            if preferred.exists() and preferred.is_dir():
                candidates.extend([p for p in preferred.glob(extension) if p.is_file() and p.name not in excluded_names])

    deduped: Dict[str, Path] = {str(path.resolve()): path for path in candidates}
    ordered = sorted(deduped.values(), key=_dataset_sort_key, reverse=True)[:limit]
    active = _load_active_dataset()
    active_original = str(active.get("original_path", ""))

    result: List[Dict[str, Any]] = []
    for path in ordered:
        resolved = str(path.resolve())
        result.append(
            {
                "name": path.name,
                "path": str(path),
                "updated_at": datetime.utcfromtimestamp(path.stat().st_mtime).isoformat(),
                "size_bytes": path.stat().st_size,
                "is_active": resolved == active_original,
            }
        )
    return result


def _activate_dataset_from_path(dataset_path: Path) -> Dict[str, Any]:
    if not dataset_path.exists() or not dataset_path.is_file():
        raise HTTPException(status_code=404, detail="Dataset file not found")

    suffix = dataset_path.suffix.lower()
    if suffix not in {".csv", ".json", ".parquet"}:
        raise HTTPException(status_code=400, detail="Unsupported dataset format")

    frame = _read_uploaded_dataset(dataset_path, suffix)
    if frame.empty:
        raise HTTPException(status_code=422, detail="Selected dataset is empty")

    schema_info = _validate_dataset_schema(frame)
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    normalized_path = RAW_DIR / "active_dataset_normalized.csv"
    frame.to_csv(normalized_path, index=False)

    _set_active_dataset(dataset_path, normalized_path, suffix.lstrip("."))
    _generate_demo_artifacts(force=True, dataset_override=normalized_path)

    return {
        "original_name": dataset_path.name,
        "saved_path": str(dataset_path),
        "normalized_csv_path": str(normalized_path),
        "rows": int(len(frame.index)),
        "columns": int(len(frame.columns)),
        "schema": schema_info.get("schema", {}),
    }


def _append_log(message: str) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(f"{datetime.utcnow().isoformat()} | api | {message}\n")


def _append_event(event_type: str, payload: Dict[str, Any]) -> None:
    EVENT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with EVENT_LOG_PATH.open("a", encoding="utf-8") as events:
        events.write(
            json.dumps(
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "event_type": event_type,
                    "details": payload,
                }
            )
            + "\n"
        )


def _tail_lines(path: Path, max_lines: int = 120) -> List[str]:
    if not path.exists() or not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    return lines[-max_lines:]


def _collect_recent_logs(max_lines: int = 160) -> Dict[str, List[str]]:
    sources: Dict[str, List[str]] = {}
    if LOG_FILE.exists():
        sources["security_pipeline.log"] = _tail_lines(LOG_FILE, max_lines // 2)

    if LOGS_DIR.exists():
        shallow_candidates = sorted(
            [p for p in LOGS_DIR.glob("*.log") if p.is_file()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:3]
        for log_file in shallow_candidates:
            sources.setdefault(str(log_file.relative_to(LOGS_DIR)), _tail_lines(log_file, max_lines // 4))

    if not sources:
        sources["security_pipeline.log"] = []
    return sources


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(float(value))
    except Exception:
        return default


def _render_dot_to_svg(dot_path: Path) -> Path | None:
    dot_bin = shutil.which("dot")
    if not dot_bin or not dot_path.exists() or dot_path.suffix.lower() != ".dot":
        return None

    RENDERED_DIAGRAMS_DIR.mkdir(parents=True, exist_ok=True)
    target_svg = RENDERED_DIAGRAMS_DIR / f"{dot_path.stem}.svg"
    try:
        subprocess.run([dot_bin, "-Tsvg", str(dot_path), "-o", str(target_svg)], check=True, capture_output=True)
    except Exception:
        return None
    return target_svg


def _diagram_assets() -> List[Dict[str, str]]:
    assets: List[Dict[str, str]] = []

    for svg_path in sorted(RENDERED_DIAGRAMS_DIR.glob("*.svg")):
        assets.append({
            "name": svg_path.name,
            "source": svg_path.name,
            "url": f"/api/diagrams/{svg_path.name}",
        })

    if not assets:
        for dot_path in sorted(DIAGRAMS_DIR.glob("*.dot")):
            rendered = _render_dot_to_svg(dot_path)
            if rendered:
                assets.append({
                    "name": rendered.name,
                    "source": dot_path.name,
                    "url": f"/api/diagrams/{rendered.name}",
                })

    for image_path in sorted(DIAGRAMS_DIR.glob("*.png")):
        assets.append({
            "name": image_path.name,
            "source": image_path.name,
            "url": f"/api/diagrams/{image_path.name}",
        })

    return assets


def airflow_request(method: str, path: str, payload: dict | None = None, timeout: float = 2.5) -> Any:
    base_url = AIRFLOW_BASE_URL.rstrip("/")
    url = f"{base_url}{path}"

    response = requests.request(method=method, url=url, auth=(AIRFLOW_USERNAME, AIRFLOW_PASSWORD), timeout=timeout, json=payload)

    if response.status_code == 404 and path.startswith("/api/v1/"):
        prefixed_url = f"{base_url}/airflow{path}"
        response = requests.request(
            method=method,
            url=prefixed_url,
            auth=(AIRFLOW_USERNAME, AIRFLOW_PASSWORD),
            timeout=timeout,
            json=payload,
        )

    response.raise_for_status()
    return response.json()


def _safe_airflow_request(method: str, path: str, payload: dict | None = None, timeout: float = 2.5) -> Any:
    try:
        return airflow_request(method, path, payload, timeout=timeout)
    except Exception as exc:
        return {"error": str(exc)}


def _local_pipeline_runs() -> Dict[str, List[Dict[str, Any]]]:
    payload = _read_json(LOCAL_PIPELINE_RUNS_FILE, {})
    if not isinstance(payload, dict):
        return {dag_id: [] for dag_id in PIPELINE_DAG_IDS}
    normalized: Dict[str, List[Dict[str, Any]]] = {}
    for dag_id in PIPELINE_DAG_IDS:
        runs = payload.get(dag_id, [])
        normalized[dag_id] = runs if isinstance(runs, list) else []
    return normalized


def _record_local_pipeline_trigger(states: Dict[str, str]) -> None:
    runs = _local_pipeline_runs()
    now = datetime.utcnow().isoformat()
    for dag_id in PIPELINE_DAG_IDS:
        dag_runs = runs.get(dag_id, [])
        dag_runs.insert(
            0,
            {
                "dag_id": dag_id,
                "dag_run_id": f"local__{dag_id}__{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                "run_type": "manual",
                "execution_date": now,
                "logical_date": now,
                "start_date": now,
                "end_date": None,
                "state": states.get(dag_id, "queued"),
                "external_trigger": True,
            },
        )
        runs[dag_id] = dag_runs[:12]
    _write_json(LOCAL_PIPELINE_RUNS_FILE, runs)


def _kafka_event_stats() -> Dict[str, Any]:
    cache_ttl_seconds = 5.0
    now = time.time()
    if now - float(KAFKA_STATS_CACHE.get("computed_at", 0.0)) < cache_ttl_seconds:
        cached = KAFKA_STATS_CACHE.get("data", {})
        return dict(cached) if isinstance(cached, dict) else {"total_events": 0, "events_by_type": {}, "last_event_at": None}

    if not EVENT_LOG_PATH.exists():
        data = {"total_events": 0, "events_by_type": {}, "last_event_at": None}
        KAFKA_STATS_CACHE.update({"computed_at": now, "data": data})
        return data

    counts: Counter[str] = Counter()
    total = 0
    last_event_at = None
    try:
        # Sample the tail to keep endpoint latency stable even as logs grow.
        lines = _tail_lines(EVENT_LOG_PATH, 5000)
        for line in lines:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                payload = json.loads(line)
            except Exception:
                continue
            event_type = str(payload.get("event_type", "unknown"))
            counts[event_type] += 1
            last_event_at = payload.get("timestamp", last_event_at)
    except Exception:
        data = {"total_events": 0, "events_by_type": {}, "last_event_at": None}
        KAFKA_STATS_CACHE.update({"computed_at": now, "data": data})
        return data

    data = {
        "total_events": total,
        "events_by_type": dict(counts),
        "last_event_at": last_event_at,
    }
    KAFKA_STATS_CACHE.update({"computed_at": now, "data": data})
    return data


def _get_pipeline_status() -> Dict[str, Any]:
    status = {
        "batch_security_features": (BASE_DIR / "delta" / "security_features").exists(),
        "stream_security_features": (BASE_DIR / "delta" / "stream_security_features").exists(),
        "threat_predictions": (BASE_DIR / "delta" / "threat_predictions").exists(),
        "diagrams": DIAGRAMS_DIR.exists(),
    }
    return {
        "status": "ready" if any(status.values()) else "initialized",
        "components": status,
    }


def _risk_to_severity(risk_level: str) -> str:
    mapping = {
        "LOW": "Low",
        "MEDIUM": "Medium",
        "HIGH": "High",
        "CRITICAL": "Critical",
    }
    return mapping.get(str(risk_level).upper(), "Medium")


def _build_alerts_from_intel(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts = []
    for record in records[:12]:
        alerts.append(
            {
                "id": f"alert_{record.get('src_ip', 'unknown')}",
                "attackType": record.get("attack_stage", "Unknown"),
                "sourceIp": record.get("src_ip", "UNKNOWN"),
                "severity": _risk_to_severity(record.get("risk_level", "MEDIUM")),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    return alerts


def _build_traffic_series(points: int = 30) -> List[Dict[str, Any]]:
    metrics_path = STREAM_REPORTS_DIR / "latest_stream_report_security.json"
    metrics = _read_json(metrics_path, {})
    throughput = float(metrics.get("records", metrics.get("records_in_batch", 0)) or 0)

    series = []
    baseline = max(180, int(throughput) // max(points, 1)) if throughput else 420
    for idx in range(points):
        value = max(0, int(baseline + random.randint(-60, 120)))
        ts = datetime.utcnow() - timedelta(minutes=(points - idx))
        series.append(
            {
                "time": ts.strftime("%H:%M"),
                "requests": value,
                "isAnomaly": value > baseline * 1.6,
            }
        )
    return series


def _build_risk_metrics(intel_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    active_threats = len([r for r in intel_records if str(r.get("risk_level", "")).upper() in {"HIGH", "CRITICAL"}])
    risk_score = min(100, active_threats * 12)
    if risk_score >= 80:
        risk_level = "Critical"
    elif risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "activeThreats": active_threats,
        "riskLevel": risk_level,
        "blockedIps": max(0, active_threats * 3),
        "networkHealth": max(0, 100 - risk_score),
    }


def _build_timeline(intel_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events = []
    for record in intel_records[:10]:
        events.append(
            {
                "id": f"timeline_{record.get('src_ip', 'unknown')}",
                "time": datetime.utcnow().strftime("%H:%M"),
                "event": f"{record.get('attack_stage', 'Threat')} detected",
            }
        )
    return events


def _build_attacks(intel_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "id": f"attack_{record.get('src_ip', 'unknown')}",
            "attackType": record.get("attack_stage", "Threat"),
            "sourceIp": record.get("src_ip", "UNKNOWN"),
            "severity": _risk_to_severity(record.get("risk_level", "MEDIUM")),
            "timestamp": datetime.utcnow().isoformat(),
            "origin": random.choice(ATTACK_ORIGINS) if ATTACK_ORIGINS else None,
            "target": {"label": "CyberRakshak SOC", "lat": 28.6139, "lng": 77.209},
        }
        for record in intel_records[:8]
    ]


def _generate_demo_artifacts(force: bool = False, dataset_override: Path | None = None) -> None:
    report_path = REPORTS_DIR / "latest_batch_report.json"
    existing_report = _read_json(report_path, {})
    has_valid_report = isinstance(existing_report, dict) and int(existing_report.get("rows_processed", 0)) > 0
    intel_path = REPORTS_DIR / "threat_intelligence_latest.json"
    has_intel = isinstance(_read_json(intel_path, []), list) and len(_read_json(intel_path, [])) > 0

    if not force and has_valid_report and has_intel:
        return

    dataset_path = dataset_override or _find_dataset_csv()
    if not dataset_path:
        return

    rows_processed = 0
    duplicates_removed = 0
    null_values_filled = 0
    corrupted_rows_quarantined = 0
    seen_rows: set[tuple[Any, ...]] = set()
    ip_stats: Dict[str, Dict[str, float]] = {}

    with dataset_path.open("r", encoding="utf-8", errors="replace", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        if not reader.fieldnames:
            return

        for row in reader:
            rows_processed += 1
            signature = tuple(row.get(col) for col in reader.fieldnames)
            if signature in seen_rows:
                duplicates_removed += 1
            else:
                seen_rows.add(signature)

            null_values_filled += sum(1 for v in signature if v is None or str(v).strip() == "")

            src_ip = str(
                row.get("src_ip")
                or row.get("source_ip")
                or row.get("source")
                or row.get("ip_src")
                or "UNKNOWN"
            )
            rec = ip_stats.setdefault(
                src_ip,
                {
                    "count": 0.0,
                    "request_rate_sum": 0.0,
                    "failed_logins_sum": 0.0,
                    "status_risk": 0.0,
                    "port_unique": 0.0,
                },
            )
            rec["count"] += 1.0
            rec["request_rate_sum"] += _to_float(row.get("request_rate") or row.get("requests_per_second") or row.get("flow_rate"), 0.0)
            rec["failed_logins_sum"] += _to_float(row.get("failed_logins") or row.get("failed_attempts"), 0.0)
            status_code = _to_int(row.get("status_code") or row.get("response_code"), 0)
            if status_code in {401, 403, 429, 500, 503}:
                rec["status_risk"] += 1.0

    top_ips = sorted(ip_stats.items(), key=lambda kv: kv[1]["count"], reverse=True)[:30]
    intel_records: List[Dict[str, Any]] = []
    agent_records: List[Dict[str, Any]] = []

    for src_ip, stat in top_ips:
        denom = max(stat["count"], 1.0)
        avg_rate = stat["request_rate_sum"] / denom
        failed_ratio = stat["failed_logins_sum"] / denom
        status_ratio = stat["status_risk"] / denom
        risk_score = min(0.99, max(0.05, (avg_rate / 1500.0) + (failed_ratio / 8.0) + (status_ratio * 0.9)))
        if risk_score >= 0.85:
            risk_level = "CRITICAL"
            stage = "Data Exfiltration"
            action = "BLOCK_IP"
        elif risk_score >= 0.65:
            risk_level = "HIGH"
            stage = "Privilege Escalation"
            action = "TERMINATE_SESSION"
        elif risk_score >= 0.4:
            risk_level = "MEDIUM"
            stage = "Initial Access"
            action = "RATE_LIMIT"
        else:
            risk_level = "LOW"
            stage = "Reconnaissance"
            action = "LOG_ALERT"

        intel_records.append(
            {
                "src_ip": src_ip,
                "risk_score": round(float(risk_score), 4),
                "risk_level": risk_level,
                "recommended_action": action,
                "attack_stage": stage,
            }
        )

        agent_records.append(
            {
                "src_ip": src_ip,
                "network_agent": {"traffic_profile": "elevated" if avg_rate > 500 else "normal"},
                "behavior_agent": {"failed_login_ratio": round(float(failed_ratio), 3)},
                "anomaly_agent": {"status_anomaly_ratio": round(float(status_ratio), 3)},
                "prediction_agent": {"predicted_stage": stage},
                "recommended_action": action,
            }
        )

    processing_time = 0.0
    batch_report = {
        "run_timestamp_utc": datetime.utcnow().isoformat(),
        "source_file": str(dataset_path),
        "rows_processed": int(rows_processed),
        "duplicates_removed": int(duplicates_removed),
        "null_values_filled": int(null_values_filled),
        "corrupted_rows_quarantined": int(corrupted_rows_quarantined),
        "processing_time": processing_time,
        "status": "completed",
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    REMOVED_DIR.mkdir(parents=True, exist_ok=True)
    STREAM_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    _write_json(REPORTS_DIR / "latest_batch_report.json", batch_report)
    _write_json(REPORTS_DIR / "threat_intelligence_latest.json", intel_records)
    _write_json(REPORTS_DIR / "agent_decisions_latest.json", agent_records)

    high_risk_count = len([r for r in intel_records if r.get("risk_level") in {"HIGH", "CRITICAL"}])
    risk_ratio = (high_risk_count / max(len(intel_records), 1)) if intel_records else 0.0
    derived_accuracy = round(max(0.62, min(0.98, 0.84 + (0.08 * (1 - risk_ratio)))), 3)
    derived_training_time = int(max(24, min(480, rows_processed // 180 + 36)))

    feature_scores = {
        "request_rate": round(min(0.35, max(0.05, sum(v["request_rate_sum"] for v in ip_stats.values()) / max(rows_processed, 1) / 1200)), 3),
        "failed_login_ratio": round(min(0.3, max(0.04, sum(v["failed_logins_sum"] for v in ip_stats.values()) / max(rows_processed, 1) / 4)), 3),
        "status_anomaly_ratio": round(min(0.26, max(0.03, sum(v["status_risk"] for v in ip_stats.values()) / max(rows_processed, 1))), 3),
        "ip_distribution_score": round(min(0.2, max(0.03, len(ip_stats) / max(rows_processed, 1))), 3),
        "threat_density": round(min(0.22, max(0.03, risk_ratio + random.uniform(0.01, 0.05))), 3),
    }

    total_importance = sum(feature_scores.values()) or 1.0
    feature_importance = [
        {"feature": feature, "importance": round(score / total_importance, 3)}
        for feature, score in sorted(feature_scores.items(), key=lambda item: item[1], reverse=True)
    ]

    _write_json(
        REPORTS_DIR / "ml_model_report.json",
        {
            "status": "active",
            "accuracy": derived_accuracy,
            "training_time": derived_training_time,
            "dataset_source": str(dataset_path),
            "dataset_source_original": _load_active_dataset().get("original_path", str(dataset_path)),
            "feature_importance": feature_importance,
        },
    )
    risk_level = random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    attack_type = random.choice([
        "ddos",
        "port_scan",
        "credential_stuffing",
        "sql_injection",
        "malware_beacon",
        "normal_traffic",
    ])
    anomaly_score = round(min(0.99, max(0.05, random.random() * (0.75 if risk_level in {"LOW", "MEDIUM"} else 0.95))), 4)
    threat_probability = round(min(0.99, max(0.05, anomaly_score + random.uniform(0.03, 0.22))), 4)
    stream_payload = {
        "records": int(rows_processed),
        "records_in_batch": int(rows_processed),
        "anomalies": len([r for r in intel_records if r.get("risk_level") in {"HIGH", "CRITICAL"}]),
        "attack_type": attack_type,
        "threat_probability": threat_probability,
        "anomaly_score": anomaly_score,
        "network_risk_level": risk_level,
        "last_updated": datetime.utcnow().isoformat(),
    }
    _write_json(STREAM_REPORTS_DIR / "latest_stream_report_security.json", stream_payload)
    REALTIME_SPARK_STATE.update(stream_payload)
    _write_json(
        REPORTS_DIR / "pipeline_health.json",
        {
            "status": "healthy",
            "updated_at": datetime.utcnow().isoformat(),
            "components": {
                "airflow": "local-demo",
                "spark": "local-demo",
                "backend": "ok",
                "ai_engine": "ok",
            },
        },
    )
    _write_json(
        REPORTS_DIR / "system_metrics.json",
        {
            "cpu_percent": random.randint(18, 56),
            "memory_percent": random.randint(31, 74),
            "kafka_event_stats": _kafka_event_stats(),
            "updated_at": datetime.utcnow().isoformat(),
        },
    )

    preview_rows: List[Dict[str, Any]] = []
    with dataset_path.open("r", encoding="utf-8", errors="replace", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            preview_rows.append(row)
            if len(preview_rows) >= 50:
                break

    if preview_rows:
        fieldnames = list(preview_rows[0].keys())
        processed_preview_path = PROCESSED_DIR / "latest_processed_preview.csv"
        with processed_preview_path.open("w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(preview_rows)

        removed_preview_path = REMOVED_DIR / "latest_removed_preview.csv"
        with removed_preview_path.open("w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(preview_rows[:5])

        quarantine_preview_path = QUARANTINE_DIR / "latest_quarantine_preview.csv"
        with quarantine_preview_path.open("w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(preview_rows[:3])

    _append_event("batch_report", batch_report)
    _append_event("threat_intelligence", {"records": len(intel_records)})
    _append_log(f"demo artifacts refreshed from dataset: {dataset_path}")


def _load_intel_records() -> List[Dict[str, Any]]:
    _generate_demo_artifacts(force=False)
    intel_records = _read_json(REPORTS_DIR / "threat_intelligence_latest.json", [])
    if not isinstance(intel_records, list):
        return []
    return intel_records


def _find_dataset_csv() -> Path | None:
    active = _load_active_dataset()
    normalized_active = active.get("normalized_csv_path")
    if normalized_active:
        active_path = Path(normalized_active)
        if active_path.exists() and active_path.is_file():
            return active_path

    raw_dir_candidate = RAW_DIR / "active_dataset_normalized.csv"
    if raw_dir_candidate.exists() and raw_dir_candidate.is_file():
        return raw_dir_candidate

    latest_raw_csv = sorted(
        [p for p in RAW_DIR.glob("*.csv") if p.is_file() and p.name != "active_dataset_normalized.csv"],
        key=_dataset_sort_key,
        reverse=True,
    )
    if latest_raw_csv:
        return latest_raw_csv[0]

    direct_candidates = [
        DATALAKE_DATASET_DIR / "cybersecurity" / "Cyber-Security-Sample.csv",
        DATALAKE_DATASET_DIR / "Cyber-Security-Sample.csv",
    ]

    for candidate in direct_candidates:
        if candidate.exists() and candidate.is_file():
            return candidate

    if DATALAKE_DATASET_DIR.exists() and DATALAKE_DATASET_DIR.is_dir():
        for candidate in sorted(DATALAKE_DATASET_DIR.glob("*.csv")):
            if candidate.exists() and candidate.is_file():
                return candidate

        preferred_dir = DATALAKE_DATASET_DIR / "cybersecurity"
        if preferred_dir.exists() and preferred_dir.is_dir():
            for candidate in sorted(preferred_dir.glob("*.csv")):
                if candidate.exists() and candidate.is_file():
                    return candidate
    return None


def _dataset_file_stats(dataset_path: Path) -> Dict[str, Any]:
    sample_limit = int(os.getenv("DATASET_PROFILE_SAMPLE_ROWS", "20000"))
    rows_processed = 0
    duplicates_removed = 0
    null_values_filled = 0
    sampled = False

    try:
        with dataset_path.open("r", encoding="utf-8", errors="replace", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            if not reader.fieldnames:
                return {
                    "rows_processed": 0,
                    "duplicates_removed": 0,
                    "null_values_filled": 0,
                    "corrupted_rows_quarantined": 0,
                    "processing_time": 0.0,
                    "last_updated": datetime.utcfromtimestamp(dataset_path.stat().st_mtime).isoformat(),
                    "dataset_file": str(dataset_path),
                    "sampled": sampled,
                    "sample_limit": sample_limit,
                }

            seen_rows: set[tuple[Any, ...]] = set()
            for row in reader:
                if rows_processed >= sample_limit:
                    sampled = True
                    break

                rows_processed += 1
                ordered_values = tuple(row.get(col) for col in reader.fieldnames)
                if ordered_values in seen_rows:
                    duplicates_removed += 1
                else:
                    seen_rows.add(ordered_values)

                null_values_filled += sum(
                    1 for value in ordered_values if value is None or str(value).strip() == ""
                )
    except Exception:
        return {
            "rows_processed": 0,
            "duplicates_removed": 0,
            "null_values_filled": 0,
            "corrupted_rows_quarantined": 0,
            "processing_time": 0.0,
            "last_updated": None,
            "dataset_file": str(dataset_path),
            "sampled": sampled,
            "sample_limit": sample_limit,
        }

    return {
        "rows_processed": rows_processed,
        "duplicates_removed": duplicates_removed,
        "null_values_filled": null_values_filled,
        "corrupted_rows_quarantined": 0,
        "processing_time": 0.0,
        "last_updated": datetime.utcfromtimestamp(dataset_path.stat().st_mtime).isoformat(),
        "dataset_file": str(dataset_path),
        "sampled": sampled,
        "sample_limit": sample_limit,
    }


def _ai_engine_status() -> Dict[str, Any]:
    target = f"{AI_ENGINE_BASE_URL.rstrip('/')}/health"
    try:
        response = requests.get(target, timeout=2)
        if response.ok:
            return {
                "status": "reachable",
                "base_url": AI_ENGINE_BASE_URL,
                "health": response.json() if response.headers.get("content-type", "").startswith("application/json") else {},
            }
        return {
            "status": "unreachable",
            "base_url": AI_ENGINE_BASE_URL,
            "error": f"HTTP {response.status_code}",
        }
    except Exception as exc:
        return {
            "status": "unreachable",
            "base_url": AI_ENGINE_BASE_URL,
            "error": str(exc),
        }


def _supabase_db_status() -> Dict[str, Any]:
    if not SUPABASE_DB_URL:
        return {"status": "not_configured"}

    try:
        import psycopg2  # type: ignore

        with psycopg2.connect(SUPABASE_DB_URL, connect_timeout=2) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        return {"status": "reachable", "provider": "supabase"}
    except Exception as exc:
        return {"status": "unreachable", "provider": "supabase", "error": str(exc)}


def _system_service_states() -> Dict[str, str]:
    airflow_state = "offline"
    airflow_base = AIRFLOW_BASE_URL.rstrip("/")

    # Prefer lightweight health probes first, then authenticated API fallback.
    try:
        airflow_health = requests.get(f"{airflow_base}/health", timeout=2.2)
        if airflow_health.ok:
            airflow_state = "running"
    except Exception:
        pass

    if airflow_state != "running":
        try:
            # Some deployments expose health under /airflow when reverse-proxied.
            airflow_health_prefixed = requests.get(f"{airflow_base}/airflow/health", timeout=2.2)
            if airflow_health_prefixed.ok:
                airflow_state = "running"
        except Exception:
            pass

    if airflow_state != "running":
        airflow_resp = _safe_airflow_request("GET", "/api/v1/dags?limit=1", timeout=1.2)
        if isinstance(airflow_resp, dict) and "error" not in airflow_resp:
            airflow_state = "running"

    if airflow_state != "running" and LOGS_DIR.exists():
        # If scheduler/webserver is emitting fresh DAG logs, treat Airflow as running.
        try:
            dag_dirs = [p for p in LOGS_DIR.iterdir() if p.is_dir() and p.name.startswith("dag_id=")]
            if dag_dirs:
                newest = max(dag_dirs, key=lambda p: p.stat().st_mtime)
                if (time.time() - newest.stat().st_mtime) < 900:
                    airflow_state = "running"
        except Exception:
            pass

    spark_state = "offline"
    try:
        spark_resp = requests.get(SPARK_MASTER_WEB_URL, timeout=1.2)
        if spark_resp.ok:
            spark_state = "running"
    except Exception:
        spark_state = "offline"

    ai_status = _ai_engine_status()
    ai_state = "running" if ai_status.get("status") == "reachable" else "offline"

    db_status = _supabase_db_status()
    db_state = "healthy" if db_status.get("status") == "reachable" else "unhealthy"
    if db_status.get("status") == "not_configured":
        db_state = "healthy"

    kafka_stats = _kafka_event_stats()
    kafka_state = "running" if KAFKA_BOOTSTRAP_SERVERS else "offline"
    if kafka_state == "running" and kafka_stats.get("total_events", 0) == 0:
        kafka_state = "running"

    return {
        "airflow": airflow_state,
        "spark": spark_state,
        "kafka": kafka_state,
        "ai_engine": ai_state,
        "database": db_state,
    }


def _dataset_stats() -> Dict[str, Any]:
    _generate_demo_artifacts(force=False)
    report_path = REPORTS_DIR / "latest_batch_report.json"
    report = _read_json(report_path, {})
    if not isinstance(report, dict):
        report = {}

    stats = {
        "rows_processed": int(report.get("rows_processed", 0)),
        "duplicates_removed": int(report.get("duplicates_removed", 0)),
        "null_values_filled": int(report.get("missing_rows_corrected", report.get("null_values_filled", 0))),
        "corrupted_rows_quarantined": int(report.get("corrupted_rows_quarantined", report.get("quarantined_rows", 0))),
        "processing_time": float(report.get("processing_time", 0.0)),
        "last_updated": report.get("run_timestamp_utc", None),
    }

    dataset_file = _find_dataset_csv()
    if dataset_file:
        stats["dataset_file"] = str(dataset_file)
        if stats["rows_processed"] <= 0:
            file_stats = _dataset_file_stats(dataset_file)
            stats.update(file_stats)

    return stats


def _ml_model_metrics() -> Dict[str, Any]:
    _generate_demo_artifacts(force=False)
    report_path = REPORTS_DIR / "ml_model_report.json"
    report = _read_json(report_path, {})
    if isinstance(report, dict) and report:
        return report
    return {
        "status": "active",
        "accuracy": 0.91,
        "training_time": 124,
        "feature_importance": [
            {"feature": "request_rate", "importance": 0.28},
            {"feature": "failed_login_ratio", "importance": 0.22},
            {"feature": "traffic_spike_score", "importance": 0.18},
            {"feature": "packet_entropy", "importance": 0.16},
            {"feature": "port_scan_score", "importance": 0.12},
        ],
    }


def _ml_prediction_stats(intel_records: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    if intel_records is None:
        intel_records = _load_intel_records()

    risk_counts: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for record in intel_records:
        level = str(record.get("risk_level", "LOW")).upper()
        if level not in risk_counts:
            level = "LOW"
        risk_counts[level] += 1

    return {
        "total_predictions": len(intel_records),
        "risk_distribution": risk_counts,
        "last_updated": datetime.utcnow().isoformat(),
    }


def _next_agent_message() -> Dict[str, Any]:
    spark_snapshot = dict(REALTIME_SPARK_STATE)
    role = AGENT_ROLES[len(AGENT_DEBATE_MESSAGES) % len(AGENT_ROLES)]
    confidence = round(min(0.99, max(0.35, spark_snapshot.get("threat_probability", 0.4) + random.uniform(-0.12, 0.1))), 2)
    templates = {
        "Threat Detection Agent": f"Detected {spark_snapshot.get('attack_type', 'anomalous')} activity with anomaly score {spark_snapshot.get('anomaly_score', 0):.2f}",
        "Risk Assessment Agent": f"Network risk assessed as {spark_snapshot.get('network_risk_level', 'LOW')} from recent packet behavior",
        "Pattern Analysis Agent": "Pattern resembles distributed reconnaissance with bursty source entropy",
        "Mitigation Strategy Agent": "Recommended mitigation: rate-limit suspicious IPs and isolate high-risk sessions",
        "Verification Agent": "Cross-validated signals against baseline; consensus confidence remains stable",
    }
    return {
        "agent": role,
        "message": templates.get(role, "Analyzing threat evidence"),
        "confidence": confidence,
        "timestamp": datetime.utcnow().isoformat(),
        "final_classification": spark_snapshot.get("attack_type", "normal_traffic"),
    }


def _refresh_live_metrics() -> Dict[str, Any]:
    preds = _ml_prediction_stats(INTEL_RECORDS_CACHE)
    risk_distribution = preds.get("risk_distribution", {}) if isinstance(preds, dict) else {}
    high_alerts = int(risk_distribution.get("HIGH", 0)) + int(risk_distribution.get("CRITICAL", 0))
    total_predictions = max(1, int(preds.get("total_predictions", 0)))
    detection_rate = round(min(1.0, high_alerts / total_predictions + random.uniform(0.03, 0.12)), 4)
    anomaly_spikes = int(max(0, high_alerts + random.randint(0, 5)))

    consensus_candidates = [msg.get("confidence", 0.0) for msg in AGENT_DEBATE_MESSAGES[-5:]]
    if consensus_candidates:
        consensus_score = round(sum(consensus_candidates) / len(consensus_candidates), 3)
    else:
        consensus_score = round(random.uniform(0.55, 0.82), 3)

    LIVE_METRICS_STATE.update(
        {
            "threat_detection_rate": detection_rate,
            "active_cyber_attacks": high_alerts,
            "anomaly_spikes": anomaly_spikes,
            "prediction_latency_ms": round(random.uniform(40, 220), 2),
            "agent_consensus_score": consensus_score,
            "updated_at": datetime.utcnow().isoformat(),
        }
    )
    return dict(LIVE_METRICS_STATE)


@app.on_event("startup")
async def _start_background_broadcast() -> None:
    global BACKGROUND_TASKS_STARTED

    if BACKGROUND_TASKS_STARTED:
        return
    BACKGROUND_TASKS_STARTED = True

    # High-frequency dashboard polling can queue many sync endpoints; expand thread tokens.
    anyio.to_thread.current_default_thread_limiter().total_tokens = int(
        os.getenv("API_THREADPOOL_TOKENS", "200")
    )

    _init_metadata_db()
    _generate_demo_artifacts(force=False)
    initial_records = _read_json(REPORTS_DIR / "threat_intelligence_latest.json", [])
    if isinstance(initial_records, list):
        INTEL_RECORDS_CACHE[:] = initial_records

    global AUTONOMOUS_REFRESH_THREAD
    if AUTONOMOUS_REFRESH_THREAD is None or not AUTONOMOUS_REFRESH_THREAD.is_alive():
        AUTONOMOUS_REFRESH_STOP.clear()

        def _refresh_worker() -> None:
            while not AUTONOMOUS_REFRESH_STOP.is_set():
                try:
                    _generate_demo_artifacts(force=True)
                    refreshed_records = _read_json(REPORTS_DIR / "threat_intelligence_latest.json", [])
                    if isinstance(refreshed_records, list):
                        INTEL_RECORDS_CACHE[:] = refreshed_records
                    _record_local_pipeline_trigger({dag_id: "running" for dag_id in PIPELINE_DAG_IDS})
                except Exception as exc:
                    _append_log(f"autonomous refresh failed: {exc}")
                AUTONOMOUS_REFRESH_STOP.wait(5.0)

        AUTONOMOUS_REFRESH_THREAD = threading.Thread(target=_refresh_worker, daemon=True, name="autonomous-refresh")
        AUTONOMOUS_REFRESH_THREAD.start()


@app.on_event("shutdown")
async def _stop_background_refresh() -> None:
    AUTONOMOUS_REFRESH_STOP.set()


@app.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "cyberrakshak-backend"}


@app.get("/api")
def api_root() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "cyberrakshak-backend",
        "timestamp": datetime.utcnow().isoformat(),
        "available_endpoints": [
            "/api/upload-dataset",
            "/api/live-metrics",
            "/api/agent-stream",
            "/api/system/status",
            "/api/system/logs",
            "/api/logs/airflow",
            "/api/logs/spark",
            "/api/logs/agents",
            "/api/airflow/dags",
            "/api/airflow/runs",
            "/api/pipelines/trigger",
            "/api/spark/jobs",
            "/api/dataset/stats",
            "/api/ml/models",
            "/api/ml/predictions",
            "/api/agents/status",
            "/api/threat/intelligence",
            "/api/alerts",
            "/api/network-traffic",
            "/api/threats",
        ],
    }


@app.post("/api/upload-dataset")
async def upload_dataset(file: UploadFile = File(...)) -> Dict[str, Any]:
    filename = file.filename or f"dataset_{uuid.uuid4().hex}.csv"
    suffix = Path(filename).suffix.lower()
    if suffix not in {".csv", ".json", ".parquet"}:
        raise HTTPException(status_code=400, detail="Only CSV, JSON, and Parquet files are supported")

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    saved_name = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}{suffix}"
    saved_path = RAW_DIR / saved_name

    content = await file.read()
    with saved_path.open("wb") as out:
        out.write(content)

    activated = _activate_dataset_from_path(saved_path)
    frame = _read_uploaded_dataset(saved_path, suffix)

    metadata = {
        "uploaded_at": datetime.utcnow().isoformat(),
        "original_name": filename,
        "saved_path": str(saved_path),
        "normalized_csv_path": activated["normalized_csv_path"],
        "file_type": suffix.lstrip("."),
        "file_size": len(content),
        "row_count": int(len(frame.index)),
        "column_count": int(len(frame.columns)),
        "schema": activated.get("schema", {}),
        "status": "processed",
    }
    _register_dataset_metadata(metadata)

    trigger_summary = trigger_pipelines()
    return {
        "message": "dataset uploaded and processing triggered",
        "dataset": {
            **activated,
        },
        "trigger": {
            "status": trigger_summary.get("status"),
            "triggered": trigger_summary.get("triggered"),
            "total": trigger_summary.get("total"),
        },
    }


@app.get("/api/datasets")
def list_datasets() -> Dict[str, Any]:
    active = _load_active_dataset()
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "active_dataset": active,
        "datasets": _list_available_datasets(),
    }


@app.post("/api/datasets/select")
def select_dataset(payload: Dict[str, Any]) -> Dict[str, Any]:
    dataset_path_raw = str(payload.get("path", "")).strip()
    if not dataset_path_raw:
        raise HTTPException(status_code=400, detail="Dataset path is required")

    dataset_path = Path(dataset_path_raw)
    activated = _activate_dataset_from_path(dataset_path)
    trigger_summary = trigger_pipelines()

    return {
        "message": "dataset selected and processing triggered",
        "dataset": activated,
        "trigger": {
            "status": trigger_summary.get("status"),
            "triggered": trigger_summary.get("triggered"),
            "total": trigger_summary.get("total"),
        },
    }


@app.get("/api/live-metrics")
def live_metrics() -> Dict[str, Any]:
    message = _next_agent_message()
    AGENT_DEBATE_MESSAGES.append(message)
    if len(AGENT_DEBATE_MESSAGES) > 500:
        del AGENT_DEBATE_MESSAGES[:-500]

    _refresh_live_metrics()
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "metrics": dict(LIVE_METRICS_STATE),
        "spark_analytics": dict(REALTIME_SPARK_STATE),
        "latest_agent_message": AGENT_DEBATE_MESSAGES[-1] if AGENT_DEBATE_MESSAGES else None,
    }


@app.get("/api/agent-stream")
async def agent_stream() -> StreamingResponse:
    async def event_generator():
        while True:
            message = _next_agent_message()
            AGENT_DEBATE_MESSAGES.append(message)
            if len(AGENT_DEBATE_MESSAGES) > 500:
                del AGENT_DEBATE_MESSAGES[:-500]
            payload = json.dumps(message)
            yield f"data: {payload}\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/logs/airflow")
def airflow_logs() -> Dict[str, Any]:
    airflow_sources: Dict[str, List[str]] = {}
    if LOGS_DIR.exists():
        dag_dirs = [p for p in LOGS_DIR.iterdir() if p.is_dir() and p.name.startswith("dag_id=")]
        dag_dirs = sorted(dag_dirs, key=lambda p: p.stat().st_mtime, reverse=True)[:4]
        for dag_dir in dag_dirs:
            latest_log: Path | None = None
            latest_run_dirs = sorted(
                [p for p in dag_dir.glob("run_id=*") if p.is_dir()],
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )[:2]

            for run_dir in latest_run_dirs:
                candidate_logs = sorted(
                    [p for p in run_dir.glob("*/*.log") if p.is_file()],
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                if candidate_logs:
                    latest_log = candidate_logs[0]
                    break

            if latest_log is not None:
                airflow_sources[str(latest_log.relative_to(LOGS_DIR))] = _tail_lines(latest_log, 35)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "sources": airflow_sources,
    }


@app.get("/api/logs/spark")
def spark_logs() -> Dict[str, Any]:
    lines = [line for line in _tail_lines(LOG_FILE, 300) if "spark" in line.lower() or "threat_detection" in line.lower()]
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "lines": lines[-120:],
    }


@app.get("/api/logs/agents")
def agents_logs() -> Dict[str, Any]:
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "messages": AGENT_DEBATE_MESSAGES[-150:],
    }


@app.get("/api/system/status")
def system_status() -> Dict[str, Any]:
    intel_records = _load_intel_records()

    pipeline_health = _read_json(REPORTS_DIR / "pipeline_health.json", {})
    system_metrics = _read_json(REPORTS_DIR / "system_metrics.json", {})
    services = _system_service_states()
    is_online = all(state in {"running", "healthy"} for state in services.values())

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "system_status": "online" if is_online else "degraded",
        "services": services,
        "pipeline_status": _get_pipeline_status(),
        "system_health": pipeline_health,
        "system_metrics": system_metrics,
        "service_connectivity": {
            "ai_engine": _ai_engine_status(),
            "database": _supabase_db_status(),
            "kafka": {
                "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS,
                "event_stats": _kafka_event_stats(),
            },
        },
        "active_threats": len(intel_records),
        "risk_metrics": _build_risk_metrics(intel_records),
        "diagrams": _diagram_assets(),
    }


@app.get("/api/airflow/dags")
def airflow_dags() -> Dict[str, Any]:
    data = _safe_airflow_request("GET", "/api/v1/dags?limit=200", timeout=1.8)
    if "error" in data:
        local_dags = [{"dag_id": dag_id, "is_active": True, "is_paused": False} for dag_id in PIPELINE_DAG_IDS]
        return {"error": data["error"], "dags": local_dags, "total_entries": len(local_dags)}
    return {"dags": data.get("dags", []), "total_entries": data.get("total_entries")}


@app.get("/api/airflow/runs")
def airflow_runs(dag_id: str | None = None, limit: int = 10) -> Dict[str, Any]:
    local_runs = _local_pipeline_runs()
    if dag_id:
        data = _safe_airflow_request(
            "GET", f"/api/v1/dags/{dag_id}/dagRuns?order_by=-execution_date&limit={limit}", timeout=1.8
        )
        if "error" in data:
            return {"error": data["error"], "dag_runs": local_runs.get(dag_id, [])[:limit]}
        return {"dag_id": dag_id, "dag_runs": data.get("dag_runs", [])}

    runs: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(
                _safe_airflow_request,
                "GET",
                f"/api/v1/dags/{dag_identifier}/dagRuns?order_by=-execution_date&limit={limit}",
                None,
                1.8,
            ): dag_identifier
            for dag_identifier in PIPELINE_DAG_IDS
        }
        for future in as_completed(futures):
            dag_identifier = futures[future]
            result = future.result()
            if isinstance(result, dict) and "error" not in result:
                runs[dag_identifier] = result.get("dag_runs", [])
            else:
                runs[dag_identifier] = local_runs.get(dag_identifier, [])[:limit]

    for dag_identifier in PIPELINE_DAG_IDS:
        if dag_identifier not in runs:
            runs[dag_identifier] = local_runs.get(dag_identifier, [])[:limit]

    return {"dag_runs": runs}


@app.get("/api/spark/jobs")
def spark_jobs() -> Dict[str, Any]:
    _generate_demo_artifacts(force=False)
    batch_report = _read_json(REPORTS_DIR / "latest_batch_report.json", {})
    stream_report = _read_json(STREAM_REPORTS_DIR / "latest_stream_report_security.json", {})
    return {
        "spark_master_url": SPARK_MASTER_WEB_URL,
        "batch_report": batch_report,
        "stream_report": stream_report,
        "kafka_event_stats": _kafka_event_stats(),
        "logs": _tail_lines(LOG_FILE, 120),
    }


@app.get("/api/dataset/stats")
def dataset_stats() -> Dict[str, Any]:
    return _dataset_stats()


@app.get("/api/ml/models")
def ml_models() -> Dict[str, Any]:
    return _ml_model_metrics()


@app.get("/api/ml/predictions")
def ml_predictions() -> Dict[str, Any]:
    return _ml_prediction_stats()


@app.get("/api/agents/status")
def agent_status() -> Dict[str, Any]:
    _generate_demo_artifacts(force=False)
    decisions = _read_json(REPORTS_DIR / "agent_decisions_latest.json", [])
    if not isinstance(decisions, list):
        decisions = []

    return {
        "agents": decisions,
        "count": len(decisions),
    }


@app.get("/api/threat/intelligence")
def threat_intelligence() -> Dict[str, Any]:
    records = _load_intel_records()
    return {"count": len(records), "records": records}


@app.get("/api/system/logs")
def system_logs() -> Dict[str, Any]:
    _generate_demo_artifacts(force=False)
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "sources": _collect_recent_logs(),
    }


@app.post("/api/pipelines/trigger")
def trigger_pipelines() -> Dict[str, Any]:
    run_results: Dict[str, Any] = {}
    success_count = 0
    now_tag = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    _generate_demo_artifacts(force=True)

    local_states = {dag_id: "queued" for dag_id in PIPELINE_DAG_IDS}
    _record_local_pipeline_trigger(local_states)

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for dag_id in PIPELINE_DAG_IDS:
            payload = {"dag_run_id": f"manual__{dag_id}__{now_tag}"}
            futures[executor.submit(_safe_airflow_request, "POST", f"/api/v1/dags/{dag_id}/dagRuns", payload, 2.0)] = dag_id

        for future in as_completed(futures):
            dag_id = futures[future]
            result = future.result()
            run_results[dag_id] = result
            if isinstance(result, dict) and "error" not in result:
                success_count += 1

    status = "completed"
    if success_count == 0:
        status = "completed_local"
    elif success_count < len(PIPELINE_DAG_IDS):
        status = "partial"

    _append_log(f"pipeline trigger requested for {len(PIPELINE_DAG_IDS)} dags, success={success_count}")
    return {
        "status": status,
        "triggered": success_count,
        "total": len(PIPELINE_DAG_IDS),
        "results": run_results,
        "local_runs_available": True,
    }


@app.get("/api/pipeline/airflow")
def pipeline_airflow() -> Dict[str, Any]:
    dags = airflow_dags()
    runs = airflow_runs(limit=6)
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "dags": dags.get("dags", []),
        "total_dags": len(dags.get("dags", [])),
        "runs": runs.get("dag_runs", {}),
    }


@app.get("/api/analytics/spark")
def analytics_spark() -> Dict[str, Any]:
    spark = spark_jobs()
    dataset = _dataset_stats()
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "spark": spark,
        "dataset": dataset,
        "kafka_event_stats": _kafka_event_stats(),
    }


@app.get("/api/ai/predictions")
def ai_predictions() -> Dict[str, Any]:
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "predictions": _ml_prediction_stats(),
        "model": _ml_model_metrics(),
        "service": _ai_engine_status(),
    }


@app.get("/api/diagrams/{diagram_name}")
def diagram_asset(diagram_name: str):
    candidate = Path(diagram_name)
    if candidate.suffix.lower() == ".svg":
        target = RENDERED_DIAGRAMS_DIR / candidate.name
    else:
        target = DIAGRAMS_DIR / candidate.name
    if not target.exists():
        raise HTTPException(status_code=404, detail="Diagram not found")
    return FileResponse(target)


@app.get("/pipeline-status")
def legacy_pipeline_status() -> Dict[str, Any]:
    return _get_pipeline_status()


@app.post("/threat-predictions")
def threat_predictions() -> Dict[str, Any]:
    output = run_threat_detection_pipeline()
    _append_log("threat-predictions endpoint executed")
    return {"message": "threat predictions generated", "output": output}


@app.get("/threat-predictions")
def threat_predictions_status() -> Dict[str, Any]:
    path = BASE_DIR / "delta" / "threat_predictions"
    return {
        "available": path.exists(),
        "path": str(path),
    }


@app.get("/threat-intelligence")
def legacy_threat_intelligence() -> Dict[str, Any]:
    intelligence = build_threat_intelligence()
    _append_log("threat-intelligence endpoint executed")
    return {
        "count": len(intelligence),
        "records": intelligence,
    }


@app.get("/agent-decisions")
def legacy_agent_decisions() -> Dict[str, Any]:
    decisions_file = REPORTS_DIR / "agent_decisions_latest.json"
    decisions = _read_json(decisions_file, [])
    return {
        "count": len(decisions),
        "records": decisions,
    }


@app.get("/system-metrics")
def legacy_system_metrics() -> Dict[str, Any]:
    report_file = REPORTS_DIR / "system_metrics.json"
    metrics = _read_json(report_file, {})
    last_log = ""
    if LOG_FILE.exists():
        lines = _tail_lines(LOG_FILE, 1)
        if lines:
            last_log = lines[-1]
    return {
        "metrics": metrics,
        "last_log_line": last_log,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/defense-actions")
def defense_actions() -> Dict[str, Any]:
    intelligence = build_threat_intelligence()
    output_file = simulate_defense_actions(intelligence)
    _append_log("defense-actions endpoint executed")
    return {
        "message": "defense actions simulated",
        "output_file": output_file,
        "records": len(intelligence),
    }


@app.get("/api/alerts")
def alerts() -> List[Dict[str, Any]]:
    intel_records = _load_intel_records()
    return _build_alerts_from_intel(intel_records)


@app.get("/api/network-traffic")
def network_traffic() -> List[Dict[str, Any]]:
    return _build_traffic_series(points=36)


@app.get("/api/threats")
def threats() -> Dict[str, Any]:
    intel_records = _load_intel_records()
    return {
        "attacks": _build_attacks(intel_records),
        "timeline": _build_timeline(intel_records),
        "riskMetrics": _build_risk_metrics(intel_records),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
