import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import requests
from deltalake import write_deltalake
from fastapi import BackgroundTasks
from fastapi import FastAPI
from fastapi import File
from fastapi import HTTPException
from fastapi import Query
from fastapi import UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas


app = FastAPI(title="Autonex Streaming Backend", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

metrics_path = Path(os.getenv("STREAM_OUTPUT_DIR", "/app/data/stream_output")) / "metrics" / "latest_metrics.json"
data_root = Path("/app/data")
datasets_root = Path("/app/datasets")
delta_raw_path = data_root / "delta" / "raw_data"
delta_uploaded_raw_path = data_root / "delta" / "uploaded_raw_data"
reports_root = data_root / "stream_output" / "reports"
events_path = reports_root / "platform_events.jsonl"
platform_report_path = reports_root / "latest_platform_report.json"
batch_report_path = data_root / "reports" / "latest_batch_report.json"
default_batch_report_path = data_root / "reports" / "latest_batch_report_default.json"
stream_report_path = reports_root / "latest_stream_report.json"
diagrams_root = data_root / "diagrams"
logs_root = Path("/app/logs")
generated_reports_root = reports_root / "generated"
default_dataset_path = datasets_root / "youtube.csv"
default_dataset_snapshot_path = datasets_root / "youtube_default.csv"
workbench_dataset_path = datasets_root / "uploaded_dataset.csv"
workbench_raw_dataset_path = data_root / "raw" / "uploaded_dataset.csv"
active_dataset_path = data_root / "raw" / "active_dataset.csv"

airflow_base_url = os.getenv("AIRFLOW_BASE_URL", "http://airflow-webserver:8080")
airflow_user = os.getenv("AIRFLOW_USERNAME", "admin")
airflow_password = os.getenv("AIRFLOW_PASSWORD", "admin")

PROFILE_CACHE: dict[str, dict] = {}
LOG_CACHE: dict[str, Any] = {"key": "", "lines": [], "generated_at": ""}
PROFILE_MAX_ROWS = int(os.getenv("PROFILE_MAX_ROWS", "200000"))


def normalized_columns(columns: list[str]) -> set[str]:
    return {str(col).strip().lower() for col in columns}


def is_youtube_like_columns(columns: list[str]) -> bool:
    normalized = normalized_columns(columns)
    required = {"video_id", "title", "channel_title", "views"}
    return required.issubset(normalized)


def read_csv_columns_only(path: Path) -> list[str]:
    try:
        return list(pd.read_csv(path, nrows=0).columns)
    except Exception:
        return []


def resolve_default_dataset_path() -> Path:
    candidates: list[Path] = [
        default_dataset_path,
        default_dataset_snapshot_path,
        data_root / "raw" / "youtube.csv",
    ]

    processed_candidates = sorted(
        data_root.joinpath("processed").glob("clean_input_*.csv"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    candidates.extend(processed_candidates)

    first_existing: Path | None = None
    for path in candidates:
        if not path.exists() or not path.is_file():
            continue
        if first_existing is None:
            first_existing = path
        columns = read_csv_columns_only(path)
        if is_youtube_like_columns(columns):
            return path

    if first_existing is not None:
        return first_existing
    return default_dataset_path


def resolve_column_name(frame: pd.DataFrame, aliases: list[str]) -> str | None:
    lookup = {str(col).strip().lower(): col for col in frame.columns}
    for alias in aliases:
        key = alias.strip().lower()
        if key in lookup:
            return lookup[key]
    return None


def ensure_default_snapshot() -> None:
    source = resolve_default_dataset_path()
    if source.exists() and not default_dataset_snapshot_path.exists():
        shutil.copyfile(source, default_dataset_snapshot_path)


def safe_int(value: Any) -> int:
    try:
        if pd.isna(value):
            return 0
    except Exception:
        pass
    try:
        return int(float(str(value).replace(",", "").strip()))
    except Exception:
        return 0


def parse_dataset_profile(dataset_path: Path) -> dict:
    if not dataset_path.exists():
        return {
            "dataset": dataset_path.name,
            "rows": 0,
            "columns": [],
            "top_channels": [],
            "top_categories": [],
            "views_distribution": [],
            "country_distribution": [],
        }

    cache_key = f"{dataset_path}:{dataset_path.stat().st_mtime_ns}"
    cached = PROFILE_CACHE.get(cache_key)
    if cached:
        return cached

    file_size_bytes = dataset_path.stat().st_size
    sampled = False
    sample_limit = PROFILE_MAX_ROWS

    if file_size_bytes > 250 * 1024 * 1024:
        sampled = True
        frame = pd.read_csv(dataset_path, nrows=sample_limit)
    else:
        frame = pd.read_csv(dataset_path)
    rows = len(frame.index)
    columns = list(frame.columns)

    top_channels = []
    top_categories = []
    views_distribution = []
    country_distribution = []
    metric_labels = {
        "top_channels": "Top Channel",
        "top_categories": "Top Category",
        "views_distribution": "Views",
        "country_distribution": "Country",
    }

    channel_column = resolve_column_name(
        frame,
        [
            "channel_title",
            "channel title",
            "channel",
            "city",
            "source",
            "state",
            "county",
            "outlet_identifier",
            "outlet_type",
        ],
    )
    category_column = resolve_column_name(
        frame,
        [
            "category_id",
            "category",
            "severity",
            "weather_condition",
            "state",
            "county",
            "item_type",
            "item_fat_content",
            "outlet_location_type",
        ],
    )
    views_column = resolve_column_name(
        frame,
        [
            "views",
            "view_count",
            "distance(mi)",
            "severity",
            "temperature(f)",
            "likes",
            "item_outlet_sales",
            "item_mrp",
            "item_visibility",
        ],
    )
    country_column = resolve_column_name(frame, ["publish_country", "country", "state"])

    if channel_column:
        metric_labels["top_channels"] = str(channel_column)
        channel_counts = frame[channel_column].fillna("UNKNOWN").astype(str).value_counts().head(8)
        top_channels = [
            {"name": str(name), "count": int(count)}
            for name, count in channel_counts.items()
        ]

    if category_column:
        metric_labels["top_categories"] = str(category_column)
        category_counts = frame[category_column].fillna("UNKNOWN").astype(str).value_counts().head(8)
        top_categories = [
            {"name": str(name), "count": int(count)}
            for name, count in category_counts.items()
        ]

    if views_column:
        metric_labels["views_distribution"] = str(views_column)
        numeric_series = pd.to_numeric(frame[views_column], errors="coerce").dropna()
        if not numeric_series.empty and int(numeric_series.nunique()) > 1:
            q = min(5, int(numeric_series.nunique()))
            buckets = pd.qcut(numeric_series, q=q, duplicates="drop")
            bucket_counts = buckets.value_counts().sort_index()
            views_distribution = [
                {"bucket": str(interval), "count": int(count)}
                for interval, count in bucket_counts.items()
            ]

    if country_column:
        metric_labels["country_distribution"] = str(country_column)
        country_counts = frame[country_column].fillna("UNKNOWN").astype(str).value_counts().head(8)
        country_distribution = [
            {"country": str(name), "count": int(count)}
            for name, count in country_counts.items()
        ]

    duplicate_rows = int(frame.duplicated().sum()) if not frame.empty else 0
    missing_values_count = int(frame.isna().sum().sum()) if not frame.empty else 0
    missing_row_count = int(frame.isna().any(axis=1).sum()) if not frame.empty else 0

    duplicate_key_rows = 0
    if not frame.empty:
        key_columns = [
            col
            for col in [
                resolve_column_name(frame, ["video_id"]),
                resolve_column_name(frame, ["trending_date", "publish_date"]),
            ]
            if col
        ]
        if key_columns:
            duplicate_key_rows = int(frame.duplicated(subset=key_columns).sum())

    profile = {
        "dataset": dataset_path.name,
        "rows": rows,
        "columns": columns,
        "top_channels": top_channels,
        "top_categories": top_categories,
        "views_distribution": views_distribution,
        "country_distribution": country_distribution,
        "metric_labels": metric_labels,
        "is_youtube_like": is_youtube_like_columns(columns),
        "duplicate_rows": duplicate_rows,
        "duplicate_key_rows": duplicate_key_rows,
        "missing_values_count": missing_values_count,
        "missing_row_count": missing_row_count,
        "sampled": sampled,
        "sample_rows": rows if sampled else None,
        "sample_limit": sample_limit if sampled else None,
    }
    PROFILE_CACHE.clear()
    PROFILE_CACHE[cache_key] = profile
    return profile


def airflow_request(method: str, path: str, payload: dict | None = None) -> Any:
    url = f"{airflow_base_url.rstrip('/')}{path}"
    response = requests.request(
        method=method,
        url=url,
        auth=(airflow_user, airflow_password),
        timeout=5,
        json=payload,
    )
    response.raise_for_status()
    return response.json()


def get_latest_run_status(dag_id: str) -> dict:
    try:
        runs = airflow_request("GET", f"/api/v1/dags/{dag_id}/dagRuns?limit=1&order_by=-start_date")
        items = runs.get("dag_runs", [])
        if not items:
            return {"dag_id": dag_id, "state": "not_started"}
        latest = items[0]
        return {
            "dag_id": dag_id,
            "dag_run_id": latest.get("dag_run_id"),
            "state": latest.get("state", "unknown"),
            "start_date": latest.get("start_date"),
            "end_date": latest.get("end_date"),
        }
    except Exception as exc:
        return {
            "dag_id": dag_id,
            "state": "unavailable",
            "error": str(exc),
        }


def read_tail_lines(file_path: Path, max_lines: int) -> list[str]:
    if not file_path.exists() or not file_path.is_file():
        return []
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-max_lines:]


def collect_live_logs(max_lines: int = 120) -> list[str]:
    if logs_root.exists():
        try:
            latest_mtime = max((p.stat().st_mtime_ns for p in logs_root.rglob("*.log") if p.is_file()), default=0)
            cache_key = f"{latest_mtime}:{max_lines}"
            if LOG_CACHE.get("key") == cache_key:
                return LOG_CACHE.get("lines", [])
        except Exception:
            latest_mtime = 0
            cache_key = f"0:{max_lines}"

    if not logs_root.exists():
        return []

    candidate_files = sorted(
        [path for path in logs_root.rglob("*.log") if path.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:4]

    merged: list[str] = []
    lines_per_file = max(20, max_lines // max(len(candidate_files), 1))
    for file_path in candidate_files:
        merged.append(f"===== {file_path.relative_to(logs_root)} =====")
        merged.extend(read_tail_lines(file_path, lines_per_file))

    result = merged[-max_lines:]
    LOG_CACHE["key"] = cache_key
    LOG_CACHE["lines"] = result
    LOG_CACHE["generated_at"] = datetime.utcnow().isoformat()
    return result


def draw_wrapped_lines(pdf: canvas.Canvas, y: float, title: str, lines: list[str], line_height: int = 14) -> float:
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(40, y, title)
    y -= line_height
    pdf.setFont("Helvetica", 9)
    for line in lines:
        if y < 40:
            pdf.showPage()
            y = 790
            pdf.setFont("Helvetica", 9)
        pdf.drawString(42, y, line[:150])
        y -= 11
    return y - 8


def create_report_pdf(mode: str) -> Path:
    generated_reports_root.mkdir(parents=True, exist_ok=True)
    ensure_default_snapshot()

    source_path = resolve_default_dataset_path() if mode == "default" else workbench_dataset_path
    if not source_path.exists():
        raise FileNotFoundError(f"Dataset for report not found: {source_path}")

    now_label = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    pdf_path = generated_reports_root / f"{mode}_dashboard_report_{now_label}.pdf"

    profile = parse_dataset_profile(source_path)
    platform = platform_report()
    stream_metrics_data = platform.get("stream_metrics", {})
    batch_data = platform.get("batch_report", {})
    stream_data = platform.get("stream_report", {})

    pdf = canvas.Canvas(str(pdf_path), pagesize=A4)
    width, height = A4
    y = height - 40

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(40, y, "Autonex Data Engineering Report")
    y -= 18
    pdf.setFont("Helvetica", 10)
    pdf.drawString(40, y, f"Generated UTC: {datetime.utcnow().isoformat()}")
    y -= 14
    pdf.drawString(40, y, f"Mode: {mode}")
    y -= 14
    pdf.drawString(40, y, f"Dataset: {source_path.name}")
    y -= 20

    y = draw_wrapped_lines(
        pdf,
        y,
        "Dataset Overview",
        [
            f"Rows: {profile.get('rows', 0)}",
            f"Columns: {', '.join(profile.get('columns', []))}",
            f"Top Channels: {json.dumps(profile.get('top_channels', []))}",
            f"Top Categories: {json.dumps(profile.get('top_categories', []))}",
            f"Country Distribution: {json.dumps(profile.get('country_distribution', []))}",
        ],
    )

    y = draw_wrapped_lines(
        pdf,
        y,
        "Pipeline Metrics",
        [
            f"Message Count: {stream_metrics_data.get('message_count', 0)}",
            f"Throughput RPS: {stream_metrics_data.get('throughput_rps', 0)}",
            f"Batch Report: {json.dumps(batch_data)}",
            f"Stream Report: {json.dumps(stream_data)}",
        ],
    )

    y = draw_wrapped_lines(
        pdf,
        y,
        "Recent Live Logs",
        collect_live_logs(max_lines=40),
        line_height=12,
    )

    diagram_files = [
        diagrams_root / "scheduled_pipeline.png",
        diagrams_root / "event_pipeline.png",
        diagrams_root / "streaming_pipeline.png",
    ]
    for diag in diagram_files:
        if not diag.exists():
            continue
        if y < 280:
            pdf.showPage()
            y = 790
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(40, y, f"Diagram: {diag.name}")
        y -= 10
        try:
            img = ImageReader(str(diag))
            img_width, img_height = img.getSize()
            target_width = min(width - 80, img_width)
            ratio = target_width / float(img_width)
            target_height = img_height * ratio
            if target_height > 220:
                target_height = 220
                ratio = target_height / float(img_height)
                target_width = img_width * ratio
            pdf.drawImage(img, 40, y - target_height, width=target_width, height=target_height, preserveAspectRatio=True, mask="auto")
            y -= target_height + 18
        except Exception:
            pdf.setFont("Helvetica", 9)
            pdf.drawString(40, y, f"Unable to embed diagram image: {diag}")
            y -= 16

    pdf.save()
    return pdf_path


def append_event(event_type: str, details: dict) -> None:
    reports_root.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "details": details,
    }
    with events_path.open("a", encoding="utf-8") as out:
        out.write(json.dumps(payload) + "\n")


def read_json_file(path: Path, default):
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return default


def build_derived_batch_report(profile: dict, dataset_path: Path) -> dict:
    duplicate_rows = int(profile.get("duplicate_key_rows") or profile.get("duplicate_rows", 0))
    missing_rows = int(profile.get("missing_row_count", 0))
    rows_processed = int(profile.get("rows", 0))
    return {
        "run_timestamp_utc": datetime.utcnow().isoformat(),
        "source_file": str(dataset_path),
        "profile": "youtube" if profile.get("is_youtube_like") else "generic",
        "quarantined_rows": missing_rows,
        "missing_rows_corrected": missing_rows,
        "duplicates_removed": duplicate_rows,
        "rows_processed": rows_processed,
        "schema_updated": False,
        "extra_columns": [],
        "paths": {
            "processed_delta": str(data_root / "delta" / "security_features"),
            "quarantine_delta": str(data_root / "delta" / "security_quarantine"),
            "missing_values_snapshot": "",
            "duplicates_snapshot": "",
        },
        "status": "derived",
    }


def resolve_default_batch_report(profile: dict, dataset_path: Path) -> dict:
    # Prefer explicit default report if available.
    explicit_default = read_json_file(default_batch_report_path, {})
    if isinstance(explicit_default, dict) and explicit_default:
        return explicit_default

    latest_batch = read_json_file(batch_report_path, {})
    if not isinstance(latest_batch, dict):
        latest_batch = {}
    latest_source = str(latest_batch.get("source_file", "")).lower()
    expected_name = dataset_path.name.lower()

    # If latest report is for a different workbench/active dataset, don't use it for default dashboard.
    if latest_batch and expected_name in latest_source and "active_dataset.csv" not in latest_source:
        return latest_batch

    derived = build_derived_batch_report(profile, dataset_path)
    default_batch_report_path.parent.mkdir(parents=True, exist_ok=True)
    with default_batch_report_path.open("w", encoding="utf-8") as handle:
        json.dump(derived, handle)
    return derived


def resolve_workbench_batch_report(profile: dict) -> dict:
    latest_batch = read_json_file(batch_report_path, {})
    if not isinstance(latest_batch, dict):
        latest_batch = {}

    latest_source = str(latest_batch.get("source_file", "")).lower()
    if latest_batch and (
        latest_source.endswith("uploaded_dataset.csv") or latest_source.endswith("active_dataset.csv")
    ):
        return latest_batch

    return build_derived_batch_report(profile, workbench_dataset_path)


def fallback_pipeline_state(dag_id: str, current: dict, batch_report: dict) -> dict:
    if current.get("state") != "unavailable":
        return current

    source_file = str(batch_report.get("source_file", "")).lower()
    if source_file.endswith("uploaded_dataset.csv") or source_file.endswith("active_dataset.csv"):
        return {
            "dag_id": dag_id,
            "state": "success",
            "dag_run_id": "local_fallback",
            "source": "backend_local",
        }

    return current


def run_local_workbench_pipeline() -> dict:
    profile = parse_dataset_profile(workbench_dataset_path)
    derived = build_derived_batch_report(profile, workbench_dataset_path)

    batch_report_path.parent.mkdir(parents=True, exist_ok=True)
    with batch_report_path.open("w", encoding="utf-8") as handle:
        json.dump(derived, handle)

    stream_summary = {
        "batch_id": int(datetime.utcnow().timestamp()),
        "generated_at": datetime.utcnow().isoformat(),
        "records_in_batch": int(profile.get("rows", 0)),
        "anomaly_counts": {"normal": int(profile.get("rows", 0))},
        "output_paths": {
            "stream_delta": str(data_root / "stream_output" / "delta_stream"),
            "warehouse": str(data_root / "stream_output" / "warehouse"),
            "metrics": str(metrics_path),
        },
    }
    stream_report_path.parent.mkdir(parents=True, exist_ok=True)
    with stream_report_path.open("w", encoding="utf-8") as handle:
        json.dump(stream_summary, handle)

    metrics_payload = {
        "batch_id": stream_summary["batch_id"],
        "generated_at": stream_summary["generated_at"],
        "message_count": int(profile.get("rows", 0)),
        "throughput_rps": float(max(1, int(profile.get("rows", 0)) // 10)),
        "top_channels": [
            {"channel_title": x.get("name", ""), "message_count": int(x.get("count", 0))}
            for x in profile.get("top_channels", [])[:8]
        ],
        "top_videos": [],
    }
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    with metrics_path.open("w", encoding="utf-8") as handle:
        json.dump(metrics_payload, handle)

    append_event("pipeline_start_requested_local", {"dataset": str(workbench_dataset_path)})
    append_event("batch_pipeline_report", derived)
    append_event("streaming_pipeline_report", stream_summary)

    return {
        "scheduled_pipeline_run": {"dag_run_id": "local_fallback", "state": "success"},
        "streaming_pipeline_run": {"dag_run_id": "local_fallback", "state": "success"},
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/stream/metrics")
def stream_metrics():
    if not metrics_path.exists():
        return {
            "batch_id": None,
            "generated_at": None,
            "message_count": 0,
            "throughput_rps": 0,
            "top_channels": [],
            "top_videos": [],
        }

    with metrics_path.open("r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/api/dashboard/default")
def default_dashboard():
    dataset_path = resolve_default_dataset_path()
    profile = parse_dataset_profile(dataset_path)
    batch_report = resolve_default_batch_report(profile, dataset_path)
    display_name = "youtube.csv" if profile.get("is_youtube_like") else dataset_path.name
    return {
        "dataset_name": display_name,
        "dataset_source": dataset_path.name,
        "dataset_profile": profile,
        "batch_report": batch_report,
        "stream_report": read_json_file(stream_report_path, {}),
        "stream_metrics": stream_metrics(),
        "pipeline_diagrams": {
            "scheduled_pipeline": str(diagrams_root / "scheduled_pipeline.png"),
            "event_pipeline": str(diagrams_root / "event_pipeline.png"),
            "streaming_pipeline": str(diagrams_root / "streaming_pipeline.png"),
        },
    }


@app.get("/api/workbench/state")
def workbench_state():
    profile = parse_dataset_profile(workbench_dataset_path) if workbench_dataset_path.exists() else {
        "dataset": "uploaded_dataset.csv",
        "rows": 0,
        "columns": [],
        "top_channels": [],
        "top_categories": [],
        "views_distribution": [],
        "country_distribution": [],
    }
    batch_report = resolve_workbench_batch_report(profile) if workbench_dataset_path.exists() else {}
    scheduled_state = fallback_pipeline_state(
        "scheduled_pipeline",
        get_latest_run_status("scheduled_pipeline"),
        batch_report,
    )
    streaming_state = fallback_pipeline_state(
        "streaming_pipeline",
        get_latest_run_status("streaming_pipeline"),
        batch_report,
    )
    return {
        "has_uploaded_dataset": workbench_dataset_path.exists(),
        "uploaded_dataset_name": workbench_dataset_path.name,
        "dataset_profile": profile,
        "batch_report": batch_report,
        "stream_report": read_json_file(stream_report_path, {}),
        "stream_metrics": read_json_file(metrics_path, {}),
        "pipeline_status": {
            "scheduled_pipeline": scheduled_state,
            "streaming_pipeline": streaming_state,
        },
        "events": platform_events(limit=25),
    }


@app.post("/api/dataset/upload")
async def upload_dataset(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".csv"):
        return {"status": "error", "message": "Only CSV files are supported"}

    datasets_root.mkdir(parents=True, exist_ok=True)
    (data_root / "raw").mkdir(parents=True, exist_ok=True)
    delta_raw_path.mkdir(parents=True, exist_ok=True)

    dataset_target = workbench_dataset_path
    raw_target = workbench_raw_dataset_path
    active_target = active_dataset_path

    with dataset_target.open("wb") as out:
        shutil.copyfileobj(file.file, out)
    shutil.copyfile(dataset_target, raw_target)

    dataframe = pd.read_csv(dataset_target)
    write_deltalake(str(delta_uploaded_raw_path), dataframe, mode="overwrite")
    shutil.copyfile(dataset_target, active_target)

    summary = {
        "file_name": file.filename,
        "stored_as": "uploaded_dataset.csv",
        "rows": int(len(dataframe.index)),
        "columns": list(dataframe.columns),
        "datasets_path": str(dataset_target),
        "raw_path": str(raw_target),
        "delta_raw_path": str(delta_uploaded_raw_path),
        "uploaded_at": datetime.utcnow().isoformat(),
    }

    reports_root.mkdir(parents=True, exist_ok=True)
    with platform_report_path.open("w", encoding="utf-8") as rep:
        json.dump({"dataset_upload": summary}, rep)

    # Clear previous run outputs so workbench reflects only the current uploaded dataset run.
    for artifact in [batch_report_path, stream_report_path, metrics_path]:
        try:
            if artifact.exists():
                artifact.unlink()
        except Exception:
            pass

    append_event("dataset_upload", summary)
    return {"status": "success", "summary": summary}


@app.post("/api/pipeline/start")
def start_data_engineering(background_tasks: BackgroundTasks):
    if not workbench_dataset_path.exists():
        raise HTTPException(status_code=400, detail="No uploaded dataset found. Upload a CSV first.")

    # Update active input files for current workbench run without replacing the default youtube dataset.
    active_dataset_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(workbench_dataset_path, active_dataset_path)
    shutil.copyfile(workbench_dataset_path, data_root / "raw" / "active_dataset.csv")

    trigger_mode = "airflow"
    try:
        scheduled_run = airflow_request(
            "POST",
            "/api/v1/dags/scheduled_pipeline/dagRuns",
            {"dag_run_id": f"manual__scheduled_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"},
        )
        streaming_run = airflow_request(
            "POST",
            "/api/v1/dags/streaming_pipeline/dagRuns",
            {"dag_run_id": f"manual__streaming_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"},
        )
        # Generate immediate workbench metrics while Airflow executes asynchronously.
        background_tasks.add_task(run_local_workbench_pipeline)
    except Exception:
        trigger_mode = "local_fallback"
        local_result = run_local_workbench_pipeline()
        scheduled_run = local_result["scheduled_pipeline_run"]
        streaming_run = local_result["streaming_pipeline_run"]

    append_event(
        "pipeline_start_requested",
        {
            "scheduled_pipeline_run_id": scheduled_run.get("dag_run_id"),
            "streaming_pipeline_run_id": streaming_run.get("dag_run_id"),
            "dataset": str(workbench_dataset_path),
        },
    )

    return {
        "status": "started",
        "mode": trigger_mode,
        "scheduled_pipeline_run": scheduled_run,
        "streaming_pipeline_run": streaming_run,
    }


@app.get("/api/pipeline/status")
def pipeline_status():
    return {
        "scheduled_pipeline": get_latest_run_status("scheduled_pipeline"),
        "streaming_pipeline": get_latest_run_status("streaming_pipeline"),
    }


@app.get("/api/pipeline/logs")
def pipeline_logs(lines: int = Query(default=120, ge=20, le=400)):
    return {
        "lines": collect_live_logs(max_lines=lines),
        "events": platform_events(limit=30),
    }


@app.get("/api/platform/events")
def platform_events(limit: int = 100):
    if not events_path.exists():
        return []
    lines = events_path.read_text(encoding="utf-8").splitlines()
    selected = lines[-max(limit, 1):]
    return [json.loads(line) for line in selected if line.strip()]


@app.get("/api/platform/report")
def platform_report():
    stream_metrics_data = stream_metrics()
    report = {
        "dataset_upload": read_json_file(platform_report_path, {}).get("dataset_upload", {}),
        "batch_report": read_json_file(batch_report_path, {}),
        "stream_report": read_json_file(stream_report_path, {}),
        "stream_metrics": stream_metrics_data,
    }
    return report


@app.get("/api/report/pdf")
def download_report_pdf(mode: str = Query(default="default", pattern="^(default|workbench)$")):
    try:
        pdf_path = create_report_pdf(mode)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=pdf_path.name,
    )


@app.get("/api/diagrams/{diagram_name}")
def get_diagram(diagram_name: str):
    allowed = {"scheduled_pipeline.png", "event_pipeline.png", "streaming_pipeline.png"}
    if diagram_name not in allowed:
        raise HTTPException(status_code=404, detail="Diagram not found")

    diagram_path = diagrams_root / diagram_name
    if not diagram_path.exists():
        raise HTTPException(status_code=404, detail="Diagram file not generated yet")

    return FileResponse(path=str(diagram_path), media_type="image/png", filename=diagram_name)
