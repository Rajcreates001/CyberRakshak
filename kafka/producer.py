import argparse
import csv
import json
import time
from pathlib import Path

from kafka import KafkaProducer


DEFAULT_DATASET = "/opt/airflow/data/raw/security_logs.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stream CSV rows to Kafka")
    parser.add_argument("--dataset", default=DEFAULT_DATASET)
    parser.add_argument("--topic", default="security-logs")
    parser.add_argument("--bootstrap-servers", default="kafka:9092")
    parser.add_argument("--delay-seconds", type=float, default=0.02)
    parser.add_argument("--max-messages", type=int, default=50000)
    return parser.parse_args()


def first_non_empty(row: dict, keys, default=""):
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip() != "":
            return value
    return default


def canonicalize_generic_row(row: dict) -> dict:
    return {
        "timestamp": first_non_empty(row, ["timestamp", "event_time", "time"], "1970-01-01T00:00:00Z"),
        "src_ip": first_non_empty(row, ["src_ip", "source_ip"], "UNKNOWN_SRC"),
        "dst_ip": first_non_empty(row, ["dst_ip", "destination_ip"], "UNKNOWN_DST"),
        "port": int(float(first_non_empty(row, ["port", "dst_port"], "0"))),
        "protocol": first_non_empty(row, ["protocol", "proto"], "UNKNOWN"),
        "packet_size": float(first_non_empty(row, ["packet_size", "bytes"], "0")),
        "connection_duration": float(first_non_empty(row, ["connection_duration", "duration"], "0")),
        "login_attempts": float(first_non_empty(row, ["login_attempts", "attempts"], "0")),
        "request_rate": float(first_non_empty(row, ["request_rate", "rate"], "0")),
        "bytes_transferred": float(first_non_empty(row, ["bytes_transferred", "total_bytes"], "0")),
        "status_code": int(float(first_non_empty(row, ["status_code", "response_code"], "0"))),
    }


def canonicalize_security_row(row: dict) -> dict:
    return {
        "timestamp": first_non_empty(row, ["timestamp"], "1970-01-01T00:00:00Z"),
        "src_ip": first_non_empty(row, ["src_ip"], "UNKNOWN_SRC"),
        "dst_ip": first_non_empty(row, ["dst_ip"], "UNKNOWN_DST"),
        "port": int(float(first_non_empty(row, ["port"], "0"))),
        "protocol": first_non_empty(row, ["protocol"], "UNKNOWN"),
        "packet_size": float(first_non_empty(row, ["packet_size"], "0")),
        "connection_duration": float(first_non_empty(row, ["connection_duration"], "0")),
        "login_attempts": float(first_non_empty(row, ["login_attempts"], "0")),
        "request_rate": float(first_non_empty(row, ["request_rate"], "0")),
        "bytes_transferred": float(first_non_empty(row, ["bytes_transferred"], "0")),
        "status_code": int(float(first_non_empty(row, ["status_code"], "0"))),
    }


def main() -> None:
    args = parse_args()
    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    producer = KafkaProducer(
        bootstrap_servers=args.bootstrap_servers,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        linger_ms=50,
        acks="all",
    )

    sent = 0
    with dataset_path.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        header = {h.strip().lower() for h in (reader.fieldnames or [])}
        use_security_schema = {"src_ip", "dst_ip", "request_rate", "bytes_transferred"}.issubset(header)
        for row in reader:
            payload = canonicalize_security_row(row) if use_security_schema else canonicalize_generic_row(row)
            producer.send(args.topic, payload)
            sent += 1
            if sent % 500 == 0:
                producer.flush()
                print(f"Producer progress: {sent} messages sent")
            if args.max_messages > 0 and sent >= args.max_messages:
                break
            time.sleep(args.delay_seconds)

    producer.flush()
    producer.close()
    print(f"Producer finished. Total sent: {sent}")


if __name__ == "__main__":
    main()
