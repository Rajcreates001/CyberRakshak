import argparse
import ipaddress
import os
import random
from datetime import datetime, timedelta

import pandas as pd


DEFAULT_ROWS = 5000
OUTPUT_PATH = os.path.join("data", "raw", "security_logs.csv")
PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "ICMP"]
ATTACK_TYPES = ["normal", "port_scan", "brute_force", "traffic_spike"]


def _random_ip(private=True):
    if private:
        network = random.choice(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
        net = ipaddress.ip_network(network)
        return str(net.network_address + random.randint(2, min(net.num_addresses - 2, 65534)))
    return f"{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _status_code(protocol: str, attack_type: str) -> int:
    if protocol in {"HTTP", "HTTPS"}:
        if attack_type == "brute_force":
            return random.choice([401, 403, 429])
        if attack_type == "traffic_spike":
            return random.choice([200, 429, 503])
        return random.choice([200, 200, 200, 404])
    return random.choice([0, 0, 0, 1])


def _base_log(ts: datetime) -> dict:
    protocol = random.choice(PROTOCOLS)
    return {
        "timestamp": ts.isoformat(),
        "src_ip": _random_ip(private=True),
        "dst_ip": _random_ip(private=False),
        "port": random.choice([22, 53, 80, 443, 8080, 3306]),
        "protocol": protocol,
        "packet_size": random.randint(64, 1514),
        "connection_duration": round(random.uniform(0.1, 120.0), 3),
        "login_attempts": random.randint(0, 2),
        "request_rate": random.randint(5, 80),
        "bytes_transferred": random.randint(512, 200000),
        "status_code": _status_code(protocol, "normal"),
        "attack_type": "normal",
    }


def _apply_port_scan(log: dict, attacker_ip: str, scan_ports: list[int]) -> dict:
    log["src_ip"] = attacker_ip
    log["port"] = random.choice(scan_ports)
    log["connection_duration"] = round(random.uniform(0.01, 1.5), 3)
    log["request_rate"] = random.randint(120, 300)
    log["packet_size"] = random.randint(64, 350)
    log["bytes_transferred"] = random.randint(64, 5000)
    log["attack_type"] = "port_scan"
    return log


def _apply_brute_force(log: dict, attacker_ip: str) -> dict:
    log["src_ip"] = attacker_ip
    log["port"] = random.choice([22, 3389, 443])
    log["login_attempts"] = random.randint(6, 20)
    log["request_rate"] = random.randint(70, 180)
    log["status_code"] = random.choice([401, 403, 429])
    log["attack_type"] = "brute_force"
    return log


def _apply_traffic_spike(log: dict, attacker_ip: str) -> dict:
    log["src_ip"] = attacker_ip
    log["request_rate"] = random.randint(300, 1200)
    log["packet_size"] = random.randint(500, 1500)
    log["connection_duration"] = round(random.uniform(0.01, 3.0), 3)
    log["bytes_transferred"] = random.randint(150000, 5000000)
    log["status_code"] = random.choice([429, 503])
    log["attack_type"] = "traffic_spike"
    return log


def generate_security_logs(num_rows: int = DEFAULT_ROWS, output_path: str = OUTPUT_PATH) -> str:
    random.seed(42)
    now = datetime.utcnow()
    attack_actor_pool = {
        "port_scan": _random_ip(private=True),
        "brute_force": _random_ip(private=True),
        "traffic_spike": _random_ip(private=True),
    }
    scan_ports = list(range(20, 140))

    logs = []
    for i in range(num_rows):
        event_time = now - timedelta(seconds=(num_rows - i) * random.uniform(0.2, 1.4))
        log = _base_log(event_time)
        attack_roll = random.random()

        if attack_roll < 0.14:
            log = _apply_port_scan(log, attack_actor_pool["port_scan"], scan_ports)
        elif attack_roll < 0.27:
            log = _apply_brute_force(log, attack_actor_pool["brute_force"])
        elif attack_roll < 0.39:
            log = _apply_traffic_spike(log, attack_actor_pool["traffic_spike"])

        logs.append(log)

    df = pd.DataFrame(logs)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate simulated cybersecurity telemetry logs")
    parser.add_argument("--rows", type=int, default=DEFAULT_ROWS, help="Number of logs to generate")
    parser.add_argument("--output", type=str, default=OUTPUT_PATH, help="CSV output path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_path = generate_security_logs(num_rows=args.rows, output_path=args.output)
    print(f"Generated {args.rows} security logs at {output_path}")


if __name__ == "__main__":
    main()
