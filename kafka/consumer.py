import argparse
import json

from kafka import KafkaConsumer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Debug consumer for security-logs topic")
    parser.add_argument("--topic", default="security-logs")
    parser.add_argument("--bootstrap-servers", default="kafka:9092")
    parser.add_argument("--max-messages", type=int, default=20)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    consumer = KafkaConsumer(
        args.topic,
        bootstrap_servers=args.bootstrap_servers,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        consumer_timeout_ms=10000,
        group_id="cyberrakshak-debug-consumer",
    )

    count = 0
    for message in consumer:
        count += 1
        print(message.value)
        if count >= args.max_messages:
            break

    consumer.close()
    print(f"Consumed {count} messages")


if __name__ == "__main__":
    main()
