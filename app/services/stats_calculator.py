import json
from collections import Counter
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parents[2]
FLOW_LOG_FILE = BASE_DIR / "logs" / "flows.jsonl"

PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def read_flow_records(limit: int = 100) -> list[dict[str, Any]]:
    if not FLOW_LOG_FILE.exists():
        return []

    records = []
    with FLOW_LOG_FILE.open("r", encoding="utf-8") as flow_log:
        for line in flow_log:
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not is_clean_flow_record(record):
                continue

            records.append(normalize_flow_record(record))

    return records[-limit:]


def is_clean_flow_record(record: dict[str, Any]) -> bool:
    return "time" in record and "raw_fields" not in record


def normalize_flow_record(record: dict[str, Any]) -> dict[str, Any]:
    protocol = record.get("protocol")

    return {
        "time": record.get("time") or record.get("export_time") or record.get("received_at"),
        "router_ip": record.get("router_ip"),
        "src_ip": record.get("src_ip"),
        "dst_ip": record.get("dst_ip"),
        "src_port": record.get("src_port"),
        "dst_port": record.get("dst_port"),
        "protocol": PROTOCOL_NAMES.get(protocol, protocol),
        "bytes": record.get("bytes") or 0,
        "packets": record.get("packets") or 0,
        "input_interface": record.get("input_interface"),
        "output_interface": record.get("output_interface"),
        "post_nat_src_ip": record.get("post_nat_src_ip"),
        "post_nat_dst_ip": record.get("post_nat_dst_ip"),
    }


def calculate_flow_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    total_bytes = sum(to_int(record.get("bytes")) for record in records)
    total_packets = sum(to_int(record.get("packets")) for record in records)
    destination_counter = Counter(
        record["dst_ip"] for record in records if record.get("dst_ip")
    )
    protocol_counter = Counter(
        record["protocol"] for record in records if record.get("protocol")
    )

    return {
        "flow_count": len(records),
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "top_destination": first_counter_value(destination_counter),
        "top_protocol": first_counter_value(protocol_counter),
    }


def first_counter_value(counter: Counter) -> str:
    if not counter:
        return "-"

    value, count = counter.most_common(1)[0]
    return f"{value} ({count})"


def to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
