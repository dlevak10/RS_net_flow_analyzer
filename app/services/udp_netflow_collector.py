import base64
import json
import os
import signal
import socket
from datetime import datetime, timezone
from pathlib import Path

from app.services.netflow_parser import NetFlowParser


DEFAULT_LOG_FILE = Path(__file__).resolve().parents[2] / "logs" / "netflow-udp.jsonl"
DEFAULT_FLOW_LOG_FILE = Path(__file__).resolve().parents[2] / "logs" / "flows.jsonl"


PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def build_log_entry(data: bytes, address: tuple[str, int]) -> dict[str, object]:
    return {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": address[0],
        "source_port": address[1],
        "payload_length": len(data),
        "payload_base64": base64.b64encode(data).decode("ascii"),
        "payload_hex_prefix": data[:32].hex(),
    }


def build_clean_flow(parsed_packet: dict[str, object], flow: dict[str, object]) -> dict[str, object]:
    protocol = flow.get("protocol")

    return {
        "time": parsed_packet.get("export_time") or parsed_packet.get("received_at"),
        "received_at": parsed_packet.get("received_at"),
        "router_ip": parsed_packet.get("router_ip"),
        "version": parsed_packet.get("version"),
        "sequence_number": parsed_packet.get("sequence_number"),
        "src_ip": flow.get("src_ip"),
        "dst_ip": flow.get("dst_ip"),
        "src_port": flow.get("src_port"),
        "dst_port": flow.get("dst_port"),
        "protocol": PROTOCOL_NAMES.get(protocol, protocol),
        "bytes": flow.get("bytes"),
        "packets": flow.get("packets"),
        "input_interface": flow.get("input_interface"),
        "output_interface": flow.get("output_interface"),
        "first_switched": flow.get("first_switched"),
        "last_switched": flow.get("last_switched"),
        "post_nat_src_ip": flow.get("post_nat_src_ip"),
        "post_nat_dst_ip": flow.get("post_nat_dst_ip"),
        "post_napt_src_port": flow.get("post_napt_src_port"),
        "post_napt_dst_port": flow.get("post_napt_dst_port"),
    }


def main() -> None:
    host = os.getenv("NETFLOW_UDP_HOST", "0.0.0.0")
    port = int(os.getenv("NETFLOW_UDP_PORT", "2055"))
    log_file = Path(os.getenv("NETFLOW_LOG_FILE", str(DEFAULT_LOG_FILE)))
    flow_log_file = Path(os.getenv("NETFLOW_FLOW_LOG_FILE", str(DEFAULT_FLOW_LOG_FILE)))
    log_file.parent.mkdir(parents=True, exist_ok=True)
    flow_log_file.parent.mkdir(parents=True, exist_ok=True)
    parser = NetFlowParser()

    running = True

    def stop_handler(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((host, port))
        server.settimeout(1.0)
        print(f"Listening for NetFlow UDP on {host}:{port}")
        print(f"Writing raw packets to {log_file}")
        print(f"Writing parsed flows to {flow_log_file}")

        while running:
            try:
                data, address = server.recvfrom(65535)
            except socket.timeout:
                continue

            entry = build_log_entry(data, address)
            with log_file.open("a", encoding="utf-8") as output:
                output.write(json.dumps(entry, ensure_ascii=False) + "\n")
                output.flush()

            parsed_packet = parser.parse_packet(
                data,
                router_ip=address[0],
                received_at=entry["received_at"],
            )
            if parsed_packet["templates_seen"] or parsed_packet["warnings"]:
                print(
                    "NetFlow packet "
                    f"version={parsed_packet['version']} "
                    f"templates={parsed_packet['templates_seen']} "
                    f"flows={len(parsed_packet['flows'])} "
                    f"warnings={parsed_packet['warnings']}"
                )

            if parsed_packet["flows"]:
                with flow_log_file.open("a", encoding="utf-8") as output:
                    for flow in parsed_packet["flows"]:
                        flow_entry = build_clean_flow(parsed_packet, flow)
                        output.write(json.dumps(flow_entry, ensure_ascii=False) + "\n")
                    output.flush()


if __name__ == "__main__":
    main()
