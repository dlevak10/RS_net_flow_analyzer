from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from struct import unpack_from
from typing import Any


TEMPLATE_SET_ID_V9 = 0
TEMPLATE_SET_ID_IPFIX = 2
OPTIONS_TEMPLATE_SET_IDS = {1, 3}


FIELD_NAMES = {
    1: "bytes",
    2: "packets",
    4: "protocol",
    5: "tos",
    6: "tcp_flags",
    7: "src_port",
    8: "src_ip",
    10: "input_interface",
    11: "dst_port",
    12: "dst_ip",
    14: "output_interface",
    15: "next_hop",
    21: "last_switched",
    22: "first_switched",
    27: "src_ipv6",
    28: "dst_ipv6",
    58: "src_vlan",
    59: "dst_vlan",
    80: "dst_mac",
    81: "src_mac",
    152: "flow_start_ms",
    153: "flow_end_ms",
    225: "post_nat_src_ip",
    226: "post_nat_dst_ip",
    227: "post_napt_src_port",
    228: "post_napt_dst_port",
}


@dataclass(frozen=True)
class FieldSpec:
    field_id: int
    length: int
    enterprise_number: int | None = None


@dataclass(frozen=True)
class Template:
    template_id: int
    fields: tuple[FieldSpec, ...]

    @property
    def fixed_record_length(self) -> int | None:
        if any(field.length == 65535 for field in self.fields):
            return None
        return sum(field.length for field in self.fields)


class NetFlowParser:
    def __init__(self) -> None:
        self.templates: dict[tuple[int, str, int, int], Template] = {}

    def parse_packet(
        self,
        data: bytes,
        router_ip: str,
        received_at: str | None = None,
    ) -> dict[str, Any]:
        if len(data) < 4:
            return self._error("packet_too_short", router_ip, received_at, len(data))

        version = unpack_from("!H", data, 0)[0]
        if version == 10:
            return self._parse_ipfix(data, router_ip, received_at)
        if version == 9:
            return self._parse_netflow_v9(data, router_ip, received_at)

        return self._error("unsupported_version", router_ip, received_at, len(data), version)

    def _parse_ipfix(self, data: bytes, router_ip: str, received_at: str | None) -> dict[str, Any]:
        if len(data) < 16:
            return self._error("ipfix_header_too_short", router_ip, received_at, len(data), 10)

        version, packet_length, export_time, sequence_number, observation_domain_id = unpack_from("!HHIII", data, 0)
        message = {
            "received_at": received_at,
            "router_ip": router_ip,
            "version": version,
            "packet_length": packet_length,
            "export_time": datetime.fromtimestamp(export_time, timezone.utc).isoformat(),
            "sequence_number": sequence_number,
            "observation_domain_id": observation_domain_id,
            "templates_seen": [],
            "flows": [],
            "warnings": [],
        }

        offset = 16
        packet_end = min(packet_length, len(data))
        while offset + 4 <= packet_end:
            set_id, set_length = unpack_from("!HH", data, offset)
            if set_length < 4 or offset + set_length > packet_end:
                message["warnings"].append(f"invalid_set_length:{set_id}")
                break

            set_payload = data[offset + 4:offset + set_length]
            if set_id == TEMPLATE_SET_ID_IPFIX:
                templates = self._parse_template_set(set_payload, version, router_ip, observation_domain_id)
                message["templates_seen"].extend(template.template_id for template in templates)
            elif set_id not in OPTIONS_TEMPLATE_SET_IDS and set_id >= 256:
                template = self.templates.get((version, router_ip, observation_domain_id, set_id))
                if template is None:
                    message["warnings"].append(f"missing_template:{set_id}")
                else:
                    message["flows"].extend(self._parse_data_set(set_payload, template))

            offset += set_length

        return message

    def _parse_netflow_v9(self, data: bytes, router_ip: str, received_at: str | None) -> dict[str, Any]:
        if len(data) < 20:
            return self._error("netflow_v9_header_too_short", router_ip, received_at, len(data), 9)

        version, count, sys_uptime, unix_seconds, sequence_number, source_id = unpack_from("!HHIIII", data, 0)
        message = {
            "received_at": received_at,
            "router_ip": router_ip,
            "version": version,
            "packet_count": count,
            "sys_uptime": sys_uptime,
            "export_time": datetime.fromtimestamp(unix_seconds, timezone.utc).isoformat(),
            "sequence_number": sequence_number,
            "source_id": source_id,
            "templates_seen": [],
            "flows": [],
            "warnings": [],
        }

        offset = 20
        while offset + 4 <= len(data):
            flowset_id, flowset_length = unpack_from("!HH", data, offset)
            if flowset_length < 4 or offset + flowset_length > len(data):
                message["warnings"].append(f"invalid_flowset_length:{flowset_id}")
                break

            flowset_payload = data[offset + 4:offset + flowset_length]
            if flowset_id == TEMPLATE_SET_ID_V9:
                templates = self._parse_template_set(flowset_payload, version, router_ip, source_id)
                message["templates_seen"].extend(template.template_id for template in templates)
            elif flowset_id not in OPTIONS_TEMPLATE_SET_IDS and flowset_id >= 256:
                template = self.templates.get((version, router_ip, source_id, flowset_id))
                if template is None:
                    message["warnings"].append(f"missing_template:{flowset_id}")
                else:
                    message["flows"].extend(self._parse_data_set(flowset_payload, template))

            offset += flowset_length

        return message

    def _parse_template_set(
        self,
        payload: bytes,
        version: int,
        router_ip: str,
        source_id: int,
    ) -> list[Template]:
        templates = []
        offset = 0

        while offset + 4 <= len(payload):
            template_id, field_count = unpack_from("!HH", payload, offset)
            offset += 4

            fields = []
            for _ in range(field_count):
                if offset + 4 > len(payload):
                    return templates

                raw_field_id, field_length = unpack_from("!HH", payload, offset)
                offset += 4
                enterprise_number = None
                field_id = raw_field_id & 0x7FFF

                if raw_field_id & 0x8000:
                    if offset + 4 > len(payload):
                        return templates
                    enterprise_number = unpack_from("!I", payload, offset)[0]
                    offset += 4

                fields.append(FieldSpec(field_id, field_length, enterprise_number))

            template = Template(template_id, tuple(fields))
            self.templates[(version, router_ip, source_id, template_id)] = template
            templates.append(template)

            if template_id == 0 and field_count == 0:
                break

        return templates

    def _parse_data_set(self, payload: bytes, template: Template) -> list[dict[str, Any]]:
        record_length = template.fixed_record_length
        if not record_length:
            return []

        records = []
        offset = 0
        while offset + record_length <= len(payload):
            record_bytes = payload[offset:offset + record_length]
            if not any(record_bytes):
                break

            record = self._parse_record(record_bytes, template)
            if record:
                records.append(record)

            offset += record_length

        return records

    def _parse_record(self, record: bytes, template: Template) -> dict[str, Any]:
        parsed: dict[str, Any] = {}
        raw_fields: dict[str, str] = {}
        offset = 0

        for field in template.fields:
            value_bytes = record[offset:offset + field.length]
            offset += field.length
            name = FIELD_NAMES.get(field.field_id)

            if name:
                parsed[name] = self._decode_known_field(field.field_id, value_bytes)
            else:
                raw_fields[str(field.field_id)] = value_bytes.hex()

        if raw_fields:
            parsed["raw_fields"] = raw_fields

        return parsed

    def _decode_known_field(self, field_id: int, value: bytes) -> Any:
        if field_id in {8, 12, 15, 225, 226} and len(value) == 4:
            return str(IPv4Address(value))

        if field_id in {27, 28} and len(value) == 16:
            return str(IPv6Address(value))

        if field_id in {80, 81} and len(value) == 6:
            return ":".join(f"{part:02x}" for part in value)

        if field_id in {152, 153} and len(value) == 8:
            milliseconds = int.from_bytes(value, "big", signed=False)
            return datetime.fromtimestamp(milliseconds / 1000, timezone.utc).isoformat()

        if len(value) in {1, 2, 4, 8}:
            return int.from_bytes(value, "big", signed=False)

        return value.hex()

    def _error(
        self,
        reason: str,
        router_ip: str,
        received_at: str | None,
        packet_length: int,
        version: int | None = None,
    ) -> dict[str, Any]:
        return {
            "received_at": received_at,
            "router_ip": router_ip,
            "version": version,
            "packet_length": packet_length,
            "templates_seen": [],
            "flows": [],
            "warnings": [reason],
        }
