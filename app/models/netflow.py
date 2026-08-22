from datetime import datetime, timedelta
from typing import TypedDict


#Mikrotik dictionary za netflow zapis
NetFlowZapis = TypedDict(
    "NetFlowZapis",
    {
        "bytes": int,
        "ip-total-length": int,
        "src-address": str,
        "dst-address": str,
        "src-port": int,
        "dst-port": int,
        "first-forwarded": datetime,
        "last-forwarded": datetime,
        "protocol": int,
        "packets": int,
        "in-interface": str,
        "out-interface": str,
        "router-id": str,
    },
)


#Primjer NetFlow zapisa za test
def create_example_record() -> NetFlowZapis:
    return create_example_records()[0]


#NetFlow zapisi za test
def create_example_records() -> list[NetFlowZapis]:
    current_time = datetime.now()

    return [{
        "bytes": 1500,
        "ip-total-length": 1500,
        "src-address": "192.168.1.10",
        "dst-address": "8.8.8.8",
        "src-port": 54321,
        "dst-port": 53,
        "first-forwarded": current_time,
        "last-forwarded": current_time + timedelta(seconds=2),
        "protocol": 17,
        "packets": 10,
        "in-interface": "ether1",
        "out-interface": "ether2",
        "router-id": "R1",
    },
    {
        "bytes": 250000,
        "ip-total-length": 1200,
        "src-address": "192.168.1.20",
        "dst-address": "192.168.1.30",
        "src-port": 443,
        "dst-port": 51432,
        "first-forwarded": current_time + timedelta(seconds=5),
        "last-forwarded": current_time + timedelta(seconds=15),
        "protocol": 6,
        "packets": 180,
        "in-interface": "ether2",
        "out-interface": "ether1",
        "router-id": "R1",
    },
    {
        "bytes": 3200,
        "ip-total-length": 84,
        "src-address": "8.8.8.8",
        "dst-address": "192.168.1.10",
        "src-port": 53,
        "dst-port": 0,
        "first-forwarded": current_time + timedelta(seconds=20),
        "last-forwarded": current_time + timedelta(seconds=21),
        "protocol": 1,
        "packets": 4,
        "in-interface": "ether2",
        "out-interface": "ether1",
        "router-id": "R2",
    }]


#Test za provjeravu prometa
def is_large_transfer(record: NetFlowZapis) -> bool:
    return record["bytes"] > 1000000
