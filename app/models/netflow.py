from datetime import datetime
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



# stari test zapis, sad se koriste zapisi iz logs/flows.jsonl.
#def create_example_record() -> NetFlowZapis | None:
#   records = create_example_records()
#    return records[0] if records else None


#NetFlow zapisi za test
#def create_example_records() -> list[NetFlowZapis]:
  #  return []

    #stari test zapisa
    # {
    #     "bytes": 1500,
    #     "ip-total-length": 1500,
    #     "src-address": "192.168.1.10",
    #     "dst-address": "8.8.8.8",
    #     "src-port": 54321,
    #     "dst-port": 53,
    #     "protocol": 17,
    #     "packets": 10,
    #     "in-interface": "ether1",
    #     "out-interface": "ether2",
    #     "router-id": "R1",
    # }


#Test za provjeravu prometa
#def is_large_transfer(record: NetFlowZapis) -> bool:
 #   return record["bytes"] > 1000000
