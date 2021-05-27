#!/usr/bin/python3
import sys
import os
from pinecrypt.server import db
from datetime import datetime

addrs = set()
for key, value in os.environ.items():
    if key.startswith("PLUTO_PEER_SOURCEIP"):
        addrs.add(value)

with open("/instance") as fh:
    instance = fh.read().strip()

db.certificates.update_one({
    "distinguished_name": os.environ["PLUTO_PEER_ID"],
    "status":"signed",
}, {
    "$set": {
        "last_seen": datetime.utcnow(),
        "instance": instance,
        "remote": {
            "addr": os.environ["PLUTO_PEER"]
        }
    },
    "$addToSet": {
        "ip": {
            "$each": list(addrs)
        }
    }
})
