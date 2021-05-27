#!/usr/bin/python3
import os
import sys
from pinecrypt.server import db
from datetime import datetime

operation, addr = sys.argv[1:3]
if operation == "delete":
    pass
else:
    common_name = sys.argv[3]
    db.certificates.update_one({
        # TODO: use digest instead
        "serial_number": "%x" % int(os.environ["tls_serial_0"]),
        "status":"signed",
    }, {
        "$set": {
            "last_seen": datetime.utcnow(),
            "instance": os.environ["instance"],
            "remote": {
                "port": int(os.environ["untrusted_port"]),
                "addr": os.environ["untrusted_ip"],
            }
        },
        "$addToSet": {
            "ip": addr
        }
    })
