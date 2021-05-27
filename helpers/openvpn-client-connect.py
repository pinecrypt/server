#!/usr/bin/python3
import os
import sys
from pinecrypt.server import db

# This implements OCSP like functionality

obj = db.certificates.find_one({
    # TODO: use digest instead
    "serial_number": "%x" % int(os.environ["tls_serial_0"]),
    "status":"signed",
})

if not obj:
    sys.exit(1)
