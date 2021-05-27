import pymongo
from pinecrypt.server import const
from pymongo import MongoClient
from time import sleep


client = MongoClient(const.MONGO_URI)
db = client.get_default_database()
collection = db["certidude_config"]

def populate(tp, key, value):
    collection.update_one({
        "key": key,
        "type": tp,
    }, {
       "$setOnInsert": {
           "value": value,
           "enabled": True
       }
    }, upsert=True)


def get(tp, key):
    return collection.find_one({
        "key": key,
        "type": tp,
    })


def options(tp):
    retval = []
    for j in collection.find({"type": tp}):
        j.pop("_id")
        retval.append(j)
    return sorted(retval, key=lambda e: e["key"])


def get_all(tp):
    return collection.find({
        "type": tp,
    })


def fixtures():
    # Signature profile for Certidude gateway replicas
    populate("SignatureProfile", "Gateway", dict(
        ou="Gateway",
        san=const.AUTHORITY_NAMESPACE,
        ca=False,
        lifetime=365 * 5,
        server_auth=True,
        client_auth=True,
        common_name="RE_FQDN",
    ))

    # Signature profile for laptops
    populate("SignatureProfile", "Roadwarrior", dict(
        ou="Roadwarrior",
        ca=False,
        common_name="RE_HOSTNAME",
        client_auth=True,
        lifetime=365 * 5,
    ))

    # Insert these to database so upgrading to version which defaults to
    # different ciphers won't break any existing deployments
    d = "ECDHE-ECDSA" if const.AUTHORITY_KEYTYPE == "ec" else "DHE-RSA"
    populate("Globals", "OPENVPN_TLS_CIPHER", "TLS-%s-WITH-AES-256-GCM-SHA384" % d)  # Used by TLS 1.2
    populate("Globals", "OPENVPN_TLS_CIPHERSUITES", "TLS_AES_256_GCM_SHA384")  # Used by TLS 1.3
    populate("Globals", "OPENVPN_TLS_VERSION_MIN", "1.2")  # 1.3 is not supported by Ubuntu 18.04
    populate("Globals", "OPENVPN_CIPHER", "AES-128-GCM")
    populate("Globals", "OPENVPN_AUTH", "SHA384")

    d = "ecp384" if const.AUTHORITY_KEYTYPE == "ec" else "modp2048"
    populate("Globals", "STRONGSWAN_DHGROUP", d)
    populate("Globals", "STRONGSWAN_IKE", "aes256-sha384-prfsha384-%s" % d)
    populate("Globals", "STRONGSWAN_ESP", "aes128gcm16-aes128gmac-%s" % d)

# Populate MongoDB during import because this module is loaded
# from several entrypoints in non-deterministic order
# TODO: Add Prometheus metric a'la "waiting for mongo"
while True:
    try:
        fixtures()
    except pymongo.errors.ServerSelectionTimeoutError:
        sleep(1)
        continue
    else:
        break
