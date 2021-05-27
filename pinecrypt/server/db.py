
from pinecrypt.server import const
from pymongo import MongoClient, ReturnDocument

return_new = ReturnDocument.AFTER
client = MongoClient(const.MONGO_URI)
db = client.get_default_database()
certificates = db["certidude_certificates"]
eventlog = db["certidude_logs"]
tokens = db["certidude_tokens"]
sessions = db["certidude_sessions"]
secrets = db["certidude_secrets"]
