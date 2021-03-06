from datetime import datetime
from pinecrypt.server import db
from pinecrypt.server.logger import CertidudeLogger

class LogHandler(CertidudeLogger):
    def emit(self, record):
        d= {}
        d["created"] = datetime.utcfromtimestamp(record.created)
#        d["facility"] = record.name
#        d["level"] = record.levelno
        d["severity"] = record.levelname.lower()
        d["message"] = record.msg % record.args
#        d["module"] = record.module
#        d["func"] = record.funcName
#        d["lineno"] = record.lineno
#        d["exception"] = logging._defaultFormatter.formatException(record.exc_info) if record.exc_info else "",
#        d["process"] = record.process
#        d["thread"] = record.thread
#        d["thread_name"] = record.threadName
        db.eventlog.insert(d, w=1)
