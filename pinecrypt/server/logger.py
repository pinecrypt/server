import time


class LoggerObject(object):
    msg = None
    args = None
    levelname = None
    created = None


class CertidudeLogger(object):

    def info(self, msg, *args):
        self.pre_emit(msg, *args, level="Info")

    def warning(self, msg, *args):
        self.pre_emit(msg, *args, level="Warning")

    def error(self, msg, *args):
        self.pre_emit(msg, *args, level="Error")

    def debug(self, msg, *args):
        self.pre_emit(msg, *args, level="Debug")

    def pre_emit(self, msg, *args, level):
        record = LoggerObject()
        record.msg = msg
        record.args = args
        record.levelname = level
        record.created = time.time()
        self.emit(record)

    def emit(self, record):
        pass
