from pinecrypt.server.decorators import serialize
from pinecrypt.server import db
from .utils.firewall import cookie_login

class LogResource(object):
    @serialize
    @cookie_login
    def on_get(self, req, resp):
        def g():
            for log in db.eventlog.find({}).limit(req.get_param_as_int("limit", required=True)).sort("created", -1):
                log.pop("_id")
                yield log
        return tuple(g())
