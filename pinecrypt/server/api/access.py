import falcon
import logging
import json
import hashlib
from pinecrypt.server import authority, errors, db
from bson.objectid import ObjectId
from pinecrypt.server.decorators import csrf_protection
from .utils.firewall import login_required, authorize_admin

logger = logging.getLogger(__name__)


class DisableEnableAccessToInstance(object):
    @csrf_protection
    @login_required
    @authorize_admin
    def on_post(self, req, resp, id):
        bool = req.get_param_as_bool("disable")

        result = db.certificates.find_one_and_update({
            "_id": ObjectId(id)
        }, {
            "$set": {
                "disabled": bool
           }
        },
        upsert=True,
        return_document=db.return_new)

        if not result:
            resp.text = "No certificate found with id %s" % id
            raise falcon.HTTPNotFound()


    @login_required
    @authorize_admin
    def on_get(self, req, resp, id):
        result = db.certificates.find_one({"_id": ObjectId(id)})

        if not result:
            resp.text = "No certificate found with id %s" % id
            raise falcon.HTTPNotFound()

        resp.text = str(result["disabled"])
