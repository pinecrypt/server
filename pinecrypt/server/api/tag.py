from pinecrypt.server import db
from pinecrypt.server.decorators import serialize, csrf_protection
from .utils.firewall import login_required, authorize_admin

class TagResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp, id):
        tags = db.certificates.find_one({"_id": db.ObjectId(id), "status": "signed"}).get("tags")
        return tags

    @csrf_protection
    @login_required
    @authorize_admin
    def on_post(self, req, resp, id):
        # TODO: Sanitize input
        key, value = req.get_param("key", required=True), req.get_param("value", required=True)
        db.certificates.update_one({
            "_id": db.ObjectId(id),
            "status": "signed"
        }, {
            "$addToSet": {"tags": "%s=%s" % (key, value)}
        })


class TagDetailResource(object):
    @csrf_protection
    @login_required
    @authorize_admin
    def on_put(self, req, resp, id, tag):
        key = tag
        if "=" in tag:
            key, prev_value = tag.split("=")

        value = req.get_param("value", required=True)
        # TODO: Make atomic https://docs.mongodb.com/manual/reference/operator/update-array/
        db.certificates.find_one_and_update({
            "_id": db.ObjectId(id),
            "status": "signed"
        }, {
            "$pull": {"tags": tag}
        })

        db.certificates.find_one_and_update({
            "_id": db.ObjectId(id),
            "status": "signed"
        }, {
            "$addToSet": {"tags": "%s=%s" % (key, value)}
        })


    @csrf_protection
    @login_required
    @authorize_admin
    def on_delete(self, req, resp, id, tag):
        db.certificates.find_one_and_update({
            "_id": db.ObjectId(id),
            "status": "signed"
        }, {
            "$pull": {"tags": tag}
        })
