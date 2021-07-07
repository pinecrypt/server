from datetime import datetime
from functools import wraps
from oscrypto import asymmetric
from json import dumps
from motor.motor_asyncio import AsyncIOMotorClient
from pinecrypt.server import const
from prometheus_client import Counter
from sanic import Sanic
from sanic.response import stream
from sanic_prometheus import monitor
from bson.objectid import ObjectId


streams_opened = Counter("pinecrypt_gateway_streams_started",
    "Total number event stream has been opened.")
events_emitted = Counter("pinecrypt_gateway_events_emitted",
    "Total number of events emitted via event streams.")


app = Sanic("events")
monitor(app).expose_endpoint()
app.config.RESPONSE_TIMEOUT = 999


def cookie_login(func):
    @wraps(func)
    async def wrapped(request, *args, **kwargs):
        if request.method != "GET":
            raise ValueError("For now stick with read-only operations for cookie auth")
        value = request.cookies.get(const.SESSION_COOKIE)
        now = datetime.utcnow()
        await app.db.certidude_sessions.update_one({
            "secret": value,
            "started": {
                "$lte": now
            },
            "expires": {
                "$gte": now
            },
        }, {
            "$set": {
                "last_seen": now
            }
        })
        return await func(request, *args, **kwargs)
    return wrapped


@app.listener("before_server_start")
async def setup_db(app, loop):
    # TODO: find cleaner way to do this, for more see
    # https://github.com/sanic-org/sanic/issues/919
    app.db = AsyncIOMotorClient(const.MONGO_URI).get_default_database()


# TODO: Change to /api/event/log and simplify nginx config to /api/event
@app.route("/api/event/")
@cookie_login
async def view_event(request):
    async def g(resp):
        await resp.write("data: response-generator-started\n\n")
        streams_opened.inc()

        async with app.db.watch(full_document="updateLookup") as stream:
            await resp.write("data: watch-stream-opened\n\n")
            async for event in stream:

                if event.get("ns").get("coll") == "certidude_certificates":

                    if event.get("operationType") == "insert" and event["fullDocument"].get("status") == "csr":
                        await resp.write("event: request-submitted\ndata: %s\n\n" % str(event["documentKey"].get("_id")))
                        events_emitted.inc()

                    if event.get("operationType") == "update" and event["updateDescription"].get("updatedFields").get("status") == "signed":
                        await resp.write("event: request-signed\ndata: %s\n\n" % str(event["documentKey"].get("_id")))
                        events_emitted.inc()

                    if event.get("operationType") == "insert" and event["fullDocument"].get("status") == "signed":
                        await resp.write("event: request-signed\ndata: %s\n\n" % event["fullDocument"].get("common_name"))
                        events_emitted.inc()

                    if event.get("operationType") == "update" and event["fullDocument"].get("status") == "revoked":
                        await resp.write("event: certificate-revoked\ndata: %s\n\n" % str(event["documentKey"].get("_id")))
                        events_emitted.inc()

                    if event.get("operationType") == "delete":
                        await resp.write("event: request-deleted\ndata: %s\n\n" % str(event["documentKey"].get("_id")))
                        events_emitted.inc()

                    if event.get("operationType") == "update" and "tags" in event.get("updateDescription").get("updatedFields"):
                        await resp.write("event: tag-update\ndata: %s\n\n" % str(event["documentKey"].get("_id")))
                        events_emitted.inc()

                    if event.get("operationType") == "update" and "attributes" in event.get("updateDescription").get("updatedFields"):
                        await resp.write("event: attribute-update\ndata: %s\n\n" % str(event["documentKey"].get("_id")))
                        events_emitted.inc()

                    if event.get("operationType") == "update" and "disabled" in event.get("updateDescription").get("updatedFields"):
                        await resp.write("event: instance-access-update\ndata: %s\n\n" % str(event["documentKey"].get("_id")))
                        events_emitted.inc()

                if event.get("ns").get("coll") == "certidude_logs":

                    from pinecrypt.server.decorators import MyEncoder

                    obj = dict(
                        created=event["fullDocument"].get("created"),
                        message=event["fullDocument"].get("message"),
                        severity=event["fullDocument"].get("severity")
                    )

                    await resp.write("event: log-entry\ndata: %s\n\n" % dumps(obj, cls=MyEncoder))
                    events_emitted.inc()
    return stream(g, content_type="text/event-stream")


@app.route("/api/event/request-signed/<id>")
async def publish(request, id):
    pipeline = [{"$match": {"operationType": "update", "fullDocument.status": "signed", "documentKey._id": ObjectId(id)}}]
    resp = await request.respond(content_type="application/x-x509-user-cert")
    async with app.db["certidude_certificates"].watch(pipeline, full_document="updateLookup") as stream:
        async for event in stream:
            cert_der = event["fullDocument"].get("cert_buf")
            cert_pem = asymmetric.dump_certificate(asymmetric.load_certificate(cert_der))
            await resp.send(cert_pem, True)
    return resp
