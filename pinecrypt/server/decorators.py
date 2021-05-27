import falcon
import ipaddress
import json
import logging
import types
from datetime import date, datetime, timedelta
from urllib.parse import urlparse
from bson.objectid import ObjectId

logger = logging.getLogger("api")


def csrf_protection(func):
    """
    Protect resource from common CSRF attacks by checking user agent and referrer
    """

    def wrapped(self, req, resp, *args, **kwargs):
        # Assume curl and python-requests are used intentionally
        if req.user_agent.startswith("curl/") or req.user_agent.startswith("python-requests/"):
            return func(self, req, resp, *args, **kwargs)

        # For everything else assert referrer
        referrer = req.headers.get("REFERER")


        if referrer:
            scheme, netloc, path, params, query, fragment = urlparse(referrer)
            if ":" in netloc:
                host, port = netloc.split(":", 1)
            else:
                host, port = netloc, None
            if host == req.host:
                return func(self, req, resp, *args, **kwargs)

        # Kaboom!
        logger.warning("Prevented clickbait from '%s' with user agent '%s'",
            referrer or "-", req.user_agent)
        raise falcon.HTTPForbidden("Forbidden",
            "No suitable UA or referrer provided, cross-site scripting disabled")
    return wrapped


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        from pinecrypt.server.user import User
        if isinstance(obj, ipaddress._IPAddressBase):
            return str(obj)
        if isinstance(obj, set):
            return tuple(obj)
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        if isinstance(obj, date):
            return obj.strftime("%Y-%m-%d")
        if isinstance(obj, timedelta):
            return obj.total_seconds()
        if isinstance(obj, types.GeneratorType):
            return tuple(obj)
        if isinstance(obj, User):
            return dict(name=obj.name, given_name=obj.given_name,
                surname=obj.surname, mail=obj.mail)
        if isinstance(obj, ObjectId):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


def serialize(func):
    """
    Falcon response serialization
    """

    def wrapped(instance, req, resp, **kwargs):
        retval = func(instance, req, resp, **kwargs)
        if not resp.text and not resp.location:
            if not req.client_accepts("application/json"):
                logger.debug("Client did not accept application/json")
                raise falcon.HTTPUnsupportedMediaType(
                    "Client did not accept application/json")
            resp.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
            resp.set_header("Pragma", "no-cache")
            resp.set_header("Expires", "0")
            resp.text = json.dumps(retval, cls=MyEncoder)
    return wrapped

