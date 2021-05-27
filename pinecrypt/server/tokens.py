import string
import pytz
import pymongo
from datetime import datetime, timedelta
from pinecrypt.server import mailer, const, errors, db
from pinecrypt.server.common import random


class TokenManager():
    def consume(self, uuid):
        now = datetime.utcnow().replace(tzinfo=pytz.UTC)

        doc = db.tokens.find_one_and_update({
            "uuid": uuid,
            "created": {"$lte": now + const.CLOCK_SKEW_TOLERANCE},
            "expires": {"$gte": now - const.CLOCK_SKEW_TOLERANCE},
            "used": False
        }, {
            "$set": {
              "used": now
            }
        }, return_document=pymongo.ReturnDocument.AFTER)

        if not doc:
            raise errors.TokenDoesNotExist

        return doc["subject"], doc["mail"], doc["created"], doc["expires"], doc["profile"]

    def issue(self, issuer, subject, subject_mail=None):
        # Expand variables
        subject_username = subject.name
        if not subject_mail:
          subject_mail = subject.mail

        # Generate token
        token = "".join(random.choice(string.ascii_lowercase +
                                      string.ascii_uppercase + string.digits) for _ in range(32))
        token_created = datetime.utcnow().replace(tzinfo=pytz.UTC)
        token_expires = token_created + timedelta(seconds=const.TOKEN_LIFETIME)

        d = {}
        d["expires"] = token_expires
        d["uuid"] = token
        d["issuer"] = issuer.name if issuer else None
        d["subject"] = subject_username
        d["mail"] = subject_mail
        d["used"] = False
        d["profile"] = "Roadwarrior"

        db.tokens.update_one({
            "subject": subject_username,
            "mail": subject_mail,
            "used": False
        }, {
            "$set": d,
            "$setOnInsert": {
                "created": token_created,
            }
        }, upsert=True)

        # Token lifetime in local time, to select timezone: dpkg-reconfigure tzdata
        try:
            with open("/etc/timezone") as fh:
                token_timezone = fh.read().strip()
        except EnvironmentError:
            token_timezone = None

        authority_name = const.AUTHORITY_NAMESPACE
        protocols = ",".join(const.SERVICE_PROTOCOLS)
        url = const.TOKEN_URL % locals()

        context = globals()
        context.update(locals())

        mailer.send("token.md", to=subject_mail, **context)
        return token

    def list(self, expired=False, used=False):
        query = {}

        if not used:
            query["used"] = {"$eq": False}

        if not expired:
            query["expires"] = {"$gte": datetime.utcnow().replace(tzinfo=pytz.UTC)}

        def g():
            for token in db.tokens.find(query).sort("expires", -1):
                token.pop("_id")
                token["uuid"] = token["uuid"][0:8]
                yield token
        return tuple(g())

    def purge(self, all=False):
        query = {}
        if not all:
            query["expires"] = {"$lt": datetime.utcnow().replace(tzinfo=pytz.UTC)}
        return db.tokens.remove(query)
