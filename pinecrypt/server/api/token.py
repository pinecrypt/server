import falcon
import logging
import re
from asn1crypto import pem
from asn1crypto.csr import CertificationRequest
from pinecrypt.server import const, errors, authority
from pinecrypt.server.decorators import serialize
from pinecrypt.server.user import User
from .utils.firewall import login_required, authorize_admin
from pinecrypt.server.mongolog import LogHandler

logger = LogHandler()

class TokenResource(object):
    def __init__(self, manager):
        self.manager = manager

    def on_put(self, req, resp):
        try:
            username, mail, created, expires, profile = self.manager.consume(req.get_param("token", required=True))
        except errors.TokenDoesNotExist:
            raise falcon.HTTPForbidden("Forbidden", "No such token or token expired")
        body = req.stream.read(req.content_length)
        header, _, der_bytes = pem.unarmor(body)
        csr = CertificationRequest.load(der_bytes)

        try:
            common_name = csr["certification_request_info"]["subject"].native["common_name"]
        except KeyError:
            logger.info("Malformed certificate signing request without common name token submitted from %s" % req.context["remote"]["addr"])
            raise falcon.HTTPBadRequest(title="Bad request",description="Common name missing from certificate signing request token")

        if not re.match(const.RE_COMMON_NAME, common_name):
            raise falcon.HTTPBadRequest("Bad request", "Invalid common name %s" % common_name)

        try:
            mongo_doc = authority.store_request(body, overwrite=const.TOKEN_OVERWRITE_PERMITTED,
               namespace="%s.%s" % (username, const.USER_NAMESPACE), address=str(req.context["remote"]["addr"]))
            _, resp.text = authority.sign(mongo_id=str(mongo_doc["_id"]), profile=profile,
                overwrite=const.TOKEN_OVERWRITE_PERMITTED,
                namespace="%s.%s" % (username, const.USER_NAMESPACE))
            resp.set_header("Content-Type", "application/x-pem-file")
            logger.info("Autosigned %s as proven by token ownership", common_name)
        except errors.DuplicateCommonNameError:
            logger.info("Another request with same common name already exists", common_name)
            raise falcon.HTTPConflict(
                title="CSR with such common name (CN) already exists",
                description="Will not overwrite existing certificate signing request, explicitly delete existing one and try again")
        except FileExistsError:
            logger.info("Won't autosign duplicate %s", common_name)
            raise falcon.HTTPConflict(
                "Certificate with such common name (CN) already exists",
                "Will not overwrite existing certificate signing request, explicitly delete existing one and try again")


    @serialize
    @login_required
    @authorize_admin
    def on_post(self, req, resp):
        username = req.get_param("username", required=True)
        if not re.match(const.RE_USERNAME, username):
            raise falcon.HTTPBadRequest("Bad request", "Invalid username")
        # TODO: validate e-mail
        self.manager.issue(
            issuer=req.context.get("user"),
            subject=User.objects.get(username),
            subject_mail=req.get_param("mail"))
