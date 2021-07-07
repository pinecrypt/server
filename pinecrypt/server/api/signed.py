
import falcon
import logging
import json
import hashlib
from pinecrypt.server import authority, errors, db
from pinecrypt.server.decorators import csrf_protection
from .utils.firewall import login_required, authorize_admin

logger = logging.getLogger(__name__)

class SignedCertificateDetailResource(object):
    def on_get_cn(self, req, resp, cn):
        try:
            id = authority.get_common_name_id(cn)
        except ValueError:
            raise falcon.HTTPNotFound("Unknown Common name",
            "Object not found with common name %s" % cn)

        id = authority.get_common_name_id(cn)
        url = req.forwarded_uri.replace(cn,"id/%s" % id)

        resp.status = falcon.HTTP_307
        resp.location = url


    def on_get(self, req, resp, id):
        preferred_type = req.client_prefers(("application/json", "application/x-pem-file"))
        try:
            cert, cert_doc, pem_buf = authority.get_signed(mongo_id=id)
        except errors.CertificateDoesNotExist:
            logger.warning("Failed to serve non-existant certificate %s to %s",
                id, req.context["remote"]["addr"])
            raise falcon.HTTPNotFound()

        cn = cert_doc["common_name"]

        if preferred_type == "application/x-pem-file":
            resp.set_header("Content-Type", "application/x-pem-file")
            resp.set_header("Content-Disposition", ("attachment; filename=%s.pem" % cn))
            resp.text = pem_buf
            logger.debug("Served certificate %s to %s as application/x-pem-file",
                cn, req.context["remote"]["addr"])
        elif preferred_type == "application/json":
            resp.set_header("Content-Type", "application/json")
            resp.set_header("Content-Disposition", ("attachment; filename=%s.json" % cn))
            try:
                signer_username = cert_doc["user"]["signature"]["username"]
            except KeyError:
                signer_username = None

            resp.text = json.dumps(dict(
                common_name=cn,
                id=str(cert_doc["_id"]),
                signer=signer_username,
                serial="%040x" % cert.serial_number,
                organizational_unit=cert.subject.native.get("organizational_unit_name"),
                signed=cert["tbs_certificate"]["validity"]["not_before"].native.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                expires=cert["tbs_certificate"]["validity"]["not_after"].native.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                sha256sum=hashlib.sha256(pem_buf).hexdigest(),
                attributes=None,
                lease=None,
                extensions=dict([
                    (e["extn_id"].native, e["extn_value"].native)
                    for e in cert["tbs_certificate"]["extensions"]
                    if e["extn_id"].native in ("extended_key_usage",)])

            ))
            logger.debug("Served certificate %s to %s as application/json",
                cn, req.context["remote"]["addr"])
        else:
            logger.debug("Client did not accept application/json or application/x-pem-file")
            raise falcon.HTTPUnsupportedMediaType(
                "Client did not accept application/json or application/x-pem-file")

    @csrf_protection
    @login_required
    @authorize_admin
    def on_delete(self, req, resp, id):
        authority.revoke(id,
            reason=req.get_param("reason", default="key_compromise"),
            user=req.context.get("user")
        )

