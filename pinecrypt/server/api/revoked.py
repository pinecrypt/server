import falcon
import logging
from pinecrypt.server import authority, const, errors
from .utils.firewall import whitelist_subnets

logger = logging.getLogger(__name__)

class RevocationListResource(object):
    @whitelist_subnets(const.CRL_SUBNETS)
    def on_get(self, req, resp):
        # Primarily offer DER encoded CRL as per RFC5280
        # This is also what StrongSwan expects
        if req.client_accepts("application/x-pkcs7-crl"):
            resp.set_header("Content-Type", "application/x-pkcs7-crl")
            resp.append_header(
                "Content-Disposition",
                ("attachment; filename=%s.crl" % const.HOSTNAME))
            # Convert PEM to DER
            logger.debug("Serving revocation list (DER) to %s", req.context["remote"]["addr"])
            resp.text = authority.export_crl(pem=False)
        elif req.client_accepts("application/x-pem-file"):
            resp.set_header("Content-Type", "application/x-pem-file")
            resp.append_header(
                "Content-Disposition",
                ("attachment; filename=%s-crl.pem" % const.HOSTNAME))
            logger.debug("Serving revocation list (PEM) to %s", req.context["remote"]["addr"])
            resp.text = authority.export_crl()
        else:
            logger.debug("Client %s asked revocation list in unsupported format" % req.context["remote"]["addr"])
            raise falcon.HTTPUnsupportedMediaType(
                "Client did not accept application/x-pkcs7-crl or application/x-pem-file")


class RevokedCertificateDetailResource(object):
    def on_get(self, req, resp, serial_number):
        try:
            cert_doc, buf = authority.get_revoked(serial_number)
        except errors.CertificateDoesNotExist:
            logger.warning("Failed to serve non-existant revoked certificate with serial %s to %s",
                serial_number, req.context["remote"]["addr"])
            raise falcon.HTTPNotFound()
        resp.set_header("Content-Type", "application/x-pem-file")
        resp.set_header("Content-Disposition", ("attachment; filename=%s.pem" % cert_doc["serial_number"]))
        resp.text = buf
        logger.debug("Served revoked certificate with serial %s to %s",
            cert_doc["serial_number"], req.context["remote"]["addr"])
