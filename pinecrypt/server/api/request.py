import click
import falcon
import logging
import json
import hashlib
from asn1crypto import pem
from asn1crypto.csr import CertificationRequest
from pinecrypt.server import const, errors, authority
from pinecrypt.server.decorators import csrf_protection, MyEncoder
from pinecrypt.server.user import DirectoryConnection
from oscrypto import asymmetric
from .utils.firewall import whitelist_subnets, whitelist_content_types, \
    login_required, login_optional, authorize_admin, validate_clock_skew

logger = logging.getLogger(__name__)

"""
openssl genrsa -out test.key 1024
openssl req -new -sha256 -key test.key -out test.csr -subj "/CN=test"
curl -f -L -H "Content-type: application/pkcs10" --data-binary @test.csr \
  http://ca.example.lan/api/request/?wait=yes
"""

class RequestListResource(object):
    @login_optional
    @whitelist_subnets(const.REQUEST_SUBNETS)
    @whitelist_content_types("application/pkcs10")
    @validate_clock_skew
    def on_post(self, req, resp):
        """
        Validate and parse certificate signing request, the RESTful way
        Endpoint urls
        /request/?wait=yes
        /request/autosign=1
        /request
        """
        reasons = []
        body = req.stream.read(req.content_length)

        try:
            header, _, der_bytes = pem.unarmor(body)
            csr = CertificationRequest.load(der_bytes)
        except ValueError:
            logger.info("Malformed certificate signing request submission from %s blocked", req.context["remote"]["addr"])
            raise falcon.HTTPBadRequest(
                "Bad request",
                "Malformed certificate signing request")
        else:
            req_public_key = asymmetric.load_public_key(csr["certification_request_info"]["subject_pk_info"])
            if authority.public_key.algorithm != req_public_key.algorithm:
                logger.info("Attempt to submit %s based request from %s blocked, only %s allowed" % (
                    req_public_key.algorithm.upper(),
                    req.context["remote"]["addr"],
                    authority.public_key.algorithm.upper()))
                raise falcon.HTTPBadRequest(
                    "Bad request",
                    "Unsupported key algorithm %s, expected %s" % (req_public_key.algorithm, authority.public_key.algorithm))

        try:
            common_name = csr["certification_request_info"]["subject"].native["common_name"]
        except KeyError:
            logger.info("Malformed certificate signing request without common name submitted from %s" % req.context["remote"]["addr"])
            raise falcon.HTTPBadRequest(title="Bad request",description="Common name missing from certificate signing request")

        """
        Determine whether autosign is allowed to overwrite already issued
        certificates automatically
        """

        overwrite_allowed = False
        for subnet in const.OVERWRITE_SUBNETS:
            if req.context["remote"]["addr"] in subnet:
                overwrite_allowed = True
                break


        """
        Handle domain computer automatic enrollment
        """
        machine = req.context.get("machine")
        if machine:
            reasons.append("machine enrollment not allowed from %s" % req.context["remote"]["addr"])
            for subnet in const.MACHINE_ENROLLMENT_SUBNETS:
                if req.context["remote"]["addr"] in subnet:
                    if common_name != machine:
                        raise falcon.HTTPBadRequest(
                            "Bad request",
                            "Common name %s differs from Kerberos credential %s!" % (common_name, machine))

                    hit = False
                    with DirectoryConnection() as conn:
                        ft = const.LDAP_COMPUTER_FILTER % ("%s$" % machine)
                        attribs = "cn",
                        r = conn.search_s(const.LDAP_BASE, 2, ft, attribs)
                        for dn, entry in r:
                            if not dn:
                                continue
                            else:
                                hit = True
                                break

                    if hit:
                        # Automatic enroll with Kerberos machine cerdentials
                        resp.set_header("Content-Type", "application/x-pem-file")
                        try:
                            mongo_doc = authority.store_request(body,address=str(req.context["remote"]["addr"]))
                            cert, resp.text = authority.sign(mongo_id=str(mongo_doc["_id"]),
                                profile="Roadwarrior", overwrite=overwrite_allowed) # TODO: handle thrown exception
                            logger.info("Automatically enrolled Kerberos authenticated machine %s (%s) from %s",
                                machine, dn, req.context["remote"]["addr"])
                            return
                        except errors.RequestExists:
                            reasons.append("same request already uploaded exists")
                            # We should still redirect client to long poll URL below
                        except errors.DuplicateCommonNameError:
                            logger.warning("rejected signing request with overlapping common name from %s",
                                req.context["remote"]["addr"])
                            raise falcon.HTTPConflict(
                                "CSR with such CN already exists",
                                 "Will not overwrite existing certificate signing request, explicitly delete CSR and try again")

                    else:
                        logger.error("Kerberos authenticated machine %s didn't fit the 'ldap computer filter' criteria %s" % (machine, ft))


        """
        Process automatic signing if the IP address is whitelisted,
        autosigning was requested and certificate can be automatically signed
        """

        if req.get_param_as_bool("autosign"):
            for subnet in const.AUTOSIGN_SUBNETS:
                if req.context["remote"]["addr"] in subnet:
                    try:
                        resp.set_header("Content-Type", "application/x-pem-file")
                        mongo_doc = authority.store_request(body,address=str(req.context["remote"]["addr"]))
                        _, resp.text = authority.sign(mongo_id=str(mongo_doc["_id"]),
                            overwrite=overwrite_allowed, profile="Roadwarrior")

                        logger.info("Signed %s as %s is whitelisted for autosign", common_name, req.context["remote"]["addr"])
                        return
                    except EnvironmentError:
                        logger.info("Autosign for %s from %s failed, signed certificate already exists",
                            common_name, req.context["remote"]["addr"])
                        reasons.append("autosign failed, signed certificate already exists")
                    break
            else:
                reasons.append("IP address not whitelisted for autosign")
        else:
            reasons.append("autosign not requested")

        # Attempt to save the request otherwise
        try:
            mongo_doc = authority.store_request(body,
                address=str(req.context["remote"]["addr"]))
        except errors.RequestExists:
            reasons.append("same request already uploaded exists")
            # We should still redirect client to long poll URL below
        except errors.DuplicateCommonNameError:
            logger.warning("rejected signing request with overlapping common name from %s",
                req.context["remote"]["addr"])
            raise falcon.HTTPConflict(
                "CSR with such CN already exists",
                "Will not overwrite existing certificate signing request, explicitly delete CSR and try again")

        # Wait the certificate to be signed if waiting is requested
        logger.info("Signing request %s from %s put on hold,  %s", common_name, req.context["remote"]["addr"], ", ".join(reasons))

        if req.get_param("wait"):
            header, _, der_bytes = pem.unarmor(body)
            url = "https://%s/api/event/request-signed/%s" % (const.AUTHORITY_NAMESPACE, str(mongo_doc["_id"]))
            click.echo("Redirecting to: %s"  % url)
            resp.status = falcon.HTTP_SEE_OTHER
            resp.set_header("Location", url)
        else:
            # Request was accepted, but not processed
            resp.status = falcon.HTTP_202
            resp.text = ". ".join(reasons)

            if req.client_accepts("application/json"):
                resp.text = json.dumps({"title":"Accepted", "description":resp.text, "id":str(mongo_doc["_id"])},
                    cls=MyEncoder)


class RequestDetailResource(object):
    def on_get(self, req, resp, id):
        """
        Fetch certificate signing request as PEM
        """

        try:
            csr, csr_doc, buf = authority.get_request(id)
        except errors.RequestDoesNotExist:
            logger.warning("Failed to serve non-existant request %s to %s",
                id, req.context["remote"]["addr"])
            raise falcon.HTTPNotFound()

        resp.set_header("Content-Type", "application/pkcs10")
        logger.debug("Signing request %s was downloaded by %s",
            csr_doc["common_name"], req.context["remote"]["addr"])

        preferred_type = req.client_prefers(("application/json", "application/x-pem-file"))

        if preferred_type == "application/x-pem-file":
            # For certidude client, curl scripts etc
            resp.set_header("Content-Type", "application/x-pem-file")
            resp.set_header("Content-Disposition", ("attachment; filename=%s.pem" % csr_doc["common_name"]))
            resp.text = buf
        elif preferred_type == "application/json":
            # For web interface events
            resp.set_header("Content-Type", "application/json")
            resp.set_header("Content-Disposition", ("attachment; filename=%s.json" % csr_doc["common_name"]))
            resp.text = json.dumps(dict(
                submitted=csr_doc["submitted"],
                common_name=csr_doc["common_name"],
                id=str(csr_doc["_id"]),
                address=csr_doc["user"]["request_addresss"],
                md5sum=hashlib.md5(buf).hexdigest(),
                sha1sum=hashlib.sha1(buf).hexdigest(),
                sha256sum=hashlib.sha256(buf).hexdigest(),
                sha512sum=hashlib.sha512(buf).hexdigest()), cls=MyEncoder)
        else:
            raise falcon.HTTPUnsupportedMediaType(
                "Client did not accept application/json or application/x-pem-file")


    @csrf_protection
    @login_required
    @authorize_admin
    def on_post(self, req, resp, id):
        """
        Sign a certificate signing request
        """
        try:
            cert, buf = authority.sign(mongo_id=id,
                profile=req.get_param("profile", default="Roadwarrior"),
                overwrite=True,
                signer=req.context.get("user").name)  #if user is cached in browser then there is no name
            # Mailing and long poll publishing implemented in the function above
        except EnvironmentError: # no such CSR
            raise falcon.HTTPNotFound(title="Not found",description="CSR not found with id %s" %  id)

        resp.text = "Certificate successfully signed"
        resp.status = falcon.HTTP_201
        resp.location = req.forwarded_uri.replace("request","sign")

        cn = cert.subject.native.get("common_name")
        logger.info("Signing request %s signed by %s from %s", cn,
            req.context.get("user"), req.context["remote"]["addr"])


    @csrf_protection
    @login_required
    @authorize_admin
    def on_delete(self, req, resp, id):
        try:
            authority.delete_request(id, user=req.context.get("user"))
            # Logging implemented in the function above
        except errors.RequestDoesNotExist as e:
            resp.text = "No certificate signing request for with id %s not found" % id
            logger.warning("User %s failed to delete signing request %s from %s, reason: %s",
                req.context["user"], id, req.context["remote"]["addr"], e)
            raise falcon.HTTPNotFound()
        except ValueError as e:
            resp.text = "No ID specified %s" % id
            logger.warning("User %s wanted to delete invalid signing request %s from %s, reason: %s",
                req.context["user"], id, req.context["remote"]["addr"], e)
            raise falcon.HTTPBadRequest()
