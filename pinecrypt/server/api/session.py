import hashlib
import logging
from pinecrypt.server import authority, const, config
from pinecrypt.server.decorators import serialize, csrf_protection
from pinecrypt.server.user import User
from .utils.firewall import login_required, authorize_admin, register_session

logger = logging.getLogger(__name__)


class CertificateAuthorityResource(object):
    def on_get(self, req, resp):
        logger.info("Served CA certificate to %s", req.context["remote"]["addr"])
        resp.stream = open(const.AUTHORITY_CERTIFICATE_PATH, "rb")
        resp.append_header("Content-Type", "application/x-x509-ca-cert")
        resp.append_header("Content-Disposition", "attachment; filename=%s.crt" %
            const.HOSTNAME)


class SessionResource(object):

    def __init__(self, manager):
        self.token_manager = manager

    @csrf_protection
    @serialize
    @login_required
    @register_session
    @authorize_admin
    def on_get(self, req, resp):
        def serialize_requests(g):
            for csr, request, server in g():
                try:
                    submission_address = request["user"]["request_address"]
                except KeyError:
                    submission_address = None
                try:
                    submission_hostname = request["user"]["request_hostname"]
                except KeyError:
                    submission_hostname = None
                yield dict(
                    id=str(request["_id"]),
                    submitted=request["submitted"],
                    common_name=request["common_name"],
                    address=submission_address,
                    hostname=submission_hostname if submission_hostname != submission_address else None,
                    md5sum=hashlib.md5(request["request_buf"]).hexdigest(),
                    sha1sum=hashlib.sha1(request["request_buf"]).hexdigest(),
                    sha256sum=hashlib.sha256(request["request_buf"]).hexdigest(),
                    sha512sum=hashlib.sha512(request["request_buf"]).hexdigest()
                )

        def serialize_revoked(g):
            for cert_obj, cert in g(limit=5):
                yield dict(
                    id=str(cert_obj["_id"]),
                    serial="%x" % cert.serial_number,
                    common_name=cert_obj["common_name"],
                    # TODO: key type, key length, key exponent, key modulo
                    signed=cert_obj["signed"],
                    expired=cert_obj["expires"],
                    revoked=cert_obj["revoked"],
                    reason=cert_obj["revocation_reason"],
                    sha256sum=hashlib.sha256(cert_obj["cert_buf"]).hexdigest())

        def serialize_certificates(g):
            for cert_doc, cert in g():
                try:
                    tags = cert_doc["tags"]
                except KeyError:  # No tags
                    tags = None


                # TODO: Load attributes from databse
                attributes = {}

                try:
                    lease = dict(
                        inner_address=cert_doc["ip"],
                        outer_address=cert_doc["remote"]["addr"],
                        last_seen=cert_doc["last_seen"],
                    )
                except KeyError: # No such attribute(s)
                    lease = None

                try:
                    #signer_username = getxattr(path, "user.signature.username").decode("ascii")
                    signer_username = cert_doc["user"]["signature"]["username"]
                except KeyError:
                    signer_username = None

                # TODO: dedup
                serialized = dict(
                    id=str(cert_doc["_id"]),
                    disabled=cert_doc["disabled"],
                    serial="%x" % cert.serial_number,
                    organizational_unit=cert.subject.native.get("organizational_unit_name"),
                    common_name=cert_doc["common_name"],
                    # TODO: key type, key length, key exponent, key modulo
                    signed=cert_doc["signed"],
                    expires=cert_doc["expires"],
                    sha256sum=hashlib.sha256(cert_doc["cert_buf"]).hexdigest(),
                    signer=signer_username,
                    lease=lease,
                    tags=tags,
                    attributes=attributes or None,
                    responder_url=None
                )

                for e in cert["tbs_certificate"]["extensions"].native:
                    if e["extn_id"] == "key_usage":
                        serialized["key_usage"] = e["extn_value"]
                    elif e["extn_id"] == "extended_key_usage":
                        serialized["extended_key_usage"] = e["extn_value"]
                    elif e["extn_id"] == "basic_constraints":
                        serialized["basic_constraints"] = e["extn_value"]
                    elif e["extn_id"] == "crl_distribution_points":
                        for c in e["extn_value"]:
                            serialized["revoked_url"] = c["distribution_point"]
                            break
                        serialized["extended_key_usage"] = e["extn_value"]
                    elif e["extn_id"] == "authority_information_access":
                        for a in e["extn_value"]:
                            if a["access_method"] == "ocsp":
                                serialized["responder_url"] = a["access_location"]
                            else:
                                raise NotImplementedError("Don't know how to handle AIA access method %s" % a["access_method"])
                    elif e["extn_id"] == "authority_key_identifier":
                        pass
                    elif e["extn_id"] == "key_identifier":
                        pass
                    elif e["extn_id"] == "subject_alt_name":
                        serialized["subject_alt_name"] = e["extn_value"][0]
                    else:
                        raise NotImplementedError("Don't know how to handle extension %s" % e["extn_id"])
                yield serialized

        logger.info("Logged in authority administrator %s from %s with %s" % (
            req.context.get("user"), req.context["remote"]["addr"], req.context["remote"]["user_agent"]))
        return dict(
            user=dict(
                name=req.context.get("user").name,
                gn=req.context.get("user").given_name,
                sn=req.context.get("user").surname,
                mail=req.context.get("user").mail
            ),
            request_submission_allowed=const.REQUEST_SUBMISSION_ALLOWED,
            service=dict(
                protocols=const.SERVICE_PROTOCOLS,
            ),
            builder=dict(
                profiles=const.IMAGE_BUILDER_PROFILES or None
            ),
            tokens=self.token_manager.list() if self.token_manager else None,
            tagging=[dict(name=t[0], type=t[1], title=t[0]) for t in const.TAG_TYPES],

            mailer=dict(
               name=const.SMTP_SENDER_NAME,
               address=const.SMTP_SENDER_ADDR
            ) if const.SMTP_SENDER_ADDR else None,
            events="/api/event/",
            requests=serialize_requests(authority.list_requests),
            signed=serialize_certificates(authority.list_signed),
            revoked=serialize_revoked(authority.list_revoked),
            signature=dict(
                revocation_list_lifetime=const.REVOCATION_LIST_LIFETIME,
                profiles=config.options("SignatureProfile"),
            ),
            authorization=dict(
                admin_users=User.objects.filter_admins(),

                user_subnets=const.USER_SUBNETS or None,
                autosign_subnets=const.AUTOSIGN_SUBNETS or None,
                request_subnets=const.REQUEST_SUBNETS or None,
                machine_enrollment_subnets=const.MACHINE_ENROLLMENT_SUBNETS or None,
                admin_subnets=const.ADMIN_SUBNETS or None,
            ),
            features=dict(
                token=True,
                tagging=True,
                leases=True,
                logging=True)
        )
