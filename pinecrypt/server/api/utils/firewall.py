
import falcon
import logging
import binascii
import click
import gssapi
import ldap
import os
import random
import string
from asn1crypto import pem, x509
from base64 import b64decode
from falcon.util import http_date_to_dt
from datetime import datetime, timedelta
from pinecrypt.server.user import User
from pinecrypt.server import const, errors, db
from prometheus_client import Counter, Histogram

clock_skew = Histogram("pinecrypt_authority_clock_skew",
    "Histogram of client-server clock skew", ["method", "path", "passed"],
    buckets=(0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0))
whitelist_blocked_requests = Counter("pinecrypt_authority_whitelist_blocked_requests",
    "Requests blocked by whitelists", ["method", "path"])

logger = logging.getLogger(__name__)


def whitelist_subnets(subnets):
    """
    Validate source IP address of API call against subnet list
    """
    def wrapper(func):
        def wrapped(self, req, resp, *args, **kwargs):
            # Check for administration subnet whitelist
            for subnet in subnets:
                if req.context["remote"]["addr"] in subnet:
                    break
            else:
                logger.info("Rejected access to administrative call %s by %s from %s, source address not whitelisted",
                    req.env["PATH_INFO"],
                    req.context.get("user", "unauthenticated user"),
                    req.context["remote"]["addr"])
                whitelist_blocked_requests.labels(method=req.method, path=req.path).inc()
                raise falcon.HTTPForbidden("Forbidden", "Remote address %s not whitelisted" % req.context["remote"]["addr"])

            return func(self, req, resp, *args, **kwargs)
        return wrapped
    return wrapper


def whitelist_content_types(*content_types):
    def wrapper(func):
        def wrapped(self, req, resp, *args, **kwargs):
            for content_type in content_types:
                if req.get_header("Content-Type") == content_type:
                    return func(self, req, resp, *args, **kwargs)
            raise falcon.HTTPUnsupportedMediaType(
                "This API call accepts only %s content type" % ", ".join(content_types))
        return wrapped
    return wrapper


def whitelist_subject(func):
    def wrapped(self, req, resp, id, *args, **kwargs):
        from pinecrypt.server import authority
        try:
            cert, cert_doc, pem_buf = authority.get_signed(id)
        except errors.CertificateDoesNotExist:
            raise falcon.HTTPNotFound()
        else:
            buf = req.get_header("X-SSL-CERT")
            if buf:
                header, _, der_bytes = pem.unarmor(buf.replace("\t", "").encode("ascii"))
                origin_cert = x509.Certificate.load(der_bytes)
                if origin_cert.native == cert.native:
                    logger.debug("Subject authenticated using certificates")
                    return func(self, req, resp, id, *args, **kwargs)
            raise falcon.HTTPForbidden("Forbidden", "Remote address %s not whitelisted" % req.context["remote"]["addr"])
    return wrapped


def authenticate(optional=False):
    def wrapper(func):
        def wrapped(resource, req, resp, *args, **kwargs):
            kerberized = False

            if "kerberos" in const.AUTHENTICATION_BACKENDS:
                for subnet in const.KERBEROS_SUBNETS:
                    if req.context["remote"]["addr"] in subnet:
                        kerberized = True

            if not req.auth: # no credentials provided
                if optional: # optional allowed
                    req.context["user"] = None
                    return func(resource, req, resp, *args, **kwargs)

                if kerberized:
                    logger.debug("No Kerberos ticket offered while attempting to access %s from %s",
                        req.env["PATH_INFO"], req.context["remote"]["addr"])
                    raise falcon.HTTPUnauthorized("Unauthorized",
                        "No Kerberos ticket offered, are you sure you've logged in with domain user account?",
                        ["Negotiate"])
                else:
                    logger.debug("No credentials offered while attempting to access %s from %s",
                        req.env["PATH_INFO"], req.context["remote"]["addr"])
                    #falcon 3.0 login fix
                    raise falcon.HTTPUnauthorized(title="Unauthorized", description="Please authenticate", challenges=("Basic",))

            if kerberized:
                if not req.auth.startswith("Negotiate "):
                    raise falcon.HTTPUnauthorized("Unauthorized",
                        "Bad header, expected Negotiate", ["Negotiate"])

                os.environ["KRB5_KTNAME"] = const.KERBEROS_KEYTAB

                try:
                    server_creds = gssapi.creds.Credentials(
                        usage="accept",
                        name=gssapi.names.Name("HTTP/%s" % const.FQDN))
                except gssapi.raw.exceptions.BadNameError:
                    logger.error("Failed initialize HTTP service principal, possibly bad permissions for %s or /etc/krb5.conf" %
                        const.KERBEROS_KEYTAB)
                    raise

                context = gssapi.sec_contexts.SecurityContext(creds=server_creds)

                token = "".join(req.auth.split()[1:])

                try:
                    context.step(b64decode(token))
                except binascii.Error:
                    # base64 errors
                    raise falcon.HTTPBadRequest(title="Bad request", description="Malformed token")
                except gssapi.raw.exceptions.BadMechanismError:
                    raise falcon.HTTPBadRequest(title="Bad request", description="""
                        Unsupported authentication mechanism (NTLM?) was offered.
                        Please make sure you've logged into the computer with domain user account.
                        The web interface should not prompt for username or password.""")

                try:
                    username, realm = str(context.initiator_name).split("@")
                except AttributeError:
                    # TODO: Better exception handling
                    raise falcon.HTTPForbidden("Failed to determine username, are you trying to log in with correct domain account?")

                assert const.KERBEROS_REALM, "KERBEROS_REALM not configured"
                if realm != const.KERBEROS_REALM:
                    raise falcon.HTTPForbidden("Forbidden",
                        "Cross-realm trust not supported")

                if username.endswith("$") and optional:
                    # Extract machine hostname
                    # TODO: Assert LDAP group membership
                    req.context["machine"] = username[:-1].lower()
                    req.context["user"] = None
                else:
                    # Attempt to look up real user
                    req.context["user"] = User.objects.get(username)

                logger.debug("Succesfully authenticated user %s for %s from %s",
                    req.context["user"], req.env["PATH_INFO"], req.context["remote"]["addr"])
                return func(resource, req, resp, *args, **kwargs)

            else:
                if not req.auth.startswith("Basic "):
                    raise falcon.HTTPUnauthorized("Forbidden", "Bad header, expected Basic", ("Basic",))

                basic, token = req.auth.split(" ", 1)
                user, passwd = b64decode(token).decode("utf-8").split(":", 1)

            if "ldap" in const.AUTHENTICATION_BACKENDS:
                upn = ("%s@%s" % (user, const.KERBEROS_REALM)).lower()
                click.echo("Connecting to %s as %s" % (const.LDAP_AUTHENTICATION_URI, upn))
                conn = ldap.initialize(const.LDAP_AUTHENTICATION_URI, bytes_mode=False)
                conn.set_option(ldap.OPT_REFERRALS, 0)

                try:
                    conn.simple_bind_s(upn, passwd)
                except ldap.STRONG_AUTH_REQUIRED:
                    logger.critical("LDAP server demands encryption, use ldaps:// instead of ldap://")
                    raise
                except ldap.SERVER_DOWN:
                    logger.critical("Failed to connect LDAP server at %s, are you sure LDAP server's CA certificate has been copied to this machine?",
                        const.LDAP_AUTHENTICATION_URI)
                    raise
                except ldap.INVALID_CREDENTIALS:
                    logger.critical("LDAP bind authentication failed for user %s from  %s",
                        repr(upn), req.context["remote"]["addr"])
                    raise falcon.HTTPUnauthorized(
                        description="Please authenticate with %s domain account username" % const.KERBEROS_REALM,
                        challenges=["Basic"])

                req.context["ldap_conn"] = conn
            else:
                raise NotImplementedError("No suitable authentication method configured")

            try:
                req.context["user"] = User.objects.get(user)
            except User.DoesNotExist:
                raise falcon.HTTPUnauthorized("Unauthorized", "Invalid credentials", ("Basic",))

            retval = func(resource, req, resp, *args, **kwargs)
            if conn:
                conn.unbind_s()
            return retval
        return wrapped
    return wrapper


def login_required(func):
    return authenticate()(func)

def login_optional(func):
    return authenticate(optional=True)(func)

def authorize_admin(func):
    @whitelist_subnets(const.ADMIN_SUBNETS)
    def wrapped(resource, req, resp, *args, **kwargs):
        if req.context.get("user").is_admin():
            return func(resource, req, resp, *args, **kwargs)
        logger.info("User '%s' not authorized to access administrative API", req.context.get("user").name)
        raise falcon.HTTPForbidden("Forbidden", "User not authorized to perform administrative operations")
    return wrapped


def authorize_server(func):
    """
    Make sure the request originator has a certificate with server flags
    """
    from asn1crypto import pem, x509
    def wrapped(resource, req, resp, *args, **kwargs):
        buf = req.get_header("X-SSL-CERT")
        if not buf:
            logger.info("No TLS certificate presented to access administrative API call from %s" % req.context["remote"]["addr"])
            raise falcon.HTTPForbidden("Forbidden", "Machine not authorized to perform the operation")

        header, _, der_bytes = pem.unarmor(buf.replace("\t", "").encode("ascii"))
        cert = x509.Certificate.load(der_bytes)
        # TODO: validate serial
        for extension in cert["tbs_certificate"]["extensions"]:
            if extension["extn_id"].native == "extended_key_usage":
                if "server_auth" in extension["extn_value"].native:
                    req.context["machine"] = cert.subject.native["common_name"]
                    return func(resource, req, resp, *args, **kwargs)
        logger.info("TLS authenticated machine '%s' not authorized to access administrative API", cert.subject.native["common_name"])
        raise falcon.HTTPForbidden("Forbidden", "Machine not authorized to perform the operation")
    return wrapped


def validate_clock_skew(func):
    def wrapped(resource, req, resp, *args, **kwargs):
        try:
            skew = abs((http_date_to_dt(req.headers["DATE"]) - datetime.utcnow()))
        except KeyError:
            raise falcon.HTTPBadRequest(title="Bad request", description="No date information specified in header")

        passed = skew < const.CLOCK_SKEW_TOLERANCE
        clock_skew.labels(method=req.method, path=req.path, passed=int(passed)).observe(skew.total_seconds())
        if passed:
            return func(resource, req, resp, *args, **kwargs)
        else:
            raise falcon.HTTPBadRequest(title="Bad request", description="Clock skew too large")
    return wrapped


def cookie_login(func):
    def wrapped(resource, req, resp, *args, **kwargs):
        now = datetime.utcnow()
        value = req.get_cookie_values(const.SESSION_COOKIE)
        db.sessions.update_one({
            "secret": value,
            "started": {
                "$lte": now
            },
            "expires": {
                "$gte": now
            },
        }, {
            "$set": {
                "last_seen": now,
           }
        })
        return func(resource, req, resp, *args, **kwargs)
    return wrapped


def generate_password(length):
    letters = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return "".join(random.choice(letters) for i in range(length))


def register_session(func):
    def wrapped(resource, req, resp, *args, **kwargs):
        now = datetime.utcnow()
        value = generate_password(50)
        db.sessions.insert({
            "user": req.context["user"].name,
            "secret": value,
            "last_seen": now,
            "started": now,
            "expires": now + timedelta(seconds=const.SESSION_AGE),
            "remote": str(req.context["remote"]),
        })
        resp.set_cookie(const.SESSION_COOKIE, value,
            max_age=const.SESSION_AGE)
        return func(resource, req, resp, *args, **kwargs)
    return wrapped
