# coding: utf-8

try:
    import coverage
except ImportError:
    pass
else:
    if coverage.process_startup():
        print("Enabled code coverage tracking")

import falcon
import click
import os
import pymongo
import signal
import sys
import pytz
import ipaddress
from asn1crypto import pem, x509
from certbuilder import CertificateBuilder, pem_armor_certificate
from datetime import datetime, timedelta
from jinja2 import Environment, PackageLoader
from oscrypto import asymmetric
from math import log, ceil
from pinecrypt.server import const, mongolog, mailer, db
from pinecrypt.server.middleware import NormalizeMiddleware, PrometheusEndpoint
from pinecrypt.server.common import cn_to_dn, generate_serial
from pinecrypt.server.mongolog import LogHandler
from time import sleep
from wsgiref.simple_server import make_server

logger = LogHandler()


def graceful_exit(signal_number, stack_frame):
    print("Received signal %d, exiting now" % signal_number)
    sys.exit(0)


def fqdn_required(func):
    def wrapped(**args):
        common_name = args.get("common_name")
        if "." in common_name:
            logger.info("Using fully qualified hostname %s" % common_name)
        else:
            raise ValueError("Fully qualified hostname not specified as common name, make sure hostname -f works")
        return func(**args)
    return wrapped


def waitfile(path):
    def wrapper(func):
        def wrapped(**args):
            while not os.path.exists(path):
                sleep(1)
            return func(**args)
        return wrapped
    return wrapper


@click.command("log", help="Dump logs")
def pinecone_log():
    for record in mongolog.collection.find():
        print(record["created"].strftime("%Y-%m-%d %H:%M:%S"),
            record["severity"],
            record["message"])


@click.command("users", help="List users")
def pinecone_users():
    from pinecrypt.server.user import User
    admins = set(User.objects.filter_admins())
    for user in User.objects.all():
        click.echo("%s;%s;%s;%s;%s" % (
            "admin" if user in admins else "user",
            user.name, user.given_name, user.surname, user.mail))


@click.command("list", help="List certificates")
@click.option("--verbose", "-v", default=False, is_flag=True, help="Verbose output")
@click.option("--show-key-type", "-k", default=False, is_flag=True, help="Show key type and length")
@click.option("--show-path", "-p", default=False, is_flag=True, help="Show filesystem paths")
@click.option("--show-extensions", "-e", default=False, is_flag=True, help="Show X.509 Certificate Extensions")
@click.option("--hide-requests", "-h", default=False, is_flag=True, help="Hide signing requests")
@click.option("--show-signed", "-s", default=False, is_flag=True, help="Show signed certificates")
@click.option("--show-revoked", "-r", default=False, is_flag=True, help="Show revoked certificates")
def pinecone_list(verbose, show_key_type, show_extensions, show_path, show_signed, show_revoked, hide_requests):
    from pinecrypt.server import db
    for o in db.certificates.find():
        print(o["common_name"], o["status"], o.get("instance"), o.get("remote"), o.get("last_seen"))


@click.command("list", help="List sessions")
def pinecone_session_list():
    from pinecrypt.server import db
    for o in db.sessions.find():
        print(o["user"], o["started"], o.get("expires"), o.get("last_seen"))


@click.command("sign", help="Sign certificate")
@click.argument("common_name")
@click.option("--profile", "-p", default="Roadwarrior", help="Profile")
@click.option("--overwrite", "-o", default=False, is_flag=True, help="Revoke valid certificate with same CN")
def pinecone_sign(common_name, overwrite, profile):
    from pinecrypt.server import authority
    authority.sign(common_name, overwrite=overwrite, profile=profile)


@click.command("disable", help="Disable client node or gateway replica temporarily")
@click.argument("common_name")
def pinecone_disable(common_name):
    from pinecrypt.server import db
    result = db.certificates.update_one({
        "common_name": common_name
    }, {
        "$set": {
            "disabled": datetime.utcnow()
        }
    })
    if result.matched_count != 1:
        raise click.ClickException("Invalid common name")


@click.command("enable", help="Enable client node or gateway replica")
@click.argument("common_name")
def pinecone_enable(common_name):
    from pinecrypt.server import db
    result = db.certificates.update_one({
        "common_name": common_name
    }, {
        "$set": {
            "disabled": False
        }
    })
    if result.matched_count != 1:
        raise click.ClickException("Invalid common name")


@click.command("revoke", help="Revoke certificate")
@click.option("--reason", "-r", default="key_compromise",
    help="Revocation reason, one of: key_compromise affiliation_changed superseded cessation_of_operation privilege_withdrawn")
@click.argument("common_name")
def pinecone_revoke(common_name, reason):
    from pinecrypt.server import authority
    authority.revoke(common_name, reason)


@click.command("kinit", help="Initialize Kerberos credential cache for LDAP")
def pinecone_housekeeping_kinit():

    # Update LDAP service ticket if Certidude is joined to domain
    if not os.path.exists("/etc/krb5.keytab"):
        raise click.ClickException("No Kerberos keytab configured")

    _, kdc = const.LDAP_ACCOUNTS_URI.rsplit("/", 1)
    cmd = "KRB5CCNAME=%s.part kinit -k %s$ -S ldap/%s@%s -t /etc/krb5.keytab" % (
        const.LDAP_GSSAPI_CRED_CACHE,
        const.HOSTNAME.upper(), kdc, const.KERBEROS_REALM
    )
    click.echo("Executing: %s" % cmd)
    if os.system(cmd):
        raise click.ClickException("Failed to initialize Kerberos credential cache!")
    os.system("chown certidude:certidude %s.part" % const.LDAP_GSSAPI_CRED_CACHE)
    os.rename("%s.part" % const.LDAP_GSSAPI_CRED_CACHE, const.LDAP_GSSAPI_CRED_CACHE)


@click.command("daily", help="Send notifications about expired certificates")
def pinecone_housekeeping_expiration():
    from pinecrypt.server import authority
    threshold_move = datetime.utcnow().replace(tzinfo=pytz.UTC) - const.CLOCK_SKEW_TOLERANCE
    threshold_notify = datetime.utcnow().replace(tzinfo=pytz.UTC) + timedelta(hours=48)
    expired = []
    about_to_expire = []

    # Collect certificates which have expired and are about to expire
    for common_name, path, buf, cert, signed, expires in authority.list_signed():
        if expires.replace(tzinfo=pytz.UTC) < threshold_move:
            expired.append((common_name, path, cert))
        elif expires.replace(tzinfo=pytz.UTC) < threshold_notify:
            about_to_expire.append((common_name, path, cert))

    # Send e-mail notifications
    if expired or about_to_expire:
        mailer.send("expiration-notification.md", **locals())

    # Move valid, but now expired certificates
    for common_name, path, cert in expired:
        expired_path = os.path.join(const.EXPIRED_DIR, "%040x.pem" % cert.serial_number)
        click.echo("Moving %s to %s" % (path, expired_path))
        os.rename(path, expired_path)
        os.remove(os.path.join(const.SIGNED_BY_SERIAL_DIR, "%040x.pem" % cert.serial_number))

    # Move revoked certificate which have expired
    for common_name, path, buf, cert, signed, expires, revoked, reason in authority.list_revoked():
        if expires.replace(tzinfo=pytz.UTC) < threshold_move:
            expired_path = os.path.join(const.EXPIRED_DIR, "%040x.pem" % cert.serial_number)
            click.echo("Moving %s to %s" % (path, expired_path))
            os.rename(path, expired_path)

    # TODO: Send separate e-mails to subjects


@click.command("events")
def pinecone_serve_events():
    from pinecrypt.server.api.events import app
    app.run(port=8001, debug=const.DEBUG)


@click.command("builder")
def pinecone_serve_builder():
    from pinecrypt.server.api.builder import app
    app.run(port=7001, debug=const.DEBUG)


@click.command("provision", help="Provision keys")
def pinecone_provision():

    # Expand variables
    distinguished_name = cn_to_dn(const.AUTHORITY_COMMON_NAME)

    # Generate and sign CA key
    if os.path.exists(const.AUTHORITY_CERTIFICATE_PATH) and os.path.exists(const.AUTHORITY_PRIVATE_KEY_PATH):
        click.echo("Authority keypair already exists")
    else:
        if const.AUTHORITY_KEYTYPE == "ec":
            click.echo("Generating %s EC key for CA ..." % const.CURVE_NAME)
            public_key, private_key = asymmetric.generate_pair("ec", curve=const.CURVE_NAME)
        else:
            click.echo("Generating %d-bit RSA key for CA ..." % const.KEY_SIZE)
            public_key, private_key = asymmetric.generate_pair("rsa", bit_size=const.KEY_SIZE)

        # https://technet.microsoft.com/en-us/library/aa998840(v=exchg.141).aspx
        builder = CertificateBuilder(distinguished_name, public_key)
        builder.hash_algo = const.CERTIFICATE_HASH_ALGORITHM
        builder.self_signed = True
        builder.ca = True
        builder.serial_number = generate_serial()

        now = datetime.utcnow().replace(tzinfo=pytz.UTC)
        builder.begin_date = now - const.CLOCK_SKEW_TOLERANCE
        builder.end_date = now + timedelta(days=const.AUTHORITY_LIFETIME_DAYS)

        certificate = builder.build(private_key)

        header, _, der_bytes = pem.unarmor(pem_armor_certificate(certificate))

        obj = {
            "name": "root",
            "key": asymmetric.dump_private_key(private_key, None),
            "cert": pem_armor_certificate(certificate)
        }

        if const.SECRET_STORAGE == "db":
            db.secrets.create_index("name", unique=True)
            try:
                db.secrets.insert_one(obj)
            except pymongo.errors.DuplicateKeyError:
                obj = db.secrets.find_one({"name": "root"})

        # Set permission bits to 600
        os.umask(0o177)
        with open(const.AUTHORITY_PRIVATE_KEY_PATH + ".part", "wb") as f:
            f.write(obj["key"])

        # Set permission bits to 644
        os.umask(0o133)
        with open(const.AUTHORITY_CERTIFICATE_PATH + ".part", "wb") as f:
            f.write(obj["cert"])

        os.rename(const.AUTHORITY_PRIVATE_KEY_PATH + ".part",
            const.AUTHORITY_PRIVATE_KEY_PATH)
        os.rename(const.AUTHORITY_CERTIFICATE_PATH + ".part",
            const.AUTHORITY_CERTIFICATE_PATH)

        click.echo("Authority certificate written to: %s" % const.AUTHORITY_CERTIFICATE_PATH)

    click.echo("Attempting self-enroll")
    from pinecrypt.server import authority
    authority.self_enroll(skip_notify=True)

    # Insert/update DNS records for the replica itself
    click.echo("Advertising via DNS: %s -> %s" % (const.FQDN, repr(const.ADVERTISE_ADDRESS)))
    db.certificates.update_one({
        "common_name": const.FQDN,
        "status": "signed",
    }, {
        "$set": {
            "dns": {
                "fqdn": const.FQDN,
                "san": const.AUTHORITY_NAMESPACE,
            },
            "ip": list(const.ADVERTISE_ADDRESS),
        }
    })

    # Separate pushed subnets by address family
    push4 = set()
    push6 = set()
    for subnet in const.PUSH_SUBNETS:
        if subnet.version == 4:
            push4.add(subnet)
        elif subnet.version == 6:
            if not const.CLIENT_SUBNET6:
                raise ValueError("Can't push IPv6 routes if no IPv6 client subnet is configured")
            push6.add(subnet)
        else:
            raise NotImplementedError()

    # Generate OpenVPN configurations
    click.echo("Generating OpenVPN configuration files...")
    from pinecrypt.server import config
    ctx = {
        "authority_namespace": const.AUTHORITY_NAMESPACE,
        "push4": push4,
        "push6": push6,
        "openvpn_tls_version_min": config.get("Globals", "OPENVPN_TLS_VERSION_MIN")["value"],
        "openvpn_tls_ciphersuites": config.get("Globals", "OPENVPN_TLS_CIPHERSUITES")["value"],
        "openvpn_tls_cipher": config.get("Globals", "OPENVPN_TLS_CIPHER")["value"],
        "openvpn_cipher": config.get("Globals", "OPENVPN_CIPHER")["value"],
        "openvpn_auth": config.get("Globals", "OPENVPN_AUTH")["value"],
        "strongswan_dhgroup": config.get("Globals", "STRONGSWAN_DHGROUP")["value"],
        "strongswan_ike": config.get("Globals", "STRONGSWAN_IKE")["value"],
        "strongswan_esp": config.get("Globals", "STRONGSWAN_ESP")["value"],
    }

    env = Environment(loader=PackageLoader("pinecrypt.server", "templates"))
    os.umask(0o133)

    d = ceil(log(const.CLIENT_SUBNET_SLOT_COUNT) / log(2))
    for slot, proto in enumerate(["udp", "tcp"]):
        ctx["proto"] = proto
        ctx["slot4"] = list(const.CLIENT_SUBNET4.subnets(d))[slot]
        ctx["slot6"] = list(const.CLIENT_SUBNET6.subnets(d))[slot] if const.CLIENT_SUBNET6 else None
        with open("/server-secrets/openvpn-%s.conf" % proto, "w") as fh:
            fh.write(env.get_template("openvpn.conf").render(ctx))

    # Merged variants for StrongSwan
    ctx["push"] = ctx["push4"].union(ctx["push6"])

    # Generate StrongSwan config
    click.echo("Generating StrongSwan configuration files...")
    slot += 1
    ctx["slot4"] = list(const.CLIENT_SUBNET4.subnets(d))[slot]
    ctx["slot6"] = list(const.CLIENT_SUBNET6.subnets(d))[slot] if const.CLIENT_SUBNET6 else []
    with open("/server-secrets/ipsec.conf", "w") as fh:
        fh.write(env.get_template("ipsec.conf").render(ctx))

    # Why do you do this StrongSwan?! You will parse the cert anyway,
    # why do I need to distinguish ECDSA vs RSA in config?!
    with open(const.SELF_CERT_PATH, "rb") as fh:
        certificate_buf = fh.read()
        header, _, certificate_der_bytes = pem.unarmor(certificate_buf)
        certificate = x509.Certificate.load(certificate_der_bytes)
        public_key = asymmetric.load_public_key(certificate["tbs_certificate"]["subject_public_key_info"])
    with open("/server-secrets/ipsec.secrets", "w") as fh:
        fh.write(": %s %s\n" % (
            "ECDSA" if public_key.algorithm == "ec" else "RSA",
            const.SELF_KEY_PATH
        ))

    # TODO: use this task to send notification emails maybe?
    click.echo("Finished starting up")
    sleep(999999999)


@click.command("backend", help="Serve main backend")
@waitfile(const.SELF_CERT_PATH)
def pinecone_serve_backend():
    from pinecrypt.server.tokens import TokenManager
    from pinecrypt.server.api.signed import SignedCertificateDetailResource
    from pinecrypt.server.api.request import RequestListResource, RequestDetailResource
    from pinecrypt.server.api.script import ScriptResource
    from pinecrypt.server.api.tag import TagResource, TagDetailResource
    from pinecrypt.server.api.bootstrap import BootstrapResource
    from pinecrypt.server.api.token import TokenResource
    from pinecrypt.server.api.session import SessionResource, CertificateAuthorityResource
    from pinecrypt.server.api.revoked import RevokedCertificateDetailResource
    from pinecrypt.server.api.log import LogResource
    from pinecrypt.server.api.revoked import RevocationListResource
    from pinecrypt.server.api.access import DisableEnableAccessToInstance

    app = falcon.App(middleware=NormalizeMiddleware())
    app.req_options.strip_url_path_trailing_slash = True
    app.req_options.auto_parse_form_urlencoded = True
    app.add_route("/metrics", PrometheusEndpoint())

    # CN to Id api call
    app.add_route("/api/signed/{cn}", SignedCertificateDetailResource(), suffix="cn")
    app.add_route("/api/signed/{cn}/tag", TagResource(), suffix="cn")

    # Certificate authority API calls
    app.add_route("/api/certificate", CertificateAuthorityResource())
    app.add_route("/api/signed/id/{id}", SignedCertificateDetailResource())
    app.add_route("/api/request/id/{id}", RequestDetailResource())
    app.add_route("/api/request", RequestListResource())
    app.add_route("/api/revoked/{serial_number}", RevokedCertificateDetailResource())
    app.add_route("/api/log", LogResource())
    app.add_route("/api/revoked", RevocationListResource())
    app.add_route("/api/toggleaccess/id/{id}", DisableEnableAccessToInstance())

    token_resource = None
    token_manager = None
    if const.USER_ENROLLMENT_ALLOWED:  # TODO: add token enable/disable flag for config
        token_manager = TokenManager()
        token_resource = TokenResource(token_manager)
        app.add_route("/api/token", token_resource)

    app.add_route("/api/session", SessionResource(token_manager))

    # Extended attributes for scripting etc.
    app.add_route("/api/signed/id/{id}/script", ScriptResource())

    # API calls used by pushed events on the JS end
    app.add_route("/api/signed/id/{id}/tag", TagResource())

    # API call used to delete existing tags
    app.add_route("/api/signed/id/{id}/tag/{tag}", TagDetailResource())

    # Bootstrap resource
    app.add_route("/api/bootstrap", BootstrapResource())

    signal.signal(signal.SIGTERM, graceful_exit)
    with make_server("127.0.0.1", 4001, app) as httpd:
        httpd.serve_forever()


@click.command("test", help="Test mailer")
@click.argument("recipient")
def pinecone_test(recipient):
    from pinecrypt.server import mailer
    mailer.send("test.md", to=recipient)


@click.command("list", help="List tokens")
def pinecone_token_list():
    from pinecrypt.server.tokens import TokenManager
    token_manager = TokenManager(const.TOKEN_DATABASE)
    cols = "uuid", "expires", "subject", "state"
    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    for token in token_manager.list(expired=True, used=True):
        token["state"] = "used" if token.get("used") else ("valid" if token.get("expires") > now else "expired")
        print(";".join([str(token.get(col)) for col in cols]))


@click.command("purge", help="Purge tokens")
@click.option("-a", "--all", default=False, is_flag=True, help="Purge all not only expired tokens")
def pinecone_token_purge(all):
    from pinecrypt.server.tokens import TokenManager
    token_manager = TokenManager(const.TOKEN_DATABASE)
    print(token_manager.purge(all))


@click.command("issue", help="Issue token")
@click.option("-m", "--subject-mail", default=None, help="Subject e-mail override")
@click.argument("subject")
def pinecone_token_issue(subject, subject_mail):
    from pinecrypt.server.tokens import TokenManager
    from pinecrypt.server.user import User
    token_manager = TokenManager(const.TOKEN_DATABASE)
    token_manager.issue(None, User.objects.get(subject), subject_mail)


@click.group("housekeeping", help="Housekeeping tasks")
def pinecone_housekeeping(): pass


@click.group("token", help="Token management")
def pinecone_token(): pass


@click.group("serve", help="Entrypoints")
def pinecone_serve(): pass


@click.group("session", help="Session management")
def pinecone_session(): pass


@click.group()
def entry_point(): pass


pinecone_serve.add_command(pinecone_serve_backend)
pinecone_serve.add_command(pinecone_serve_events)
pinecone_serve.add_command(pinecone_serve_builder)
pinecone_session.add_command(pinecone_session_list)
pinecone_token.add_command(pinecone_token_list)
pinecone_token.add_command(pinecone_token_purge)
pinecone_token.add_command(pinecone_token_issue)
pinecone_housekeeping.add_command(pinecone_housekeeping_kinit)
pinecone_housekeeping.add_command(pinecone_housekeeping_expiration)
entry_point.add_command(pinecone_token)
entry_point.add_command(pinecone_serve)
entry_point.add_command(pinecone_sign)
entry_point.add_command(pinecone_revoke)
entry_point.add_command(pinecone_list)
entry_point.add_command(pinecone_housekeeping)
entry_point.add_command(pinecone_users)
entry_point.add_command(pinecone_test)
entry_point.add_command(pinecone_log)
entry_point.add_command(pinecone_provision)
entry_point.add_command(pinecone_session)
entry_point.add_command(pinecone_disable)
entry_point.add_command(pinecone_enable)

if __name__ == "__main__":
    entry_point()
