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
import logging
import os
import pymongo
import signal
import socket
import sys
import pytz
from asn1crypto import pem, x509
from certbuilder import CertificateBuilder, pem_armor_certificate
from datetime import datetime, timedelta
from oscrypto import asymmetric
from pinecrypt.server import const, mongolog, mailer, db
from pinecrypt.server.middleware import NormalizeMiddleware, PrometheusEndpoint
from pinecrypt.server.common import cn_to_dn, generate_serial
from time import sleep
from wsgiref.simple_server import make_server

logger = logging.getLogger(__name__)
mongolog.register()


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


@click.command("ocsp-responder")
@waitfile(const.AUTHORITY_CERTIFICATE_PATH)
def pinecone_serve_ocsp_responder():
    from pinecrypt.server.api.ocsp import app
    app.run(port=5001, debug=const.DEBUG)


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
    default_policy = "REJECT" if const.DEBUG else "DROP"

    click.echo("Setting up firewall rules")
    if const.REPLICAS:
        # TODO: atomic update with `ipset restore`
        for replica in const.REPLICAS:
            for fam, _, _, _, addrs in socket.getaddrinfo(replica, None):
                if fam == 10:
                    os.system("ipset add ipset6-mongo-replicas %s" % addrs[0])
                elif fam == 2:
                    os.system("ipset add ipset4-mongo-replicas %s" % addrs[0])

    os.system("ipset create -exist -quiet ipset4-client-ingress hash:ip timeout 3600 counters")
    os.system("ipset create -exist -quiet ipset6-client-ingress hash:ip family inet6 timeout 3600 counters")

    os.system("ipset create -exist -quiet ipset4-client-egress hash:ip timeout 3600 counters")
    os.system("ipset create -exist -quiet ipset6-client-egress hash:ip family inet6 timeout 3600 counters")

    os.system("ipset create -exist -quiet ipset4-mongo-replicas hash:ip")
    os.system("ipset create -exist -quiet ipset6-mongo-replicas hash:ip family inet6")

    os.system("ipset create -exist -quiet ipset4-prometheus-subnets hash:net")
    os.system("ipset create -exist -quiet ipset6-prometheus-subnets hash:net family inet6")

    for subnet in const.PROMETHEUS_SUBNETS:
        os.system("ipset add -exist -quiet ipset%d-prometheus-subnets %s" % (subnet.version, subnet))

    def g():
        yield "*filter"
        yield ":INBOUND_BLOCKED - [0:0]"
        yield "-A INBOUND_BLOCKED -j %s -m comment --comment \"Default policy\"" % default_policy

        yield ":OUTBOUND_CLIENT - [0:0]"
        yield "-A OUTBOUND_CLIENT -m set ! --match-set ipset4-client-ingress dst -j SET --add-set ipset4-client-ingress dst"
        yield "-A OUTBOUND_CLIENT -j ACCEPT"

        yield ":INBOUND_CLIENT - [0:0]"
        yield "-A INBOUND_CLIENT -m set ! --match-set ipset4-client-ingress src -j SET --add-set ipset4-client-ingress src"
        yield "-A INBOUND_CLIENT -j ACCEPT"

        yield ":INPUT DROP [0:0]"
        yield "-A INPUT -i lo -j ACCEPT -m comment --comment \"Allow loopback\""
        yield "-A INPUT -p icmp -j ACCEPT -m comment --comment \"Allow ping\""
        yield "-A INPUT -p esp -j ACCEPT -m comment --comment \"Allow ESP traffic\""
        yield "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment \"Allow returning packets\""
        yield "-A INPUT -p tcp --dport 22 -j ACCEPT -m comment --comment \"Allow SSH\""
        yield "-A INPUT -p udp --dport 53 -j ACCEPT -m comment --comment \"Allow GoreDNS over UDP\""
        yield "-A INPUT -p tcp --dport 53 -j ACCEPT -m comment --comment \"Allow GoreDNS over TCP\""
        yield "-A INPUT -p tcp --dport 80 -j ACCEPT -m comment --comment \"Allow insecure HTTP\""
        yield "-A INPUT -p tcp --dport 443 -j ACCEPT -m comment --comment \"Allow HTTPS / OpenVPN TCP\""
        yield "-A INPUT -p tcp --dport 8443 -j ACCEPT -m comment --comment \"Allow mutually authenticated HTTPS\""
        yield "-A INPUT -p udp --dport 1194 -j ACCEPT -m comment --comment \"Allow OpenVPN UDP\""
        yield "-A INPUT -p udp --dport 500 -j ACCEPT -m comment --comment \"Allow IPsec IKE\""
        yield "-A INPUT -p udp --dport 4500 -j ACCEPT -m comment --comment \"Allow IPsec NAT traversal\""
        if const.REPLICAS:
            yield "-A INPUT -p tcp --dport 27017 -j ACCEPT -m set --match-set ipset4-mongo-replicas src -m comment --comment \"Allow MongoDB internode\""
        yield "-A INPUT -p tcp --dport 9090 -j ACCEPT -m set --match-set ipset4-prometheus-subnets src -m comment --comment \"Allow Prometheus\""
        yield "-A INPUT -j INBOUND_BLOCKED"

        yield ":FORWARD DROP [0:0]"
        yield "-A FORWARD -i tunudp0 -j INBOUND_CLIENT -m comment --comment \"Inbound traffic from OpenVPN UDP clients\""
        yield "-A FORWARD -i tuntcp0 -j INBOUND_CLIENT -m comment --comment \"Inbound traffic from OpenVPN TCP clients\""
        yield "-A FORWARD -m policy --dir in --pol ipsec  -j INBOUND_CLIENT -m comment --comment \"Inbound traffic from IPSec clients\""
        yield "-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j OUTBOUND_CLIENT -m comment --comment \"Outbound traffic to clients\""
        yield "-A FORWARD -j %s -m comment --comment \"Default policy\"" % default_policy

        yield ":OUTPUT DROP [0:0]"
        yield "-A OUTPUT -j ACCEPT"
        yield "COMMIT"

        yield "*nat"
        yield ":PREROUTING ACCEPT [0:0]"
        yield ":INPUT ACCEPT [0:0]"
        yield ":OUTPUT ACCEPT [0:0]"
        yield ":POSTROUTING ACCEPT [0:0]"
        yield "-A POSTROUTING -j MASQUERADE"
        yield "COMMIT"

    with open("/tmp/rules4", "w") as fh:
        for line in g():
            fh.write(line)
            fh.write("\n")

    if not const.DISABLE_FIREWALL:
        os.system("iptables-restore < /tmp/rules4")
        os.system("sed -e 's/ipset4/ipset6/g' -e 's/p icmp/p ipv6-icmp/g' /tmp/rules4 > /tmp/rules6")
        os.system("ip6tables-restore < /tmp/rules6")
        os.system("sysctl -w net.ipv6.conf.all.forwarding=1")
        os.system("sysctl -w net.ipv6.conf.default.forwarding=1")
        os.system("sysctl -w net.ipv4.ip_forward=1")

    if const.REPLICAS:
        click.echo("Provisioning MongoDB replicaset")
        # WTF https://github.com/docker-library/mongo/issues/339
        c = pymongo.MongoClient("localhost", 27017)
        config = {"_id": "rs0", "members": [
            {"_id": index, "host": "%s:27017" % hostname} for index, hostname in enumerate(const.REPLICAS)]}
        print("Provisioning MongoDB replicaset: %s" % repr(config))
        try:
            c.admin.command("replSetInitiate", config)
        except pymongo.errors.OperationFailure:
            print("Looks like it's already initialized")
            pass

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

        # Set permission bits to 640
        os.umask(0o137)
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

    # TODO: use this task to send notification emails maybe?
    click.echo("Finished starting up")
    sleep(86400)


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


@click.command("openvpn", help="Start OpenVPN server process")
@click.option("--local", "-l", default="0.0.0.0", help="OpenVPN listening address, defaults to all interfaces")
@click.option("--proto", "-t", default="udp", type=click.Choice(["udp", "tcp"]), help="OpenVPN transport protocol, UDP by default")
@click.option("--client-subnet-slot", "-s", type=int, help="Client subnet slot index")
@waitfile(const.SELF_CERT_PATH)
def pinecone_serve_openvpn(local, proto, client_subnet_slot):
    from pinecrypt.server import config
    # TODO: Generate (per-client configs) from MongoDB
    executable = "/usr/sbin/openvpn"

    args = executable,
    slot4 = const.CLIENT_SUBNET4_SLOTS[client_subnet_slot]
    args += "--server", str(slot4.network_address), str(slot4.netmask),
    if const.CLIENT_SUBNET6:
        args += "--server-ipv6", str(const.CLIENT_SUBNET6_SLOTS[client_subnet_slot]),
    args += "--local", local

    # Support only two modes TCP 443 and UDP 1194
    if proto == "tcp":
        args += "--dev", "tuntcp0",
        args += "--port-share", "127.0.0.1", "1443",
        args += "--proto", "tcp-server",
        args += "--port", "443",
        args += "--socket-flags", "TCP_NODELAY",
        args += "--management", "127.0.0.1", "7506",
        instance = "%s-openvpn-tcp-443" % const.FQDN
    else:
        args += "--dev", "tunudp0",
        args += "--proto", "udp",
        args += "--port", "1194",
        args += "--management", "127.0.0.1", "7505",
        instance = "%s-openvpn-udp-1194" % const.FQDN
    args += "--setenv", "instance", instance
    db.certificates.update_many({
        "instance": instance
    }, {
        "$unset": {
            "ip": "",
            "instance": "",
        }
    })

    # Send keep alive packets, mainly for UDP
    args += "--keepalive", "60", "120",

    args += "--opt-verify",

    args += "--key", const.SELF_KEY_PATH
    args += "--cert", const.SELF_CERT_PATH
    args += "--ca", const.AUTHORITY_CERTIFICATE_PATH

    if const.PUSH_SUBNETS:
        args += "--push", "route-metric 1000"
    for subnet in const.PUSH_SUBNETS:
        if subnet.version == 4:
            args += "--push", "route %s %s" % (subnet.network_address, subnet.netmask),
        elif subnet.version == 6:
            if not const.CLIENT_SUBNET6:
                raise ValueError("Can't push IPv6 routes if no IPv6 client subnet is configured")
            args += "--push", "route-ipv6 %s" % subnet
        else:
            raise NotImplementedError()

    # TODO: Figure out how to do dhparam without blocking initially
    if os.path.exists(const.DHPARAM_PATH):
        args += "--dh", const.DHPARAM_PATH
    else:
        args += "--dh", "none"

    # For more info see: openvpn --show-tls
    args += "--tls-version-min", config.get("Globals", "OPENVPN_TLS_VERSION_MIN")["value"]
    args += "--tls-ciphersuites", config.get("Globals", "OPENVPN_TLS_CIPHERSUITES")["value"],  # Used by TLS 1.3
    args += "--tls-cipher", config.get("Globals", "OPENVPN_TLS_CIPHER")["value"],  # Used by TLS 1.2

    # Data channel encryption parameters
    # TODO: Rename to --data-cipher when OpenVPN 2.5 becomes available
    args += "--cipher", config.get("Globals", "OPENVPN_CIPHER")["value"]
    args += "--auth", config.get("Globals", "OPENVPN_AUTH")["value"]

    # Just to sanity check ourselves
    args += "--tls-cert-profile", "preferred",

    # Disable cipher negotiation since we know what we want
    args += "--ncp-disable",

    args += "--script-security", "2",
    args += "--learn-address", "/helpers/openvpn-learn-address.py"
    args += "--client-connect", "/helpers/openvpn-client-connect.py"
    args += "--verb", "0",

    logger.info("Executing: %s" % (" ".join(args)))
    os.execv(executable, args)


@click.command("strongswan", help="Start StrongSwan")
@click.option("--client-subnet-slot", "-s", type=int, help="Client subnet slot index")
@waitfile(const.SELF_CERT_PATH)
def pinecone_serve_strongswan(client_subnet_slot):
    from pinecrypt.server import config
    slots = []
    slots.append(const.CLIENT_SUBNET4_SLOTS[client_subnet_slot])
    if const.CLIENT_SUBNET6:
        slots.append(const.CLIENT_SUBNET6_SLOTS[client_subnet_slot])

    with open("/etc/ipsec.conf", "w") as fh:
        fh.write("config setup\n")
        fh.write("  strictcrlpolicy=yes\n")
        fh.write("  charondebug=\"cfg 2\"\n")

        fh.write("\n")
        fh.write("ca authority\n")
        fh.write("  auto=add\n")
        fh.write("  cacert=%s\n" % const.AUTHORITY_CERTIFICATE_PATH)
        fh.write("\n")
        fh.write("conn s2c\n")
        fh.write("  auto=add\n")
        fh.write("  keyexchange=ikev2\n")

        fh.write("  left=%s\n" % const.AUTHORITY_NAMESPACE)
        fh.write("  leftsendcert=always\n")
        fh.write("  leftallowany=yes\n")  # For load-balancing
        fh.write("  leftcert=%s\n" % const.SELF_CERT_PATH)
        if const.PUSH_SUBNETS:
            fh.write("  leftsubnet=%s\n" % ",".join([str(j) for j in const.PUSH_SUBNETS]))
        fh.write("  leftupdown=/helpers/updown.py\n")

        fh.write("  right=%any\n")
        fh.write("  rightsourceip=%s\n" % ",".join([str(j) for j in slots]))
        fh.write("  ike=%s!\n" % config.get("Globals", "STRONGSWAN_IKE")["value"])
        fh.write("  esp=%s!\n" % config.get("Globals", "STRONGSWAN_ESP")["value"])
    with open("/etc/ipsec.conf") as fh:
        print(fh.read())

    # Why do you do this StrongSwan?! You will parse the cert anyway,
    # why do I need to distinguish ECDSA vs RSA in config?!
    with open(const.SELF_CERT_PATH, "rb") as fh:
        certificate_buf = fh.read()
        header, _, certificate_der_bytes = pem.unarmor(certificate_buf)
        certificate = x509.Certificate.load(certificate_der_bytes)
        public_key = asymmetric.load_public_key(certificate["tbs_certificate"]["subject_public_key_info"])
    with open("/etc/ipsec.secrets", "w") as fh:
        fh.write(": %s %s\n" % (
            "ECDSA" if public_key.algorithm == "ec" else "RSA",
            const.SELF_KEY_PATH
        ))
    executable = "/usr/sbin/ipsec"
    args = executable, "start", "--nofork"
    logger.info("Executing: %s" % (" ".join(args)))
    instance = "%s-ipsec" % const.FQDN

    db.certificates.update_many({
        "instance": instance
    }, {
        "$unset": {
            "ip": "",
            "instance": "",
        }
    })

    # TODO: Find better way to push env vars to updown script
    with open("/instance", "w") as fh:
        fh.write(instance)
    os.execv(executable, args)


pinecone_serve.add_command(pinecone_serve_openvpn)
pinecone_serve.add_command(pinecone_serve_strongswan)
pinecone_serve.add_command(pinecone_serve_backend)
pinecone_serve.add_command(pinecone_serve_ocsp_responder)
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

if __name__ == "__main__":
    entry_point()
