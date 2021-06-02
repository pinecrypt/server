import ldap
import click
import os
import re
import socket
import sys
from datetime import timedelta
from ipaddress import ip_network

RE_USERNAME = r"^[a-z][a-z0-9]+$"
RE_FQDN = r"^(([a-z0-9]|[a-z0-9][a-z0-9\-_]*[a-z0-9])\.)+([a-z0-9]|[a-z0-9][a-z0-9\-_]*[a-z0-9])?$"
RE_HOSTNAME = r"^[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?$"
RE_COMMON_NAME = r"^[A-Za-z0-9\-\_]+$"

# Make sure locales don't mess up anything
assert re.match(RE_USERNAME, "abstuzxy19")


# To be migrated to Mongo or removed
def parse_tag_types(d):
    r = []
    for j in d.split(","):
        r.append(j.split("/"))
    return r


TAG_TYPES = parse_tag_types(os.getenv("TAG_TYPES", "owner/str,location/str,phone/str,other/str"))
SCRIPT_DIR = ""
IMAGE_BUILDER_PROFILES = []
SERVICE_PROTOCOLS = ["ikev2", "openvpn"]

MONGO_URI = os.getenv("MONGO_URI")
REPLICAS = os.getenv("REPLICAS")
if REPLICAS:
    REPLICAS = REPLICAS.split(",")
    if MONGO_URI:
        raise ValueError("Simultanously specifying MONGO_URI and REPLICAS doesn't make sense")
    MONGO_URI = "mongodb://%s/default?replicaSet=rs0" % (",".join(["%s:27017" % j for j in REPLICAS]))
elif not MONGO_URI:
    MONGO_URI = "mongodb://127.0.0.1:27017/default?replicaSet=rs0"

KEY_SIZE = 4096
CURVE_NAME = "secp384r1"

# Kerberos-like clock skew tolerance
CLOCK_SKEW_TOLERANCE = timedelta(minutes=5)

AUTHORITY_PRIVATE_KEY_PATH = "/authority-secrets/ca_key.pem"
AUTHORITY_CERTIFICATE_PATH = "/server-secrets/ca_cert.pem"
SELF_CERT_PATH = "/server-secrets/self_cert.pem"
SELF_KEY_PATH = "/server-secrets/self_key.pem"
DHPARAM_PATH = "/server-secrets/dhparam.pem"
BUILDER_TARBALLS = ""

FQDN = socket.getfqdn()

try:
    HOSTNAME, DOMAIN = FQDN.split(".", 1)
except ValueError:  # If FQDN is not configured
    click.echo("FQDN not configured: %s" % repr(FQDN))
    sys.exit(255)


def getenv_in(key, default, *vals):
    val = os.getenv(key, default)
    if val not in (default,) + vals:
        raise ValueError("Got %s for %s, expected one of %s" % (repr(val), key, vals))
    return val


# Authority namespace corresponds to DNS entry which represents refers to all replicas
AUTHORITY_NAMESPACE = os.getenv("AUTHORITY_NAMESPACE", FQDN)
if FQDN != AUTHORITY_NAMESPACE and not FQDN.endswith(".%s" % AUTHORITY_NAMESPACE):
    raise ValueError("Instance fully qualified domain name %s does not belong under %s, was expecing something like replica1.%s" % (
        repr(FQDN), repr(AUTHORITY_NAMESPACE), AUTHORITY_NAMESPACE))
USER_NAMESPACE = "u.%s" % AUTHORITY_NAMESPACE
MACHINE_NAMESPACE = "m.%s" % AUTHORITY_NAMESPACE
AUTHORITY_COMMON_NAME = "Pinecrypt Gateway at %s" % AUTHORITY_NAMESPACE
AUTHORITY_ORGANIZATION = os.getenv("AUTHORITY_ORGANIZATION")
AUTHORITY_LIFETIME_DAYS = 20 * 365

# Advertise following IP addresses via DNS record
ADVERTISE_ADDRESS = [j for j  in os.getenv("ADVERTISE_ADDRESS", "").split(",") if j]
if not ADVERTISE_ADDRESS:
    ADVERTISE_ADDRESS = set()
    for fam, _, _, _, addrs in socket.getaddrinfo(FQDN, None):
        if fam in (2, 10):
            ADVERTISE_ADDRESS.add(addrs[0])

# Mailer settings
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = os.getenv("SMTP_PORT", 25)
SMTP_TLS = getenv_in("SMTP_TLS", "tls", "starttls", "none")
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_SENDER_NAME = os.getenv("SMTP_SENDER_NAME", "Pinecrypt Gateway at %s" % AUTHORITY_NAMESPACE)
SMTP_SENDER_ADDR = os.getenv("SMTP_SENDER_ADDR")

# Stuff that gets embedded in each issued certificate
AUTHORITY_CERTIFICATE_URL = "http://%s/api/certificate" % AUTHORITY_NAMESPACE
AUTHORITY_CRL_ENABLED = os.getenv("AUTHORITY_CRL_ENABLED", False)
AUTHORITY_CRL_URL = "http://%s/api/revoked/" % AUTHORITY_NAMESPACE
AUTHORITY_OCSP_URL = "http://%s/api/ocsp/" % AUTHORITY_NAMESPACE
AUTHORITY_OCSP_DISABLED = os.getenv("AUTHORITY_OCSP_DISABLED", False)
AUTHORITY_KEYTYPE = getenv_in("AUTHORITY_KEYTYPE", "ec", "rsa")

# Tokens
TOKEN_URL = "https://%(authority_name)s/#action=enroll&title=dev.lan&token=%(token)s&subject=%(subject_username)s&protocols=%(protocols)s"
TOKEN_LIFETIME = 3600 * 24
TOKEN_OVERWRITE_PERMITTED = os.getenv("TOKEN_OVERWRITE_PERMITTED")
# TODO: Check if we don't have base or servers

AUTHENTICATION_BACKENDS = set(["ldap"])
MAIL_SUFFIX = os.getenv("MAIL_SUFFIX")

KERBEROS_KEYTAB = os.getenv("KERBEROS_KEYTAB", "/server-secrets/krb5.keytab")
KERBEROS_REALM = os.getenv("KERBEROS_REALM")
LDAP_AUTHENTICATION_URI = os.getenv("LDAP_AUTHENTICATION_URI")
LDAP_GSSAPI_CRED_CACHE = os.getenv("LDAP_GSSAPI_CRED_CACHE", "/run/certidude/krb5cc")
LDAP_ACCOUNTS_URI = os.getenv("LDAP_ACCOUNTS_URI")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN")
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD")
LDAP_BASE = os.getenv("LDAP_BASE")
LDAP_MAIL_ATTRIBUTE = os.getenv("LDAP_MAIL_ATTRIBUTE", "mail")
LDAP_USER_FILTER = os.getenv("LDAP_USER_FILTER", "(samaccountname=%s)")
LDAP_ADMIN_FILTER = os.getenv("LDAP_ADMIN_FILTER", "(samaccountname=%s)")
LDAP_COMPUTER_FILTER = os.getenv("LDAP_COMPUTER_FILTER", "()")

LDAP_CA_CERT = os.getenv("LDAP_CA_CERT")
if LDAP_CA_CERT:
    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, LDAP_CA_CERT)

if os.getenv("LDAP_DEBUG"):
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    ldap.set_option(ldap.OPT_DEBUG_LEVEL, 1)


def getenv_subnets(key, default=""):
    return set([ip_network(j) for j in os.getenv(key, default).replace(",", " ").split(" ") if j])


USER_SUBNETS = getenv_subnets("AUTH_USER_SUBNETS", "0.0.0.0/0 ::/0")
ADMIN_SUBNETS = getenv_subnets("AUTH_ADMIN_SUBNETS", "0.0.0.0/0 ::/0")
AUTOSIGN_SUBNETS = getenv_subnets("AUTH_AUTOSIGN_SUBNETS", "")
REQUEST_SUBNETS = getenv_subnets("AUTH_REQUEST_SUBNETS", "0.0.0.0/0 ::/0").union(AUTOSIGN_SUBNETS)
CRL_SUBNETS = getenv_subnets("AUTH_CRL_SUBNETS", "0.0.0.0/0 ::/0")
OVERWRITE_SUBNETS = getenv_subnets("AUTH_OVERWRITE_SUBNETS", "")
MACHINE_ENROLLMENT_SUBNETS = getenv_subnets("AUTH_MACHINE_ENROLLMENT_SUBNETS", "0.0.0.0/0 ::/0")
KERBEROS_SUBNETS = getenv_subnets("AUTH_KERBEROS_SUBNETS", "0.0.0.0/0 ::/0")
PROMETHEUS_SUBNETS = getenv_subnets("PROMETHEUS_SUBNETS", "")

BOOTSTRAP_TEMPLATE = ""
USER_ENROLLMENT_ALLOWED = True
USER_MULTIPLE_CERTIFICATES = True

REQUEST_SUBMISSION_ALLOWED = os.getenv("REQUEST_SUBMISSION_ALLOWED")
REVOCATION_LIST_LIFETIME = os.getenv("REVOCATION_LIST_LIFETIME")

PUSH_SUBNETS = [ip_network(j) for j in os.getenv("PUSH_SUBNETS", "").replace(" ", ",").split(",") if j]
CLIENT_SUBNET4 = ip_network(os.getenv("CLIENT_SUBNET4", "192.168.33.0/24"))
CLIENT_SUBNET6 = ip_network(os.getenv("CLIENT_SUBNET6")) if os.getenv("CLIENT_SUBNET6") else None
CLIENT_SUBNET_SLOT_COUNT = int(os.getenv("CLIENT_SUBNET_COUNT", 4))

if CLIENT_SUBNET4.netmask == str("255.255.255.255"):
    raise ValueError("Invalid client subnet specification: %s" % CLIENT_SUBNET4)

if "%s" not in LDAP_USER_FILTER:
    raise ValueError("No placeholder %s for username in 'ldap user filter'")
if "%s" not in LDAP_ADMIN_FILTER:
    raise ValueError("No placeholder %s for username in 'ldap admin filter'")

AUDIT_EMAIL = os.getenv("AUDIT_EMAIL")
DEBUG = bool(os.getenv("DEBUG"))

SESSION_COOKIE = "sha512brownies"
SESSION_AGE = 3600

SECRET_STORAGE = getenv_in("SECRET_STORAGE", "fs", "db")

DISABLE_FIREWALL = os.getenv("DISABLE_FIREWALL") == "True" if os.getenv("DISABLE_FIREWALL") else False
