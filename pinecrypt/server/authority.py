import click
import logging
import os
import re
import socket
import pytz
from oscrypto import asymmetric
from asn1crypto import pem, x509
from asn1crypto.csr import CertificationRequest
from certbuilder import CertificateBuilder
from pinecrypt.server import mailer, const, errors, config, db
from pinecrypt.server.common import cn_to_dn, generate_serial, cert_to_dn
from crlbuilder import CertificateListBuilder, pem_armor_crl
from csrbuilder import CSRBuilder, pem_armor_csr
from datetime import datetime, timedelta
from bson.objectid import ObjectId

logger = logging.getLogger(__name__)

# Cache CA certificate
with open(const.AUTHORITY_CERTIFICATE_PATH, "rb") as fh:
    certificate_buf = fh.read()
    header, _, certificate_der_bytes = pem.unarmor(certificate_buf)
    certificate = x509.Certificate.load(certificate_der_bytes)
    public_key = asymmetric.load_public_key(certificate["tbs_certificate"]["subject_public_key_info"])

with open(const.AUTHORITY_PRIVATE_KEY_PATH, "rb") as fh:
    key_buf = fh.read()
    header, _, key_der_bytes = pem.unarmor(key_buf)
    private_key = asymmetric.load_private_key(key_der_bytes)


def self_enroll(skip_notify=False):
    common_name = const.HOSTNAME

    try:
        cert, cert_doc, pem_buf = get_signed(common_name=common_name,namespace=const.AUTHORITY_NAMESPACE)
        self_public_key = asymmetric.load_public_key(cert["tbs_certificate"]["subject_public_key_info"])
        private_key = asymmetric.load_private_key(const.SELF_KEY_PATH)
    except (NameError, FileNotFoundError, errors.CertificateDoesNotExist) as error:  # certificate or private key not found
        click.echo("Generating private key for frontend: %s" % const.SELF_KEY_PATH)
        with open(const.SELF_KEY_PATH, 'wb') as fh:
            if public_key.algorithm == "ec":
                self_public_key, private_key = asymmetric.generate_pair("ec", curve=public_key.curve)
            elif public_key.algorithm == "rsa":
                self_public_key, private_key = asymmetric.generate_pair("rsa", bit_size=public_key.bit_size)
            else:
                raise NotImplemented("CA certificate public key algorithm %s not supported" % public_key.algorithm)
            fh.write(asymmetric.dump_private_key(private_key, None))
    else:
        now = datetime.utcnow().replace(tzinfo=pytz.UTC)
        if now + timedelta(days=1) < cert_doc["expires"].replace(tzinfo=pytz.UTC) and os.path.exists(const.SELF_CERT_PATH):
            click.echo("Self certificate still valid, delete to self-enroll again")
            return


    builder = CSRBuilder({"common_name": common_name}, self_public_key)
    request = builder.build(private_key)

    now = datetime.utcnow().replace(tzinfo=pytz.UTC)

    d ={}
    d["submitted"] = now
    d["common_name"] = common_name
    d["request_buf"] = request.dump()
    d["status"] = "csr"
    d["user"] = {}

    doc = db.certificates.find_one_and_update({
        "common_name":d["common_name"]
    }, {
        "$set": d,
        "$setOnInsert": {
            "created": now,
            "ip": [],
       }},
        upsert=True,
        return_document=db.return_new)

    id = str(doc.get("_id"))
    cert, buf = sign(mongo_id=id, skip_notify=skip_notify, overwrite=True,
        profile="Gateway", namespace=const.AUTHORITY_NAMESPACE)

    os.umask(0o133)
    with open(const.SELF_CERT_PATH + ".part", "wb") as fh:
        fh.write(buf)
    os.rename(const.SELF_CERT_PATH + ".part", const.SELF_CERT_PATH)


def get_common_name_id(cn):
    cn = cn.lower()
    doc = db.certificates.find_one({"common_name": cn})

    if not doc:
        raise ValueError("Object not found with common name %s" % cn)

    return str(doc["_id"])

def list_revoked(limit=0):
    # TODO: sort recent to oldest
    for cert_revoked_doc in db.certificates.find({"status": "revoked"}):
        cert = x509.Certificate.load(cert_revoked_doc["cert_buf"])
        yield cert_revoked_doc, cert
        if limit:  # TODO: Use mongo for this
            limit -= 1
            if limit <= 0:
                return

# TODO: it should be possible to regex search common_name directly from mongodb
def list_signed(common_name=None):
    for cert_doc in db.certificates.find({"status" : "signed"}):
        if common_name:
            if common_name.startswith("^"):
                if not re.match(common_name, cert_doc["common_name"]):
                    continue
            else:
                if common_name != cert_doc["common_name"]:
                    continue
        cert = x509.Certificate.load(cert_doc["cert_buf"])
        yield cert_doc, cert

def list_requests():
    for request in db.certificates.find({"status": "csr"}):
        csr = CertificationRequest.load(request["request_buf"])
        yield csr, request, "." in request["common_name"]

def list_replicas():
    """
    Return list of Mongo objects referring to all active replicas
    """
    for doc in db.certificates.find({"status" : "signed", "profile.ou": "Gateway"}):
        yield doc

def get_ca_cert():
    fh = open(const.AUTHORITY_CERTIFICATE_PATH, "rb")
    server_certificate = asymmetric.load_certificate(fh.read())
    fh.close()
    return server_certificate

def get_request(id):
    if not id:
        raise ValueError("Invalid id parameter %s" % id)

    csr_doc = db.certificates.find_one({"_id": ObjectId(id), "status": "csr"})

    if not csr_doc:
       raise errors.RequestDoesNotExist("Certificate signing request with id %s does not exist" % id)

    csr = CertificationRequest.load(csr_doc["request_buf"])
    return csr, csr_doc, pem_armor_csr(csr)

def get_by_serial(serial):
    serial_string = "%x" % serial
    query = {"serial_number": serial_string}

    cert_doc = db.certificates.find_one(query)

    if not cert_doc:
        raise errors.CertificateDoesNotExist("Certificate with serial %s not found" % serial)

    cert = x509.Certificate.load(cert_doc["cert_buf"])
    return cert_doc, cert

def get_signed(mongo_id=False, common_name=False, namespace=const.AUTHORITY_NAMESPACE):

    if mongo_id:
        query = {"_id": ObjectId(mongo_id), "status": "signed"}
    elif common_name:
        common_name = "%s.%s" % (common_name, namespace)
        query = {"common_name": common_name, "status": "signed"}
    else:
        raise ValueError("No Id or common name specified for signed certificate search")

    cert_doc = db.certificates.find_one(query)

    if not cert_doc:
        raise errors.CertificateDoesNotExist("We did not found certificate with CN %s" % repr(common_name))

    cert = x509.Certificate.load(cert_doc["cert_buf"])
    pem_buf = asymmetric.dump_certificate(cert)
    return cert, cert_doc, pem_buf


# TODO: get revoked cert from database by serial
def get_revoked(serial):

    if isinstance(serial, int):
        serial = "%x" % serial

    query = {"serial_number":serial, "status": "revoked"}
    cert_doc = db.certificates.find_one(query)

    if not cert_doc:
        raise errors.CertificateDoesNotExist

    cert_pem_buf = pem.armor("CERTIFICATE",cert_doc["cert_buf"])
    return cert_doc, cert_pem_buf


def store_request(buf, overwrite=False, address="", user="", namespace=const.MACHINE_NAMESPACE):
    """
    Store CSR for later processing
    """
    # TODO: Raise exception for any CSR where CN is set to one of servers/replicas
    now = datetime.utcnow().replace(tzinfo=pytz.UTC)

    if not buf:
        raise ValueError("No signing request supplied")

    if pem.detect(buf):
        header, _, der_bytes = pem.unarmor(buf)
        csr = CertificationRequest.load(der_bytes)
    else:
        csr = CertificationRequest.load(buf)
        der_bytes = csr.dump()

    common_name = csr["certification_request_info"]["subject"].native["common_name"].lower()

    if not re.match(const.RE_COMMON_NAME, common_name):
        raise ValueError("Invalid common name %s" % repr(common_name))


    query = {"common_name": common_name, "status": "csr"}
    doc = db.certificates.find_one(query)
    d ={}
    user_object = {}

    if doc and not overwrite:
        if doc["request_buf"] == der_bytes:
            raise errors.RequestExists("Request already exists")
        else:
            raise errors.DuplicateCommonNameError("Another request with same common name already exists")
    else:
        # TODO: does CSR contain any timestamp??
        d["submitted"] = now
        d["common_name"] = common_name
        d["request_buf"] = der_bytes
        d["status"] = "csr"

    pem_buf = pem_armor_csr(csr)
    attach_csr = pem_buf, "application/x-pem-file", common_name + ".csr"
    mailer.send("request-stored.md", attachments=(attach_csr,), common_name=common_name)
    user_object["request_addresss"] = address
    user_object["name"] = user

    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(address)
    except (socket.herror, OSError):  # Failed to resolve hostname or resolved to multiple
        pass
    else:
        user_object["request_hostname"] = hostname

    d["user"] = user_object

    doc = db.certificates.find_one_and_update({
        "common_name":d["common_name"]
    }, {
        "$set": d,
        "$setOnInsert": {
            "created": now,
            "ip": [],
        }},
        upsert=True,
        return_document=db.return_new)

    return doc

def revoke(mongo_id, reason, user="root"):
    """
    Revoke valid certificate
    """
    cert, cert_doc, pem_buf = get_signed(mongo_id)
    common_name = cert_doc["common_name"]

    if reason not in ("key_compromise", "ca_compromise", "affiliation_changed",
        "superseded", "cessation_of_operation", "certificate_hold",
        "remove_from_crl", "privilege_withdrawn"):
        raise ValueError("Invalid revocation reason %s" % reason)

    logger.info("Revoked certificate %s by %s", common_name, user)

    if mongo_id:
        query = {"_id": ObjectId(mongo_id), "status": "signed"}
    elif common_name:
        query = {"common_name": common_name, "status": "signed"}
    else:
        raise ValueError("No common name or Id specified")

    prev = db.certificates.find_one(query)
    newValue = { "$set": { "status": "revoked", "revocation_reason": reason, "revoked": datetime.utcnow().replace(tzinfo=pytz.UTC)} }
    db.certificates.find_one_and_update(query,newValue)

    attach_cert = pem_buf, "application/x-pem-file", common_name + ".crt"

    mailer.send("certificate-revoked.md",
        attachments=(attach_cert,),
        serial_hex="%x" % cert.serial_number,
        common_name=common_name)

def export_crl(pem=True):
    builder = CertificateListBuilder(
        const.AUTHORITY_CRL_URL,
        certificate,
        generate_serial()
    )

    # Get revoked certificates from database
    for cert_revoked_doc in db.certificates.find({"status": "revoked"}):
        builder.add_certificate(
            int(cert_revoked_doc["serial"][:-4],16),
            datetime.utcfromtimestamp(cert_revoked_doc["revoked"]).replace(tzinfo=pytz.UTC),
            cert_revoked_doc["revocation_reason"]
        )

    certificate_list = builder.build(private_key)

    if pem:
        return pem_armor_crl(certificate_list)
    return certificate_list.dump()


def delete_request(id, user="root"):

    if not id:
        raise ValueError("No ID specified")

    query = {"_id": ObjectId(id), "status": "csr"}
    doc = db.certificates.find_one(query)

    if not doc:
        logger.info("Signing request with id %s not found" % (
        id))
        raise errors.RequestDoesNotExist

    res = db.certificates.delete_one(query)

    logger.info("Rejected signing request %s %s by %s" % (doc["common_name"],
        id, user))


def sign(profile, skip_notify=False, overwrite=False, signer=None, namespace=const.MACHINE_NAMESPACE, mongo_id=None):
    # TODO: buf is now DER format, convert to PEM just to get POC work
    if mongo_id:
        csr_doc = db.certificates.find_one({"_id": ObjectId(mongo_id)})
        csr = CertificationRequest.load(csr_doc["request_buf"])
        csr_buf_pem = pem.armor("CERTIFICATE REQUEST",csr_doc["request_buf"])
    else:
        raise ValueError("ID missing, what CSR to sign")


    assert isinstance(csr, CertificationRequest)

    csr_pubkey = asymmetric.load_public_key(csr["certification_request_info"]["subject_pk_info"])
    common_name = csr["certification_request_info"]["subject"].native["common_name"].lower()

    assert "." not in common_name  # TODO: correct validation

    common_name = "%s.%s" % (common_name, namespace)

    attachments = [
        (csr_buf_pem, "application/x-pem-file", common_name + ".csr"),
    ]

    revoked_path = None
    overwritten = False

    query = {"common_name": common_name, "status": "signed"}
    prev = db.certificates.find_one(query)

    if prev:
        if overwrite:
            newValue = { "$set": { "status": "revoked", "revoked": datetime.utcnow().replace(tzinfo=pytz.UTC), "revocation_reason": "superseded"} }
            doc = db.certificates.find_one_and_update(query,newValue,return_document=db.return_new)
            overwritten = True
        else:
            raise FileExistsError("Will not overwrite existing certificate")

    profile = config.get("SignatureProfile", profile)["value"]
    builder = CertificateBuilder(cn_to_dn(common_name,
        ou=profile["ou"]), csr_pubkey)
    builder.serial_number = generate_serial()

    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    builder.begin_date = now - const.CLOCK_SKEW_TOLERANCE
    builder.end_date = now + timedelta(days=profile["lifetime"])
    builder.issuer = certificate
    builder.ca = profile["ca"]
    subject_alt_name = profile.get("san")
    if subject_alt_name:
        builder.subject_alt_domains = [subject_alt_name, common_name]
    else:
        builder.subject_alt_domains = [common_name]
    if profile.get("server_auth"):
        builder.extended_key_usage.add("server_auth")
        builder.extended_key_usage.add("ike_intermediate")
    if profile.get("client_auth"):
        builder.extended_key_usage.add("client_auth")
    if not const.AUTHORITY_OCSP_DISABLED:
        builder.ocsp_url = const.AUTHORITY_OCSP_URL
    if const.AUTHORITY_CRL_ENABLED:
        builder.crl_url = const.AUTHORITY_CRL_URL

    end_entity_cert = builder.build(private_key)
    # PEM format cert
    end_entity_cert_buf = asymmetric.dump_certificate(end_entity_cert)

    # Write certificate to database
    # DER format cert
    cert_der_bytes = asymmetric.dump_certificate(end_entity_cert,encoding="der")

    d = {
        "common_name": common_name,
        "status": "signed",
        "disabled": False,
        "serial_number": "%x" % builder.serial_number,
        "signed": builder.begin_date,
        "expires": builder.end_date,
        "cert_buf": cert_der_bytes,
        "profile": profile,
        "distinguished_name": cert_to_dn(end_entity_cert),
        "dns": {
            "fqdn": common_name,
        }
    }

    if subject_alt_name:
        d["dns"]["san"] = subject_alt_name

    if signer:
        user_obj = {}
        user_obj["signature"] = {"username": signer}
        d["user"] = user_obj

    db.certificates.update_one({
        "_id": ObjectId(mongo_id),
    }, {
        "$set": d,
        "$setOnInsert": {
            "created": now,
            "ip": [],
        }
    })

    attachments.append((end_entity_cert_buf, "application/x-pem-file", common_name + ".crt"))
    cert_serial_hex = "%x" % end_entity_cert.serial_number

    # TODO: Copy attributes from revoked certificate

    if not skip_notify:
        mailer.send("certificate-signed.md", **locals())

    return end_entity_cert, end_entity_cert_buf
