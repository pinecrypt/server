import hashlib
from pinecrypt.server import authority, const, config
from pinecrypt.server.common import cert_to_dn
from pinecrypt.server.decorators import serialize
from pinecrypt.server.mongolog import LogHandler

logger = LogHandler()

# Algorithm mappings for pki.js
SIGNATURE_ALGO_MAPPING = {
    "rsassa_pkcs1v15": "RSASSA-PKCS1-v1_5",
    "ecdsa": "ECDSA",
}

HASH_ALGO_MAPPING = {
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
}

CURVE_NAME_MAPPING = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
}

class BootstrapResource(object):
    @serialize
    def on_get(self, req, resp):
        """
        Return publicly accessible info unlike /api/session
        """
        return dict(
            hostname=const.FQDN,
            namespace=const.AUTHORITY_NAMESPACE,
            replicas=[doc["common_name"] for doc in authority.list_replicas()],
            globals=list(config.get_all("Globals")),
            openvpn=dict(
                tls_version_min=config.get("Globals", "OPENVPN_TLS_VERSION_MIN")["value"],
                tls_ciphersuites=config.get("Globals", "OPENVPN_TLS_CIPHERSUITES")["value"],
                tls_cipher=config.get("Globals", "OPENVPN_TLS_CIPHER")["value"],
                cipher=config.get("Globals", "OPENVPN_CIPHER")["value"],
                auth=config.get("Globals", "OPENVPN_AUTH")["value"]
            ),
            strongswan=dict(
                dhgroup=config.get("Globals", "STRONGSWAN_DHGROUP")["value"],
                ike=config.get("Globals", "STRONGSWAN_IKE")["value"],
                esp=config.get("Globals", "STRONGSWAN_ESP")["value"],
            ),
            webcrypto=dict(
                hash_algorithm=HASH_ALGO_MAPPING[authority.certificate.hash_algo],
                signature_algorithm=SIGNATURE_ALGO_MAPPING[authority.certificate.signature_algo],
                curve=CURVE_NAME_MAPPING.get(const.CURVE_NAME),
            ),
            certificate=dict(
                key_size=const.KEY_SIZE,
                curve=const.CURVE_NAME,
                hash_algorithm=authority.certificate.hash_algo,
                signature_algorithm=authority.certificate.signature_algo,
                algorithm=authority.public_key.algorithm,
                common_name=authority.certificate.subject.native["common_name"],
                distinguished_name=cert_to_dn(authority.certificate),
                md5sum=hashlib.md5(authority.certificate_buf).hexdigest(),
                blob=authority.certificate_buf.decode("ascii"),
                organization=authority.certificate["tbs_certificate"]["subject"].native.get("organization_name"),
                signed=authority.certificate["tbs_certificate"]["validity"]["not_before"].native.replace(tzinfo=None),
                expires=authority.certificate["tbs_certificate"]["validity"]["not_after"].native.replace(tzinfo=None)
            ),
            user_enrollment_allowed=const.USER_ENROLLMENT_ALLOWED,
            user_multiple_certificates=const.USER_MULTIPLE_CERTIFICATES,
        )
