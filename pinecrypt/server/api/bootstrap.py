import hashlib
import logging
from pinecrypt.server import authority, const, config
from pinecrypt.server.common import cert_to_dn
from pinecrypt.server.decorators import serialize

logger = logging.getLogger(__name__)

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
            certificate=dict(
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
