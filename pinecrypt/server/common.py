
from pinecrypt.server import const
from random import SystemRandom
from time import time_ns

random = SystemRandom()

MAPPING = dict(
  common_name="CN",
  organizational_unit_name="OU",
  organization_name="O"
)


def cert_to_dn(cert):
    d = []
    for key, value in cert["tbs_certificate"]["subject"].native.items():
        if not isinstance(value, list):
            value = [value]
        for comp in value:
            d.append("%s=%s" % (MAPPING[key], comp))
    return ", ".join(d)


def cn_to_dn(common_name, ou=None):
    d = {"common_name": common_name}
    if ou:
        d["organizational_unit_name"] = ou
    if const.AUTHORITY_ORGANIZATION:
        d["organization_name"] = const.AUTHORITY_ORGANIZATION
    return d


def generate_serial():
    return time_ns() << 56 | random.randint(0, 2 ** 56 - 1)
