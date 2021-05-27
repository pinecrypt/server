
import click
import ldap
import ldap.filter
import ldap.sasl
import os
from pinecrypt.server import const

class User(object):
    def __init__(self, username, mail, given_name="", surname=""):
        self.name = username
        self.mail = mail
        self.given_name = given_name
        self.surname = surname

    def format(self):
        if self.given_name or self.surname:
            return " ".join([j for j in [self.given_name, self.surname] if j]), "<%s>" % self.mail
        else:
            return None, self.mail

    def __repr__(self):
        return " ".join([j for j in self.format() if j])

    def __hash__(self):
        return hash(self.mail)

    def __eq__(self, other):
        if other == None:
            return False
        assert isinstance(other, User), "%s is not instance of User" % repr(other)
        return self.mail == other.mail

    def is_admin(self):
        if not hasattr(self, "_is_admin"):
            self._is_admin = self.objects.is_admin(self)
        return self._is_admin

    class DoesNotExist(Exception):
        pass


class DirectoryConnection(object):
    def __enter__(self):
        if const.LDAP_CA_CERT and not os.path.exists(const.LDAP_CA_CERT):
            raise FileNotFoundError(const.LDAP_CA_CERT)
        if const.LDAP_BIND_DN and const.LDAP_BIND_PASSWORD:
            self.conn = ldap.initialize(const.LDAP_ACCOUNTS_URI, bytes_mode=False)
            self.conn.simple_bind_s(const.LDAP_BIND_DN, const.LDAP_BIND_PASSWORD)
        else:
            if not os.path.exists(const.LDAP_GSSAPI_CRED_CACHE):
                raise ValueError("Ticket cache at %s not initialized, unable to "
                    "authenticate with computer account against LDAP server!" % const.LDAP_GSSAPI_CRED_CACHE)
            os.environ["KRB5CCNAME"] = const.LDAP_GSSAPI_CRED_CACHE
            self.conn = ldap.initialize(const.LDAP_ACCOUNTS_URI, bytes_mode=False)
            self.conn.set_option(ldap.OPT_REFERRALS, 0)
            click.echo("Connecting to %s using Kerberos ticket cache from %s" %
                (const.LDAP_ACCOUNTS_URI, const.LDAP_GSSAPI_CRED_CACHE))
            self.conn.sasl_interactive_bind_s('', ldap.sasl.gssapi())

        return self.conn

    def __exit__(self, type, value, traceback):
        self.conn.unbind_s()


class ActiveDirectoryUserManager(object):
    def get(self, dirty_username):
        username = ldap.filter.escape_filter_chars(dirty_username)

        with DirectoryConnection() as conn:
            ft = const.LDAP_USER_FILTER % username
            attribs = "cn", "givenName", "sn", const.LDAP_MAIL_ATTRIBUTE, "userPrincipalName"
            r = conn.search_s(const.LDAP_BASE, 2, ft, attribs)
            for dn, entry in r:
                if not dn:
                    continue
                if entry.get("givenname") and entry.get("sn"):
                    given_name, = entry.get("givenName")
                    surname, = entry.get("sn")
                else:
                    cn, = entry.get("cn")
                    if b" " in cn:
                        given_name, surname = cn.split(b" ", 1)
                    else:
                        given_name, surname = cn, b""

                mail, = entry.get(const.LDAP_MAIL_ATTRIBUTE) or ((username + "@" + const.DOMAIN).encode("ascii"),)
                return User(username, mail.decode("ascii"),
                    given_name.decode("utf-8"), surname.decode("utf-8"))
            raise User.DoesNotExist("User %s does not exist" % username)

    def filter(self, ft):
        with DirectoryConnection() as conn:
            attribs = "givenName", "surname", "samaccountname", "cn", const.LDAP_MAIL_ATTRIBUTE, "userPrincipalName"
            r = conn.search_s(const.LDAP_BASE, 2, ft, attribs)
            for dn,entry in r:
                if not dn:
                    continue
                username, = entry.get("sAMAccountName")
                cn, = entry.get("cn")
                mail, = entry.get(const.LDAP_MAIL_ATTRIBUTE) or entry.get("userPrincipalName") or (username + b"@" + const.DOMAIN.encode("ascii"),)
                if entry.get("givenName") and entry.get("sn"):
                    given_name, = entry.get("givenName")
                    surname, = entry.get("sn")
                else:
                    cn, = entry.get("cn")
                    if b" " in cn:
                        given_name, surname = cn.split(b" ", 1)
                    else:
                        given_name, surname = cn, b""
                yield User(username.decode("utf-8"), mail.decode("utf-8"),
                    given_name.decode("utf-8"), surname.decode("utf-8"))

    def filter_admins(self):
        """
        Return admin User objects
        """
        return self.filter(const.LDAP_ADMIN_FILTER % "*")

    def all(self):
        """
        Return all valid User objects
        """
        return self.filter(ft=const.LDAP_USER_FILTER % "*")

    def is_admin(self, user):
        with DirectoryConnection() as conn:
            ft = const.LDAP_ADMIN_FILTER % user.name
            r = conn.search_s(const.LDAP_BASE, 2, ft, ["cn"])
            for dn, entry in r:
                if not dn:
                    continue
                return True
            return False

User.objects = ActiveDirectoryUserManager()
