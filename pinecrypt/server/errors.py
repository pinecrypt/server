
class AuthorityError(Exception):
    pass

class RequestExists(AuthorityError):
    pass

class RequestDoesNotExist(AuthorityError):
    pass

class CertificateDoesNotExist(AuthorityError):
    pass

class TokenDoesNotExist(AuthorityError):
    pass

class FatalError(AuthorityError):
    """
    Exception to be raised when user intervention is required
    """
    pass

class DuplicateCommonNameError(FatalError):
    pass
