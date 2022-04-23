class PdaException(Exception):
    pass


class PdaCredentialException(PdaException):
    pass


class PdaAuthException(PdaException):
    pass


class PdaPostException(PdaException):
    pass


class PdaPutException(PdaException):
    pass


class PdaGetException(PdaException):
    pass

class PdaDeleteException(PdaException):
    pass
