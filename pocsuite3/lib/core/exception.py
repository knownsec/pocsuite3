

class PocsuiteBaseException(Exception):
    pass


class PocsuiteUserQuitException(PocsuiteBaseException):
    pass


class PocsuiteShellQuitException(PocsuiteBaseException):
    pass


class PocsuiteDataException(PocsuiteBaseException):
    pass


class PocsuiteGenericException(PocsuiteBaseException):
    pass


class PocsuiteSystemException(PocsuiteBaseException):
    pass


class PocsuiteFilePathException(PocsuiteBaseException):
    pass


class PocsuiteConnectionException(PocsuiteBaseException):
    pass


class PocsuiteThreadException(PocsuiteBaseException):
    pass


class PocsuiteValueException(PocsuiteBaseException):
    pass


class PocsuiteMissingPrivileges(PocsuiteBaseException):
    pass


class PocsuiteSyntaxException(PocsuiteBaseException):
    pass


class PocsuiteValidationException(PocsuiteBaseException):
    pass