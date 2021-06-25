from http.client import HTTPException


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


class PocsuiteMissingMandatoryOptionException(PocsuiteBaseException):
    pass


class PocsuitePluginBaseException(PocsuiteBaseException):
    pass


class PocsuitePluginDorkException(PocsuitePluginBaseException):
    pass


class PocsuiteHeaderTypeException(PocsuiteBaseException):
    pass

class PocsuiteIncompleteRead(HTTPException):
    def __init__(self, partial, expected=None):
        self.args = partial,
        self.partial = partial
        self.expected = expected
    def __repr__(self):
        if self.expected is not None:
            e = ', %i more expected' % self.expected
        else:
            e = ''
        return '%s(%i bytes read%s)' % (self.__class__.__name__,
                                        len(self.partial), e)
    def __str__(self):
        return repr(self)