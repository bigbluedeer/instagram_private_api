# flake8: noqa

from .client import Client
from .common import ClientDeprecationWarning
from .compatpatch import ClientCompatPatch
from .errors import (
    ClientError, ClientLoginError, ClientCookieExpiredError,
    ClientConnectionError, ClientForbiddenError,
    ClientThrottledError, ClientBadRequestError,
)

__version__ = '1.6.0'
