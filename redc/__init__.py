from .callbacks import StreamCallback
from .client import Client
from .codes import HTTPStatus
from .exceptions import HTTPError
from .response import Response
from . import utils

__all__ = [
    "Client",
    "Response",
    "HTTPError",
    "HTTPStatus",
    "StreamCallback",
    "utils",
]

__version__ = "0.1.0.dev3"
__copyright__ = "Copyright (c) 2025 RedC, AYMENJD"
__license__ = "MIT License"

VERSION = __version__
