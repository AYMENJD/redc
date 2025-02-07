from .callbacks import StreamCallback, ProgressCallback
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
    "ProgressCallback",
    "utils",
]

__version__ = "0.1.1.dev2"
__copyright__ = "Copyright (c) 2025 RedC, AYMENJD"
__license__ = "MIT License"

VERSION = __version__
