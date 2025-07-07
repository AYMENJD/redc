from . import utils
from .callbacks import ProgressCallback, StreamCallback
from .client import Client
from .codes import HTTPStatus
from .exceptions import HTTPError
from .response import Response

__all__ = [
    "utils",
    "ProgressCallback",
    "StreamCallback",
    "Client",
    "HTTPStatus",
    "HTTPError",
    "Response",
]

__version__ = "0.1.8"
__copyright__ = "Copyright (c) 2025 RedC, AYMENJD"
__license__ = "MIT License"

VERSION = __version__
