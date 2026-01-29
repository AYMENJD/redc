from .exceptions import HTTPError
from .utils import Headers, json_loads


class Response:
    def __init__(
        self,
        status_code: int,
        headers: bytes,
        response: bytes,
        url: str,
        elapsed: float,
        curl_code: int,
        curl_error_message: str,
        raise_for_status: bool = False,
    ):
        """Represents an HTTP response of RedC"""

        self.status_code = status_code
        """HTTP response status code; If the value is ``-1``, it indicates a cURL error occurred"""

        self.headers = None
        """HTTP response headers"""
        self.history = None
        """History of requests that led to this response"""

        if headers:
            self.history = Headers.parse_history(headers)
            self.headers = self.history.pop(-1).headers

        self.__response = response

        self.url = url
        """Final effective URL used for the request"""
        self.elapsed_microseconds = elapsed
        """Elapsed time in microseconds"""
        self.elapsed = elapsed / 1_000_000
        """Elapsed time in seconds"""

        self.curl_code = curl_code
        """CURL return code"""
        self.curl_error_message = curl_error_message
        """CURL error message"""

        if raise_for_status:
            self.raise_for_status()

    @property
    def content(self) -> bytes:
        """Returns the raw response content"""
        return self.__response

    @property
    def ok(self):
        """Checks if the request is successful and with no errors"""
        return bool(self)

    @property
    def is_redirect(self) -> bool:
        """True if this response is a redirect"""

        if self.status_code == -1 or not self.headers:
            return False

        return (
            self.status_code in (300, 301, 302, 303, 307, 308)
            and "location" in self.headers
        )

    @property
    def is_permanent_redirect(self) -> bool:
        """True if this response is a permanent redirect"""

        if self.status_code == -1:
            return False

        return self.status_code in (301, 308)

    def text(self, encoding: str = "utf-8"):
        """Decodes the response content into a string

        Parameters:
            encoding (``str``, *optional*):
                The encoding to use for decoding. Default is "utf-8"

        Returns:
            ``str``
        """

        if self.status_code != -1:
            return self.__response.decode(encoding=encoding)

    def json(self):
        """Parses the response content as JSON"""
        if self.status_code != -1:
            return json_loads(self.__response)

    def raise_for_status(self):
        """Raises an HTTPError if the response status indicates an error"""
        if self.status_code == -1 or (400 <= self.status_code <= 599):
            raise HTTPError(self.status_code, self.curl_code, self.curl_error_message)

    def __bool__(self):
        return self.status_code != -1 and 200 <= self.status_code <= 299
