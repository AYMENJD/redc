from .exceptions import HTTPError
from .utils import Headers, json_loads


class Response:
    def __init__(
        self,
        status_code: int,
        headers: bytes,
        response: bytes,
        curl_code: int,
        curl_error_message: str,
        raise_for_status: bool = False,
    ):
        """Represents an HTTP response of RedC"""

        self.status_code = status_code
        """HTTP response status code; If the value is ``-1``, it indicates a cURL error occurred"""

        self.headers = None if status_code == -1 else Headers.parse_headers(headers)
        """HTTP response headers"""

        self.__response = response

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
