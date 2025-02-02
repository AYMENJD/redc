from ..codes import HTTPStatus


class HTTPError(Exception):
    """Exception raised for HTTP and CURL-related errors"""

    def __init__(self, status_code: int, curl_error_code: int, curl_error_message: str):
        self.status_code = status_code
        self.curl_error_code = curl_error_code
        self.curl_error_message = curl_error_message
        self.is_curl_error = status_code == -1

        if self.is_curl_error:
            super().__init__(f"CURL {self.curl_error_code}: {self.curl_error_message}")
        else:
            short_description = HTTPStatus.get_description(self.status_code)

            super().__init__(
                self.status_code
                if not short_description
                else f"{self.status_code} - {short_description}"
            )
