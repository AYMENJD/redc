from urllib.parse import urlencode

from .callbacks import StreamCallback
from .redc_ext import RedC
from .response import Response
from .utils import json_dumps, parse_base_url


class Client:
    """RedC client for making HTTP requests"""

    def __init__(
        self,
        base_url: str = None,
        buffer_size: int = 16384,
        force_verbose: bool = None,
        json_encoder=json_dumps,
    ):
        """
        Initialize the RedC client

        Example:
            .. code-block:: python

                >>> client = Client(base_url="https://example.com")
                >>> response = await client.get("/api/data")

        Parameters:
            base_url (``str``, *optional*):
                The base URL for the client. Default is ``None``

            buffer_size (``int``, *optional*):
                The buffer size for libcurl. Must be greater than ``1024`` bytes. Default is ``16384`` (16KB)

            force_verbose (``bool``, *optional*):
                Force verbose output for all requests. Default is ``None``

            json_encoder (``Callable`` , *optional*):
                A callable for encoding JSON data. Default is ``json_dumps``
        """

        assert isinstance(base_url, (str, type(None))), "base_url must be string"
        assert isinstance(buffer_size, int), "buffer_size must be int"
        assert buffer_size >= 1024, "buffer_size must be bigger than 1024 bytes"

        assert isinstance(force_verbose, (bool, type(None))), (
            "force_verbose must be bool or None"
        )

        self.force_verbose = force_verbose

        self.__base_url = (
            None if not isinstance(base_url, str) else parse_base_url(base_url)
        )
        self.__json_encoder = json_encoder
        self.__redc_ext = RedC(buffer_size)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def request(
        self,
        method: str,
        url: str,
        form: dict = None,
        json: dict = None,
        data: dict[str, str] = None,
        files: dict[str, str] = None,
        headers: dict[str, str] = None,
        timeout: float = 30.0,
        connect_timeout: float = 0.0,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        stream_callback: StreamCallback = None,
        verbose: bool = False,
    ):
        """
        Make an HTTP request with the specified method and parameters

        Example:
            .. code-block:: python

                >>> response = await client.request("GET", "/api/data", headers={"Authorization": "Bearer token"})

        Parameters:
            method (``str``):
                The HTTP method to use (e.g., "GET", "POST")

            url (``str``):
                The URL to send the request to or path if ``base_url`` is specified in ``Client``

            form (``dict``, *optional*):
                Form data to send in the request body. Default is ``None``

            json (``dict``, *optional*):
                JSON data to send in the request body. Default is ``None``

            data (``dict[str, str]``, *optional*):
                Multipart form data to send in the request body. Default is ``None``

            files (``dict[str, str]``, *optional*):
                A dictionary specifying files to upload as part of a multipart form request, ``key`` is the form field and ``value`` is string containing the file path

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            timeout (``float``, *optional*):
                The total timeout for the request in seconds. Default is ``30.0``

            connect_timeout (``float``, *optional*):
                The connection timeout for the request in seconds. Default is ``0.0``

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

        Returns:
            :class:`redc.Response`
        """

        if stream_callback is not None:
            if not isinstance(stream_callback, StreamCallback):
                raise TypeError("stream_callback must be of type StreamCallback")

            stream_callback = stream_callback.callback

        if form is not None:
            if isinstance(form, dict):
                form = urlencode(form)
            else:
                raise TypeError("form must be of type dict[str, str]")

        if json is not None:
            if isinstance(json, dict):
                json = self.__json_encoder(json)
                if headers is None:
                    headers = {}
                headers["Content-Type"] = "application/json"
            else:
                raise TypeError("json must be of type dict[str, str]")

        if data is not None:
            if not isinstance(data, dict):
                raise TypeError("data must be of type dict[str, str]")

        if files is not None:
            if not isinstance(files, dict):
                raise TypeError("files must be of type dict[str, str]")

        if timeout <= 0:
            raise ValueError("timeout must be greater than 0")

        if connect_timeout < 0:
            raise ValueError("connect_timeout must be 0 or greater")
        elif connect_timeout > timeout:
            raise ValueError("connect_timeout must be less than `timeout` argument")

        if headers is not None:
            if isinstance(headers, dict):
                headers = [f"{k}: {v}" for k, v in headers.items()]
            else:
                raise TypeError("headers must be of type dict[str, str]")

        if self.__base_url:
            url = f"{self.__base_url}{url.lstrip('/')}"

        return Response(
            *(
                await self.__redc_ext.request(
                    method=method,
                    url=url,
                    raw_data=form or json or "",
                    data=data,
                    files=files,
                    headers=headers,
                    timeout_ms=int(timeout * 1000),
                    connect_timeout_ms=int(connect_timeout * 1000),
                    allow_redirect=allow_redirect,
                    proxy_url=proxy_url,
                    verify=verify,
                    stream_callback=stream_callback,
                    verbose=self.force_verbose or verbose,
                )
            )
        )

    async def get(
        self,
        url: str,
        headers: dict[str, str] = None,
        timeout: float = 30.0,
        connect_timeout: float = 0.0,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        stream_callback: StreamCallback = None,
        verbose: bool = False,
    ):
        """
        Make a GET request

        Example:
            .. code-block:: python

                >>> response = await client.get("/api/data", headers={"Authorization": "Bearer token"})

        Parameters:
            url (``str``):
                The URL to send the GET request to or path if ``base_url`` is specified in ``Client``

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            timeout (``float``, *optional*):
                The total timeout for the request in seconds. Default is ``30.0``

            connect_timeout (``float``, *optional*):
                The connection timeout for the request in seconds. Default is ``0.0``

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

        Returns:
            :class:`redc.Response`
        """
        return await self.request(
            method="GET",
            url=url,
            headers=headers,
            timeout=timeout,
            connect_timeout=connect_timeout,
            allow_redirect=allow_redirect,
            proxy_url=proxy_url,
            verify=verify,
            stream_callback=stream_callback,
            verbose=self.force_verbose or verbose,
        )

    async def head(
        self,
        url: str,
        headers: dict[str, str] = None,
        timeout: float = 30.0,
        connect_timeout: float = 0.0,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        verbose: bool = False,
    ):
        """
        Make a HEAD request

        Example:
            .. code-block:: python

                >>> response = await client.head("/api/data", headers={"Authorization": "Bearer token"})

        Parameters:
            url (``str``):
                The URL to send the HEAD request to or path if ``base_url`` is specified in ``Client``

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            timeout (``float``, *optional*):
                The total timeout for the request in seconds. Default is ``30.0``

            connect_timeout (``float``, *optional*):
                The connection timeout for the request in seconds. Default is ``0.0``

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

        Returns:
            :class:`redc.Response`
        """
        return await self.request(
            method="HEAD",
            url=url,
            headers=headers,
            timeout=timeout,
            connect_timeout=connect_timeout,
            allow_redirect=allow_redirect,
            proxy_url=proxy_url,
            verify=verify,
            verbose=self.force_verbose or verbose,
        )

    async def post(
        self,
        url: str,
        form: dict = None,
        json: dict = None,
        data: dict[str, str] = None,
        files: dict[str, str] = None,
        headers: dict[str, str] = None,
        timeout: float = 30.0,
        connect_timeout: float = 0.0,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        stream_callback: StreamCallback = None,
        verbose: bool = False,
    ):
        """
        Make a POST request

        Example:
            .. code-block:: python

                >>> response = await client.post(
                ...     "/api/data",
                ...     json={"key": "value"},
                ...     headers={"Authorization": "Bearer token"}
                ... )

        Parameters:
            url (``str``):
                The URL to send the POST request to or path if ``base_url`` is specified in ``Client``

            form (``dict``, *optional*):
                Form data to send in the request body. Default is ``None``

            json (``dict``, *optional*):
                JSON data to send in the request body. Default is ``None``

            data (``dict[str, str]``, *optional*):
                Multipart form data to send in the request body. Default is ``None``

            files (``dict[str, str]``, *optional*):
                A dictionary specifying files to upload as part of a multipart form request, ``key`` is the form field and ``value`` is string containing the file path

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            timeout (``float``, *optional*):
                The total timeout for the request in seconds. Default is ``30.0``

            connect_timeout (``float``, *optional*):
                The connection timeout for the request in seconds. Default is ``0.0``

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

        Returns:
            :class:`redc.Response`
        """
        return await self.request(
            method="POST",
            url=url,
            form=form,
            json=json,
            data=data,
            files=files,
            headers=headers,
            timeout=timeout,
            connect_timeout=connect_timeout,
            allow_redirect=allow_redirect,
            proxy_url=proxy_url,
            verify=verify,
            stream_callback=stream_callback,
            verbose=self.force_verbose or verbose,
        )

    async def put(
        self,
        url: str,
        form: dict = None,
        json: dict = None,
        data: dict[str, str] = None,
        files: dict[str, str] = None,
        headers: dict[str, str] = None,
        timeout: float = 30.0,
        connect_timeout: float = 0.0,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        stream_callback: StreamCallback = None,
        verbose: bool = False,
    ):
        """
        Make a PUT request

        Example:
            .. code-block:: python

                >>> response = await client.put(
                ...     "/api/data/1",
                ...     json={"key": "new_value"},
                ...     headers={"Authorization": "Bearer token"}
                ... )

        Parameters:
            url (``str``):
                The URL to send the PUT request to or path if ``base_url`` is specified in ``Client``

            form (``dict``, *optional*):
                Form data to send in the request body. Default is ``None``

            json (``dict``, *optional*):
                JSON data to send in the request body. Default is ``None``

            data (``dict[str, str]``, *optional*):
                Multipart form data to send in the request body. Default is ``None``

            files (``dict[str, str]``, *optional*):
                A dictionary specifying files to upload as part of a multipart form request, ``key`` is the form field and ``value`` is string containing the file path

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            timeout (``float``, *optional*):
                The total timeout for the request in seconds. Default is ``30.0``

            connect_timeout (``float``, *optional*):
                The connection timeout for the request in seconds. Default is ``0.0``

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

        Returns:
            :class:`redc.Response`
        """
        return await self.request(
            method="PUT",
            url=url,
            form=form,
            json=json,
            data=data,
            files=files,
            headers=headers,
            timeout=timeout,
            connect_timeout=connect_timeout,
            allow_redirect=allow_redirect,
            proxy_url=proxy_url,
            verify=verify,
            stream_callback=stream_callback,
            verbose=self.force_verbose or verbose,
        )

    async def patch(
        self,
        url: str,
        form: dict = None,
        json: dict = None,
        data: dict[str, str] = None,
        files: dict[str, str] = None,
        headers: dict[str, str] = None,
        timeout: float = 30.0,
        connect_timeout: float = 0.0,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        stream_callback: StreamCallback = None,
        verbose: bool = False,
    ):
        """
        Make a PATCH request

        Example:
            .. code-block:: python

                >>> response = await client.patch(
                ...     "/api/data/1",
                ...     json={"key": "updated_value"},
                ...     headers={"Authorization": "Bearer token"}
                ... )

        Parameters:
            url (``str``):
                The URL to send the PATCH request to or path if ``base_url`` is specified in ``Client``

            form (``dict``, *optional*):
                Form data to send in the request body. Default is ``None``

            json (``dict``, *optional*):
                JSON data to send in the request body. Default is ``None``

            data (``dict[str, str]``, *optional*):
                Multipart form data to send in the request body. Default is ``None``

            files (``dict[str, str]``, *optional*):
                A dictionary specifying files to upload as part of a multipart form request, ``key`` is the form field and ``value`` is string containing the file path

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            timeout (``float``, *optional*):
                The total timeout for the request in seconds. Default is ``30.0``

            connect_timeout (``float``, *optional*):
                The connection timeout for the request in seconds. Default is ``0.0``

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

        Returns:
            :class:`redc.Response`
        """

        return await self.request(
            method="PATCH",
            url=url,
            form=form,
            json=json,
            data=data,
            files=files,
            headers=headers,
            timeout=timeout,
            connect_timeout=connect_timeout,
            allow_redirect=allow_redirect,
            proxy_url=proxy_url,
            verify=verify,
            stream_callback=stream_callback,
            verbose=self.force_verbose or verbose,
        )

    async def delete(
        self,
        url: str,
        headers: dict[str, str] = None,
        timeout: float = 30.0,
        connect_timeout: float = 0.0,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        stream_callback: StreamCallback = None,
        verbose: bool = False,
    ):
        """
        Make a DELETE request

        Example:
            .. code-block:: python

                >>> response = await client.delete("/api/data/1", headers={"Authorization": "Bearer token"})

        Parameters:
            url (``str``):
                The URL to send the DELETE request to or path if ``base_url`` is specified in ``Client``

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            timeout (``float``, *optional*):
                The total timeout for the request in seconds. Default is ``30.0``

            connect_timeout (``float``, *optional*):
                The connection timeout for the request in seconds. Default is ``0.0``

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

        Returns:
            :class:`redc.Response`
        """
        return await self.request(
            method="DELETE",
            url=url,
            headers=headers,
            timeout=timeout,
            connect_timeout=connect_timeout,
            allow_redirect=allow_redirect,
            proxy_url=proxy_url,
            verify=verify,
            stream_callback=stream_callback,
            verbose=self.force_verbose or verbose,
        )

    async def options(
        self,
        url: str,
        headers: dict[str, str] = None,
        timeout: float = 30.0,
        connect_timeout: float = 0.0,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        verbose: bool = False,
    ):
        """
        Make an OPTIONS request

        Example:
            .. code-block:: python

                >>> response = await client.options("/api/data", headers={"Authorization": "Bearer token"})

        Parameters:
            url (``str``):
                The URL to send the OPTIONS request to or path if ``base_url`` is specified in ``Client``

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            timeout (``float``, *optional*):
                The total timeout for the request in seconds. Default is ``30.0``

            connect_timeout (``float``, *optional*):
                The connection timeout for the request in seconds. Default is ``0.0``

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

        Returns:
            :class:`redc.Response`
        """
        return await self.request(
            method="OPTIONS",
            url=url,
            headers=headers,
            timeout=timeout,
            connect_timeout=connect_timeout,
            allow_redirect=allow_redirect,
            proxy_url=proxy_url,
            verify=verify,
            verbose=self.force_verbose or verbose,
        )

    async def close(self):
        """
        Close the RedC client and free up resources.

        This method must be called when the client is no longer needed to avoid memory leaks
        or unexpected behavior
        """
        self.__redc_ext.close()
