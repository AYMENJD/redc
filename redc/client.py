import asyncio
from typing import BinaryIO, Union
from urllib.parse import urlencode

import redc

from .callbacks import ProgressCallback, StreamCallback
from .redc_ext import RedC
from .response import Response
from .utils import Headers, json_dumps, parse_base_url, get_fsize


class Client:
    """RedC client for making HTTP requests"""

    def __init__(
        self,
        base_url: str = None,
        buffer_size: int = 16384,
        headers: dict = None,
        timeout: tuple = (30.0, 0.0),
        ca_cert_path: str = None,
        force_verbose: bool = None,
        raise_for_status: bool = False,
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

            headers (``dict``, *optional*):
                Headers to include in every request. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of `(total_timeout, connect_timeout)` in seconds to include in every request. Default is ``(30.0, 0.0)``

            ca_cert_path (``str``, *optional*):
                Path to a CA certificate bundle file for SSL/TLS verification. Default is ``None``

            force_verbose (``bool``, *optional*):
                Force verbose output for all requests. Default is ``None``

            raise_for_status (``bool``, *optional*):
                If ``True``, automatically raises an :class:`redc.HTTPError` for responses with HTTP status codes
                indicating an error (i.e., 4xx or 5xx) or for CURL errors (e.g., network issues, timeouts). Default is ``False``

            json_encoder (``Callable`` , *optional*):
                A callable for encoding JSON data. Default is :class:`redc.utils.json_dumps`
        """

        assert isinstance(base_url, (str, type(None))), "base_url must be string"
        assert isinstance(buffer_size, int), "buffer_size must be int"
        assert isinstance(ca_cert_path, (str, type(None))), (
            "ca_cert_path must be string"
        )
        assert isinstance(timeout, tuple) and len(timeout) == 2, (
            "timeout must be a tuple of (total_timeout, connect_timeout)"
        )
        assert isinstance(force_verbose, (bool, type(None))), (
            "force_verbose must be bool or None"
        )
        assert isinstance(raise_for_status, bool), "raise_for_status must be bool"

        assert buffer_size >= 1024, "buffer_size must be bigger than 1024 bytes"

        self.force_verbose = force_verbose
        self.raise_for_status = raise_for_status

        self.__base_url = (
            parse_base_url(base_url) if isinstance(base_url, str) else None
        )
        self.__default_headers = Headers(headers if isinstance(headers, dict) else {})
        self.__timeout = timeout
        self.__ca_cert_path = ca_cert_path if isinstance(ca_cert_path, str) else ""
        self.__json_encoder = json_encoder
        self.__loop = asyncio.get_event_loop()
        self.__redc_ext = RedC(buffer_size)

        self.__set_default_headers()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    @property
    def is_running(self):
        """Checks if RedC is currently running

        Returns:
            ``bool``: ``True`` if RedC is running, False otherwise
        """

        return self.__redc_ext.is_running()

    @property
    def default_headers(self):
        """Returns default headers that are set on all requests"""

        return self.__default_headers

    async def request(
        self,
        method: str,
        url: str,
        form: dict = None,
        json: dict = None,
        data: Union[dict[str, str], BinaryIO] = None,
        files: dict[str, str] = None,
        headers: dict[str, str] = None,
        timeout: tuple = None,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        stream_callback: StreamCallback = None,
        progress_callback: ProgressCallback = None,
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

            data (``dict[str, str]`` || ``BinaryIO``, *optional*):
                Multipart form data dict or a binary file-like object (requires ``readinto``). Default is ``None``

            files (``dict[str, str]``, *optional*):
                A dictionary specifying files to upload as part of a multipart form request, ``key`` is the form field and ``value`` is string containing the file path

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            progress_callback (:class:`redc.ProgressCallback`, *optional*):
                Callback for tracking upload and download progress. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

        Returns:
            :class:`redc.Response`
        """

        if stream_callback is not None:
            if not isinstance(stream_callback, StreamCallback):
                raise TypeError("stream_callback must be of type StreamCallback")

            stream_callback = stream_callback.callback

        if progress_callback is not None:
            if not isinstance(progress_callback, ProgressCallback):
                raise TypeError("progress_callback must be of type ProgressCallback")

            progress_callback = progress_callback.callback

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

        file_stream = None
        file_size = 0
        if data is not None:
            if hasattr(data, "readinto"):
                file_stream = data
                file_size = get_fsize(file_stream)
                data = None
            elif not isinstance(data, dict):
                raise TypeError(
                    "data must be either dict[str, str] or a file-like object with readinto method"
                )

        if files is not None:
            if not isinstance(files, dict):
                raise TypeError("files must be of type dict[str, str]")

        timeout, connect_timeout = timeout if timeout is not None else self.__timeout

        if timeout <= 0:
            raise ValueError("timeout must be greater than 0")

        if connect_timeout < 0:
            raise ValueError("connect_timeout must be 0 or greater")
        elif connect_timeout > timeout:
            raise ValueError("connect_timeout must be less than `timeout` argument")

        if headers is not None:
            if isinstance(headers, dict):
                headers = {
                    **self.__default_headers,
                    **{k.lower(): v for k, v in headers.items()},
                }
                headers = [f"{k}: {v}" for k, v in headers.items()]
            else:
                raise TypeError("headers must be of type dict[str, str]")
        else:
            headers = [f"{k}: {v}" for k, v in self.__default_headers.items()]

        if self.__base_url:
            url = f"{self.__base_url}{url.lstrip('/')}"

        return Response(
            *(
                await self.__redc_ext.request(
                    method=method,
                    url=url,
                    raw_data=form or json or "",
                    file_stream=file_stream,
                    file_size=file_size,
                    data=data,
                    files=files,
                    headers=headers,
                    timeout_ms=int(timeout * 1000),
                    connect_timeout_ms=int(connect_timeout * 1000),
                    allow_redirect=allow_redirect,
                    proxy_url=proxy_url,
                    verify=verify,
                    ca_cert_path=self.__ca_cert_path,
                    stream_callback=stream_callback,
                    progress_callback=progress_callback,
                    verbose=self.force_verbose or verbose,
                )
            ),
            raise_for_status=self.raise_for_status,
        )

    async def get(
        self,
        url: str,
        headers: dict[str, str] = None,
        timeout: tuple = None,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        stream_callback: StreamCallback = None,
        progress_callback: ProgressCallback = None,
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

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            progress_callback (:class:`redc.ProgressCallback`, *optional*):
                Callback for tracking upload and download progress. Default is ``None``

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
            allow_redirect=allow_redirect,
            proxy_url=proxy_url,
            verify=verify,
            stream_callback=stream_callback,
            progress_callback=progress_callback,
            verbose=self.force_verbose or verbose,
        )

    async def head(
        self,
        url: str,
        headers: dict[str, str] = None,
        timeout: tuple = None,
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

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

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
        data: Union[dict[str, str], BinaryIO] = None,
        files: dict[str, str] = None,
        headers: dict[str, str] = None,
        timeout: tuple = None,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        stream_callback: StreamCallback = None,
        progress_callback: ProgressCallback = None,
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

            data (``dict[str, str]`` || ``BinaryIO``, *optional*):
                Multipart form data dict or a binary file-like object (requires ``readinto``). Default is ``None``

            files (``dict[str, str]``, *optional*):
                A dictionary specifying files to upload as part of a multipart form request, ``key`` is the form field and ``value`` is string containing the file path

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            progress_callback (:class:`redc.ProgressCallback`, *optional*):
                Callback for tracking upload and download progress. Default is ``None``

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
            allow_redirect=allow_redirect,
            proxy_url=proxy_url,
            verify=verify,
            stream_callback=stream_callback,
            progress_callback=progress_callback,
            verbose=self.force_verbose or verbose,
        )

    async def put(
        self,
        url: str,
        form: dict = None,
        json: dict = None,
        data: Union[dict[str, str], BinaryIO] = None,
        files: dict[str, str] = None,
        headers: dict[str, str] = None,
        timeout: tuple = None,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        stream_callback: StreamCallback = None,
        progress_callback: ProgressCallback = None,
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

            data (``dict[str, str]`` || ``BinaryIO``, *optional*):
                Multipart form data dict or a binary file-like object (requires ``readinto``). Default is ``None``

            files (``dict[str, str]``, *optional*):
                A dictionary specifying files to upload as part of a multipart form request, ``key`` is the form field and ``value`` is string containing the file path

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            progress_callback (:class:`redc.ProgressCallback`, *optional*):
                Callback for tracking upload and download progress. Default is ``None``

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
            allow_redirect=allow_redirect,
            proxy_url=proxy_url,
            verify=verify,
            stream_callback=stream_callback,
            progress_callback=progress_callback,
            verbose=self.force_verbose or verbose,
        )

    async def patch(
        self,
        url: str,
        form: dict = None,
        json: dict = None,
        data: Union[dict[str, str], BinaryIO] = None,
        files: dict[str, str] = None,
        headers: dict[str, str] = None,
        timeout: tuple = None,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        stream_callback: StreamCallback = None,
        progress_callback: ProgressCallback = None,
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

            data (``dict[str, str]`` || ``BinaryIO``, *optional*):
                Multipart form data dict or a binary file-like object (requires ``readinto``). Default is ``None``

            files (``dict[str, str]``, *optional*):
                A dictionary specifying files to upload as part of a multipart form request, ``key`` is the form field and ``value`` is string containing the file path

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            progress_callback (:class:`redc.ProgressCallback`, *optional*):
                Callback for tracking upload and download progress. Default is ``None``

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
            allow_redirect=allow_redirect,
            proxy_url=proxy_url,
            verify=verify,
            stream_callback=stream_callback,
            progress_callback=progress_callback,
            verbose=self.force_verbose or verbose,
        )

    async def delete(
        self,
        url: str,
        headers: dict[str, str] = None,
        timeout: tuple = None,
        allow_redirect: bool = True,
        proxy_url: str = "",
        verify: bool = True,
        stream_callback: StreamCallback = None,
        progress_callback: ProgressCallback = None,
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

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirect (``bool``, *optional*):
                Whether to allow redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy URL to use for the request

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            progress_callback (:class:`redc.ProgressCallback`, *optional*):
                Callback for tracking upload and download progress. Default is ``None``

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
            allow_redirect=allow_redirect,
            proxy_url=proxy_url,
            verify=verify,
            stream_callback=stream_callback,
            progress_callback=progress_callback,
            verbose=self.force_verbose or verbose,
        )

    async def options(
        self,
        url: str,
        headers: dict[str, str] = None,
        timeout: tuple = None,
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

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

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

        return await self.__loop.run_in_executor(None, self.__redc_ext.close)

    def __set_default_headers(self):
        if "user-agent" not in self.__default_headers:
            self.__default_headers["user-agent"] = f"redc/{redc.__version__}"

        if "connection" not in self.__default_headers:
            self.__default_headers["connection"] = "keep-alive"
