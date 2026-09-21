import asyncio
from functools import lru_cache
from typing import BinaryIO, Callable, Literal, Union

import trustifi

import redc

from .callbacks import ProgressCallback, StreamCallback
from .redc_ext import RedC
from .response import Response
from .utils import Headers, json_dumps, parse_base_url

_SSL_VERSIONS = ("default", "1.0", "1.1", "1.2", "1.3")
_SSL_RANK = {"1.0": 1, "1.1": 2, "1.2": 3, "1.3": 4}
_IP_VERSIONS = ("any", "4", "6")


def _check_tls_version(name, value):
    assert isinstance(value, str), f"{name} must be string"
    assert value in _SSL_VERSIONS, (
        f"{name} must be one of 'default', '1.0', '1.1', '1.2', '1.3'"
    )


def _check_tls_range(tls_version, tls_version_max):
    if tls_version == "default" or tls_version_max == "default":
        return
    if _SSL_RANK[tls_version] > _SSL_RANK[tls_version_max]:
        raise ValueError("tls_version must be less than or equal to tls_version_max")


def _check_ip_version(value):
    assert isinstance(value, str), "ip_version must be string"
    assert value in _IP_VERSIONS, "ip_version must be one of 'any', '4', '6'"


class Client:
    """RedC client for making HTTP requests"""

    def __init__(
        self,
        base_url: str = None,
        read_buffer_size: int = 16384,
        headers: dict = None,
        persist_cookies: bool = False,
        http_version: Literal["auto", "1", "1.1", "2", "3"] = "3",
        tls_version: Literal["default", "1.0", "1.1", "1.2", "1.3"] = "default",
        tls_version_max: Literal["default", "1.0", "1.1", "1.2", "1.3"] = "default",
        interface: str = None,
        ip_version: Literal["any", "4", "6"] = "any",
        no_proxy: str = None,
        max_total_connections: int = 1024,
        max_host_connections: int = 64,
        max_idle_connections: int = 2048,
        max_concurrent_streams: int = 200,
        pool_min_size: int = 16,
        pool_max_size: int = 512,
        backend: Literal["threaded", "asyncio"] = "asyncio",
        timeout: tuple = (30.0, 0.0),
        cert: str = None,
        verbose: bool = None,
        raise_for_status: bool = False,
        json_encoder: Callable[..., bytes] = json_dumps,
        keep_alive: bool = True,
    ):
        """
        Initialize the RedC client

        Example:
            .. code-block:: python

                >>> client = Client(base_url="https://example.com")
                >>> response = await client.get("/api/data")

        Args:
            base_url (``str``, *optional*):
                The base URL for the client. Default is ``None``

            read_buffer_size (``int``, *optional*):
                The read buffer size for libcurl. Must be greater than ``1024`` bytes.
                Default is ``16384`` (16KB)

            headers (``dict``, *optional*):
                Headers to include in every request. Default is ``None``

            persist_cookies (``bool``, *optional*):
                Whether to persist cookies across requests. Default is ``False``

            http_version (``auto`` | ``1`` | ``1.1`` | ``2`` | ``3``, *optional*):
                Preferred HTTP version to attempt; libcurl may downgrade version as needed. Default is ``3``

            tls_version (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Minimum TLS version (this version or later). ``default`` leaves the floor to libcurl.
                Default is ``default``

            tls_version_max (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Maximum TLS version. ``default`` leaves the cap to libcurl.
                Default is ``default``

            interface (``str``, *optional*):
                Local interface name or IP address for outgoing connections.
                ``if!``, ``host!``, and ``ifhost!`` prefixes are passed through to libcurl.
                A hostname triggers a blocking DNS lookup. Default is ``None``

            ip_version (``any`` | ``4`` | ``6``, *optional*):
                Which addresses of a hostname may be used. A numeric address in the URL is used as written.
                Default is ``any``

            no_proxy (``str``, *optional*):
                Comma-separated hosts that skip ``proxy_url`` and connect directly.
                ``*`` skips the proxy for every host. ``""`` proxies every host and ignores
                the ``no_proxy`` environment variable. ``None`` leaves that variable in effect.
                Default is ``None``

            max_total_connections (``int``, *optional*):
                The maximum number of active TCP connections allowed simultaneously.
                Set to ``0`` for unlimited. Default is ``1024``

            max_host_connections (``int``, *optional*):
                The maximum number of active connections allowed per specific host.
                Set to ``0`` for unlimited. Default is ``64``

            max_idle_connections (``int``, *optional*):
                The maximum size of the network connection cache (Keep-Alive).
                These are TCP connections kept open for reuse after a request completes.
                Default is ``2048``

            max_concurrent_streams (``int``, *optional*):
                The maximum number of concurrent streams allowed per HTTP/2 or HTTP/3 connection.
                Default is ``200``

            pool_min_size (``int``, *optional*):
                The number of internal request handles to pre-allocate during initialization to reduce startup latency.
                Default is ``16``

            pool_max_size (``int``, *optional*):
                The maximum number of reusable request handles to retain in the pool.
                Excess handles created during high concurrency are destroyed rather than recycled.
                Default is ``2048``

            backend (``threaded`` | ``asyncio``, *optional*):
                Selects the execution backend used by RedC.

                ``asyncio`` is lightweight and performs best for low to moderate
                concurrency, where only a small number of requests are active.
                In such scenarios, it often provides lower latency and better
                performance

                ``threaded`` is optimized for higher concurrency and sustained load.
                While it may be less efficient for very small workloads, it generally
                achieves higher overall throughput (requests per second) as the number
                of concurrent requests increases

                As a rule of thumb:
                    - Low concurrency → ``asyncio``
                    - High concurrency → ``threaded``

                Default is ``asyncio``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds.
                Default is ``(30.0, 0.0)``

            cert (``str``, *optional*):
                Path to a CA certificate bundle file for SSL/TLS verification.
                Default is ``None`` (uses the [trustifi](https://github.com/AYMENJD/trustifi) CA bundle)

            verbose (``bool``, *optional*):
                Force verbose output for all requests. Default is ``None``

            raise_for_status (``bool``, *optional*):
                If ``True``, automatically raises an :class:`redc.exceptions.HTTPError` for responses with HTTP status codes
                indicating an error (i.e., 4xx or 5xx) or base :class:`redc.exceptions.CurlError` for CURL errors (e.g., network issues, timeouts).
                Default is ``False``

            json_encoder (``Callable``, *optional*):
                A callable for encoding JSON data. Default is :class:`redc.utils.json_dumps`

            keep_alive (``bool``, *optional*):
                Whether to keep the underlying TCP connection alive after the request completes.
                When ``True``, connections are reused for subsequent requests (default HTTP behavior).
                When ``False``, the connection is closed immediately after the transfer.
                Default is ``True``
        """

        self.allowed_http_versions = ("auto", "1", "1.1", "2", "3")

        assert isinstance(base_url, (str, type(None))), "base_url must be string"
        assert isinstance(read_buffer_size, int), "read_buffer_size must be int"
        assert isinstance(persist_cookies, bool), "persist_cookies must be bool"
        assert isinstance(http_version, str), "http_version must be string"
        assert http_version in self.allowed_http_versions, (
            "http_version must be one of 'auto', '1', '1.1', '2', '3'"
        )
        _check_tls_version("tls_version", tls_version)
        _check_tls_version("tls_version_max", tls_version_max)
        _check_tls_range(tls_version, tls_version_max)
        assert isinstance(interface, (str, type(None))), "interface must be string"
        _check_ip_version(ip_version)
        assert isinstance(no_proxy, (str, type(None))), "no_proxy must be string"
        assert isinstance(cert, (str, type(None))), "cert must be string"
        assert isinstance(timeout, tuple) and len(timeout) == 2, (
            "timeout must be a tuple of (total_timeout, connect_timeout)"
        )
        assert isinstance(verbose, (bool, type(None))), "verbose must be bool or None"
        assert isinstance(raise_for_status, bool), "raise_for_status must be bool"
        assert isinstance(keep_alive, bool), "keep_alive must be bool"

        assert read_buffer_size >= 1024, (
            "read_buffer_size must be bigger than 1024 bytes"
        )

        assert max_total_connections >= 0, (
            "max_total_connections must be greater than or equal to 0"
        )
        assert max_host_connections >= 0, (
            "max_host_connections must be greater than or equal to 0"
        )
        assert max_idle_connections >= 0, "max_idle_connections must be greater than 0"
        assert max_concurrent_streams >= 0, (
            "max_concurrent_streams must be greater than or equal to 0"
        )

        assert pool_min_size >= 0, "pool_min_size must be greater than or equal to 0"
        assert pool_max_size > 0, "pool_max_size must be greater than 0"
        assert pool_max_size >= pool_min_size, (
            "pool_max_size must be greater than or equal to pool_min_size"
        )
        assert backend in ("threaded", "asyncio"), (
            "backend must be one of 'threaded' or 'asyncio'"
        )

        self.verbose = verbose
        self.raise_for_status = raise_for_status
        self.__keep_alive = keep_alive

        self.__base_url = (
            parse_base_url(base_url) if isinstance(base_url, str) else None
        )

        self.__default_headers = Headers(headers if isinstance(headers, dict) else {})

        self.__default_http_version = http_version
        self.__default_tls_version = tls_version
        self.__default_tls_version_max = tls_version_max
        self.__default_interface = interface or ""
        self.__default_ip_version = ip_version
        self.__default_no_proxy = no_proxy
        self.__allowed_http_versions_set = set(self.allowed_http_versions)
        self.__empty_set = {"", None}
        self.__timeout = timeout
        self.__cert = cert if isinstance(cert, str) else trustifi.where()
        self.json_encoder = json_encoder
        self.__loop = asyncio.get_event_loop()
        self.__redc_ext = RedC(
            read_buffer_size=read_buffer_size,
            persist_cookies=persist_cookies,
            max_total_connections=max_total_connections,
            max_host_connections=max_host_connections,
            max_idle_connections=max_idle_connections,
            max_concurrent_streams=max_concurrent_streams,
            pool_min_size=pool_min_size,
            pool_max_size=pool_max_size,
            threaded=backend == "threaded",
        )

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

    @property
    @lru_cache
    def curl_version(self) -> str:
        """Return current installed curl version info"""

        return self.__redc_ext.curl_version()

    @property
    def cookies(self) -> dict[str, str]:
        """Returns all stored session cookies as a dict

        Returns:
            ``dict[str, str]``
        """
        cookies = {}
        for cookie in self.__redc_ext.get_cookies(netscape=False):
            name = cookie["name"]
            value = cookie["value"]
            if name:
                cookies[name] = value
        return cookies

    def get_cookies(self, netscape: bool = False) -> Union[list[dict], list[str]]:
        """Retrieves currently stored session cookies

        Args:
            netscape (``bool``, *optional*):
                If ``True``, returns raw Netscape-formatted strings; if ``False``, returns dicts. Default is ``False``

        Returns:
            ``list[dict]`` | ``list[str]``
        """

        return self.__redc_ext.get_cookies(netscape)

    def clear_cookies(self) -> None:
        """Clears all cookies from the current session"""

        return self.__redc_ext.clear_cookies()

    async def request(
        self,
        method: str,
        url: str,
        params: Union[dict[str, str], tuple[str, str], str, bytes] = None,
        json=None,
        data: Union[dict[str, str], BinaryIO] = None,
        files: dict[str, str] = None,
        headers: dict[str, str] = None,
        cookies: dict[str, str] = None,
        http_version: Literal["auto", "1", "1.1", "2", "3"] = None,
        tls_version: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        tls_version_max: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        timeout: tuple = None,
        allow_redirects: Union[bool, int] = True,
        proxy_url: str = "",
        no_proxy: str = None,
        interface: str = None,
        ip_version: Literal["any", "4", "6"] = None,
        auth: Union[tuple, str] = None,
        verify: bool = True,
        cert: str = None,
        stream_callback: StreamCallback = None,
        progress_callback: ProgressCallback = None,
        verbose: bool = False,
        keep_alive: bool = None,
    ):
        """
        Make an HTTP request with the specified method and parameters

        Example:
            .. code-block:: python

                >>> response = await client.request("GET", "/api/data", headers={"Authorization": "Bearer token"})

        Args:
            method (``str``):
                The HTTP method to use (e.g., "GET", "POST")

            url (``str``):
                The URL to send the request to or path if ``base_url`` is specified in ``Client``

            params (``dict[str, str]`` | ``tuple[str, str]`` | ``str`` | ``bytes``, *optional*):
                Query parameters to include in the request. Default is ``None``

            json (``dict``, *optional*):
                JSON data to send in the request body. Default is ``None``

            data (``dict`` | ``list[tuple]`` | ``bytes`` | ``str`` | ``BinaryIO``, *optional*):
                Data to send in the body of the Request.
                - If a **dict** or **list of tuples**: Sends as ``application/x-www-form-urlencoded``.
                - If **bytes** or **str**: Sends as raw body.
                - If a **file-like object** (has ``readinto``): Streams the data.
                - If ``files`` is provided, ``data`` constitutes the non-file fields of the multipart request.
                Default is ``None``

            files (``dict``, *optional*):
                Dictionary of ``name': file-val`` for multipart encoding upload.
                ``file-val`` can be
                - A **string** (file path).
                - **bytes** (file content).
                - A **file-like object** (stream).
                - A **tuple** in the format
                    - ``('filename', file-val)``
                    - ``('filename', file-val, 'content_type')``
                    - ``('filename', file-val, 'content_type', custom_headers)``
                        where ``custom_headers`` is a ``dict`` containing additional headers for the file part.
                Default is ``None``

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            cookies (``dict[str, str]``, *optional*):
                Cookies to include in the request. Default is ``None``

            http_version (``auto`` | ``1`` | ``1.1`` | ``2`` | ``3``, *optional*):
                Preferred HTTP version to attempt; libcurl may downgrade version as needed. Default is ``3``

            tls_version (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Minimum TLS version (this version or later). ``default`` leaves the floor to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            tls_version_max (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Maximum TLS version. ``default`` leaves the cap to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirects (``bool`` | ``int``, *optional*):
                Whether to follow HTTP redirects. ``True`` enables redirects with a default limit of ``30``.
                ``int`` sets a custom limit, ``False`` disables redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy server URL to use for the request (e.g., ``http://user:pass@host:port``).

            no_proxy (``str``, *optional*):
                Comma-separated hosts that skip the proxy and connect directly.
                ``*`` skips the proxy for every host. ``""`` proxies every host and ignores
                the ``no_proxy`` environment variable. When ``None``, uses the client-level default.
                Default is ``None``

            interface (``str``, *optional*):
                Local interface name or IP address for outgoing connections.
                ``if!``, ``host!``, and ``ifhost!`` prefixes are passed through to libcurl.
                When ``None``, uses the client-level default. ``""`` does not bind for this request.
                Default is ``None``

            ip_version (``any`` | ``4`` | ``6``, *optional*):
                Which addresses of a hostname may be used. A numeric address in the URL is used as written.
                When ``None``, uses the client-level default. Default is ``None``

            auth (``tuple`` | ``str``, *optional*):
                A tuple of ``(username, password)`` or ``(username, password, type)`` for HTTP authentication or a string for Bearer authentication.
                Supported types are: ``basic``, ``digest``, ``digest_ie``, ``ntlm`` and ``any``. Default is ``basic``

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            cert (``str``, *optional*):
                Path to a CA certificate bundle file for SSL/TLS verification. Default is ``None``, which uses the trustifi CA bundle

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            progress_callback (:class:`redc.ProgressCallback`, *optional*):
                Callback for tracking upload and download progress. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

            keep_alive (``bool``, *optional*):
                Whether to keep the underlying TCP connection alive after the request completes.
                When ``None``, uses the client-level default. Default is ``None``

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

        if http_version is not None:
            assert http_version in self.__allowed_http_versions_set, (
                "http_version must be one of 'auto', '1', '1.1', '2', '3'"
            )

        if tls_version is None:
            tls_version = self.__default_tls_version
        else:
            _check_tls_version("tls_version", tls_version)

        if tls_version_max is None:
            tls_version_max = self.__default_tls_version_max
        else:
            _check_tls_version("tls_version_max", tls_version_max)

        _check_tls_range(tls_version, tls_version_max)

        if interface is None:
            interface = self.__default_interface
        else:
            assert isinstance(interface, str), "interface must be string"

        if ip_version is None:
            ip_version = self.__default_ip_version
        else:
            _check_ip_version(ip_version)

        if no_proxy is None:
            no_proxy = self.__default_no_proxy
        else:
            assert isinstance(no_proxy, str), "no_proxy must be string"

        if json is not None:
            json = self.json_encoder(json)
            if headers is None:
                headers = {}
            headers["Content-Type"] = "application/json"

        timeout, connect_timeout = timeout if timeout is not None else self.__timeout

        if timeout <= 0:
            raise ValueError("timeout must be greater than 0")

        if connect_timeout < 0:
            raise ValueError("connect_timeout must be 0 or greater")
        elif connect_timeout > timeout:
            raise ValueError("connect_timeout must be less than `timeout` argument")

        headers = self.__build_headers(headers)

        if self.__base_url:
            url = f"{self.__base_url}{url.lstrip('/')}"

        return Response.from_result(
            result=await self.__redc_ext.request(
                method=method,
                url=url,
                params=params,
                raw_data=json,
                data=data,
                files=files,
                headers=headers,
                cookies=cookies,
                http_version=http_version or self.__default_http_version,
                tls_version=tls_version,
                tls_version_max=tls_version_max,
                timeout_ms=int(timeout * 1000),
                connect_timeout_ms=int(connect_timeout * 1000),
                allow_redirects=allow_redirects,
                proxy_url=proxy_url,
                no_proxy="" if no_proxy is None else no_proxy,
                no_proxy_set=no_proxy is not None,
                interface=interface,
                ip_version=ip_version,
                auth=auth,
                verify=verify,
                cert=cert or self.__cert,
                stream_callback=stream_callback,
                progress_callback=progress_callback,
                verbose=self.verbose or verbose,
                keep_alive=keep_alive if keep_alive is not None else self.__keep_alive,
            ),
            raise_for_status=self.raise_for_status,
        )

    async def get(
        self,
        url: str,
        params: Union[dict[str, str], tuple[str, str], str, bytes] = None,
        headers: dict[str, str] = None,
        cookies: dict[str, str] = None,
        http_version: Literal["auto", "1", "1.1", "2", "3"] = None,
        tls_version: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        tls_version_max: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        timeout: tuple = None,
        allow_redirects: Union[bool, int] = True,
        proxy_url: str = "",
        no_proxy: str = None,
        interface: str = None,
        ip_version: Literal["any", "4", "6"] = None,
        verify: bool = True,
        auth: Union[tuple, str] = None,
        cert: str = None,
        stream_callback: StreamCallback = None,
        progress_callback: ProgressCallback = None,
        verbose: bool = False,
        keep_alive: bool = None,
    ):
        """
        Make a GET request

        Example:
            .. code-block:: python

                >>> response = await client.get("/api/data", headers={"Authorization": "Bearer token"})

        Args:
            url (``str``):
                The URL to send the GET request to or path if ``base_url`` is specified in ``Client``

            params (``dict[str, str]`` | ``tuple[str, str]`` | ``str`` | ``bytes``, *optional*):
                Query parameters to include in the request. Default is ``None``

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            cookies (``dict[str, str]``, *optional*):
                Cookies to include in the request. Default is ``None``

            http_version (``auto`` | ``1`` | ``1.1`` | ``2`` | ``3``, *optional*):
                Preferred HTTP version to attempt; libcurl may downgrade version as needed. Default is ``3``

            tls_version (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Minimum TLS version (this version or later). ``default`` leaves the floor to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            tls_version_max (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Maximum TLS version. ``default`` leaves the cap to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirects (``bool`` | ``int``, *optional*):
                Whether to follow HTTP redirects. ``True`` enables redirects with a default limit of ``30``.
                ``int`` sets a custom limit, ``False`` disables redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy server URL to use for the request (e.g., ``http://user:pass@host:port``).

            no_proxy (``str``, *optional*):
                Comma-separated hosts that skip the proxy and connect directly.
                ``*`` skips the proxy for every host. ``""`` proxies every host and ignores
                the ``no_proxy`` environment variable. When ``None``, uses the client-level default.
                Default is ``None``

            interface (``str``, *optional*):
                Local interface name or IP address for outgoing connections.
                ``if!``, ``host!``, and ``ifhost!`` prefixes are passed through to libcurl.
                When ``None``, uses the client-level default. ``""`` does not bind for this request.
                Default is ``None``

            ip_version (``any`` | ``4`` | ``6``, *optional*):
                Which addresses of a hostname may be used. A numeric address in the URL is used as written.
                When ``None``, uses the client-level default. Default is ``None``

            auth (``tuple`` | ``str``, *optional*):
                A tuple of ``(username, password)`` or ``(username, password, type)`` for HTTP authentication or a string for Bearer authentication.
                Supported types are: ``basic``, ``digest``, ``digest_ie``, ``ntlm`` and ``any``. Default is ``basic``

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            cert (``str``, *optional*):
                Path to a CA certificate bundle file for SSL/TLS verification. Default is ``None``, which uses the trustifi CA bundle

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            progress_callback (:class:`redc.ProgressCallback`, *optional*):
                Callback for tracking upload and download progress. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

            keep_alive (``bool``, *optional*):
                Whether to keep the underlying TCP connection alive after the request completes.
                When ``None``, uses the client-level default. Default is ``None``

        Returns:
            :class:`redc.Response`
        """

        return await self.request(
            method="GET",
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            http_version=http_version or self.__default_http_version,
            tls_version=tls_version,
            tls_version_max=tls_version_max,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxy_url=proxy_url,
            no_proxy=no_proxy,
            interface=interface,
            ip_version=ip_version,
            auth=auth,
            verify=verify,
            cert=cert,
            stream_callback=stream_callback,
            progress_callback=progress_callback,
            verbose=verbose,
            keep_alive=keep_alive,
        )

    async def head(
        self,
        url: str,
        params: Union[dict[str, str], tuple[str, str], str, bytes] = None,
        headers: dict[str, str] = None,
        cookies: dict[str, str] = None,
        http_version: Literal["auto", "1", "1.1", "2", "3"] = None,
        tls_version: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        tls_version_max: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        timeout: tuple = None,
        allow_redirects: Union[bool, int] = True,
        proxy_url: str = "",
        no_proxy: str = None,
        interface: str = None,
        ip_version: Literal["any", "4", "6"] = None,
        verify: bool = True,
        auth: Union[tuple, str] = None,
        cert: str = None,
        verbose: bool = False,
        keep_alive: bool = None,
    ):
        """
        Make a HEAD request

        Example:
            .. code-block:: python

                >>> response = await client.head("/api/data", headers={"Authorization": "Bearer token"})

        Args:
            url (``str``):
                The URL to send the HEAD request to or path if ``base_url`` is specified in ``Client``

            params (``dict[str, str]`` | ``tuple[str, str]`` | ``str`` | ``bytes``, *optional*):
                Query parameters to include in the request. Default is ``None``

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            cookies (``dict[str, str]``, *optional*):
                Cookies to include in the request. Default is ``None``

            http_version (``auto`` | ``1`` | ``1.1`` | ``2`` | ``3``, *optional*):
                Preferred HTTP version to attempt; libcurl may downgrade version as needed. Default is ``3``

            tls_version (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Minimum TLS version (this version or later). ``default`` leaves the floor to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            tls_version_max (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Maximum TLS version. ``default`` leaves the cap to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirects (``bool`` | ``int``, *optional*):
                Whether to follow HTTP redirects. ``True`` enables redirects with a default limit of ``30``.
                ``int`` sets a custom limit, ``False`` disables redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy server URL to use for the request (e.g., ``http://user:pass@host:port``).

            no_proxy (``str``, *optional*):
                Comma-separated hosts that skip the proxy and connect directly.
                ``*`` skips the proxy for every host. ``""`` proxies every host and ignores
                the ``no_proxy`` environment variable. When ``None``, uses the client-level default.
                Default is ``None``

            interface (``str``, *optional*):
                Local interface name or IP address for outgoing connections.
                ``if!``, ``host!``, and ``ifhost!`` prefixes are passed through to libcurl.
                When ``None``, uses the client-level default. ``""`` does not bind for this request.
                Default is ``None``

            ip_version (``any`` | ``4`` | ``6``, *optional*):
                Which addresses of a hostname may be used. A numeric address in the URL is used as written.
                When ``None``, uses the client-level default. Default is ``None``

            auth (``tuple`` | ``str``, *optional*):
                A tuple of ``(username, password)`` or ``(username, password, type)`` for HTTP authentication or a string for Bearer authentication.
                Supported types are: ``basic``, ``digest``, ``digest_ie``, ``ntlm`` and ``any``. Default is ``basic``

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            cert (``str``, *optional*):
                Path to a CA certificate bundle file for SSL/TLS verification. Default is ``None``, which uses the trustifi CA bundle

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

            keep_alive (``bool``, *optional*):
                Whether to keep the underlying TCP connection alive after the request completes.
                When ``None``, uses the client-level default. Default is ``None``

        Returns:
            :class:`redc.Response`
        """

        return await self.request(
            method="HEAD",
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            http_version=http_version or self.__default_http_version,
            tls_version=tls_version,
            tls_version_max=tls_version_max,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxy_url=proxy_url,
            no_proxy=no_proxy,
            interface=interface,
            ip_version=ip_version,
            auth=auth,
            verify=verify,
            cert=cert,
            verbose=verbose,
            keep_alive=keep_alive,
        )

    async def post(
        self,
        url: str,
        params: Union[dict[str, str], tuple[str, str], str, bytes] = None,
        json=None,
        data: Union[dict[str, str], BinaryIO] = None,
        files: dict[str, str] = None,
        headers: dict[str, str] = None,
        cookies: dict[str, str] = None,
        http_version: Literal["auto", "1", "1.1", "2", "3"] = None,
        tls_version: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        tls_version_max: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        timeout: tuple = None,
        allow_redirects: Union[bool, int] = True,
        proxy_url: str = "",
        no_proxy: str = None,
        interface: str = None,
        ip_version: Literal["any", "4", "6"] = None,
        verify: bool = True,
        auth: Union[tuple, str] = None,
        cert: str = None,
        stream_callback: StreamCallback = None,
        progress_callback: ProgressCallback = None,
        verbose: bool = False,
        keep_alive: bool = None,
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

        Args:
            url (``str``):
                The URL to send the POST request to or path if ``base_url`` is specified in ``Client``

            params (``dict[str, str]`` | ``tuple[str, str]`` | ``str`` | ``bytes``, *optional*):
                Query parameters to include in the request. Default is ``None``

            json (``Any``, *optional*):
                JSON data to send in the request body. Default is ``None``

            data (``dict`` | ``list[tuple]`` | ``bytes`` | ``str`` | ``BinaryIO``, *optional*):
                Data to send in the body of the Request.
                - If a **dict** or **list of tuples**: Sends as ``application/x-www-form-urlencoded``.
                - If **bytes** or **str**: Sends as raw body.
                - If a **file-like object** (has ``readinto``): Streams the data.
                - If ``files`` is provided, ``data`` constitutes the non-file fields of the multipart request.
                Default is ``None``

            files (``dict``, *optional*):
                Dictionary of ``name': file-val`` for multipart encoding upload.
                ``file-val`` can be
                - A **string** (file path).
                - **bytes** (file content).
                - A **file-like object** (stream).
                - A **tuple** in the format
                    - ``('filename', file-val)``
                    - ``('filename', file-val, 'content_type')``
                    - ``('filename', file-val, 'content_type', custom_headers)``
                        where ``custom_headers`` is a ``dict`` containing additional headers for the file part.
                Default is ``None``

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            cookies (``dict[str, str]``, *optional*):
                Cookies to include in the request. Default is ``None``

            http_version (``auto`` | ``1`` | ``1.1`` | ``2`` | ``3``, *optional*):
                Preferred HTTP version to attempt; libcurl may downgrade version as needed. Default is ``3``

            tls_version (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Minimum TLS version (this version or later). ``default`` leaves the floor to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            tls_version_max (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Maximum TLS version. ``default`` leaves the cap to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirects (``bool`` | ``int``, *optional*):
                Whether to follow HTTP redirects. ``True`` enables redirects with a default limit of ``30``.
                ``int`` sets a custom limit, ``False`` disables redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy server URL to use for the request (e.g., ``http://user:pass@host:port``).

            no_proxy (``str``, *optional*):
                Comma-separated hosts that skip the proxy and connect directly.
                ``*`` skips the proxy for every host. ``""`` proxies every host and ignores
                the ``no_proxy`` environment variable. When ``None``, uses the client-level default.
                Default is ``None``

            interface (``str``, *optional*):
                Local interface name or IP address for outgoing connections.
                ``if!``, ``host!``, and ``ifhost!`` prefixes are passed through to libcurl.
                When ``None``, uses the client-level default. ``""`` does not bind for this request.
                Default is ``None``

            ip_version (``any`` | ``4`` | ``6``, *optional*):
                Which addresses of a hostname may be used. A numeric address in the URL is used as written.
                When ``None``, uses the client-level default. Default is ``None``

            auth (``tuple`` | ``str``, *optional*):
                A tuple of ``(username, password)`` or ``(username, password, type)`` for HTTP authentication or a string for Bearer authentication.
                Supported types are: ``basic``, ``digest``, ``digest_ie``, ``ntlm`` and ``any``. Default is ``basic``

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            cert (``str``, *optional*):
                Path to a CA certificate bundle file for SSL/TLS verification. Default is ``None``, which uses the trustifi CA bundle

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            progress_callback (:class:`redc.ProgressCallback`, *optional*):
                Callback for tracking upload and download progress. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

            keep_alive (``bool``, *optional*):
                Whether to keep the underlying TCP connection alive after the request completes.
                When ``None``, uses the client-level default. Default is ``None``

        Returns:
            :class:`redc.Response`
        """

        return await self.request(
            method="POST",
            url=url,
            params=params,
            json=json,
            data=data,
            files=files,
            headers=headers,
            cookies=cookies,
            http_version=http_version or self.__default_http_version,
            tls_version=tls_version,
            tls_version_max=tls_version_max,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxy_url=proxy_url,
            no_proxy=no_proxy,
            interface=interface,
            ip_version=ip_version,
            auth=auth,
            verify=verify,
            cert=cert,
            stream_callback=stream_callback,
            progress_callback=progress_callback,
            verbose=verbose,
            keep_alive=keep_alive,
        )

    async def put(
        self,
        url: str,
        params: Union[dict[str, str], tuple[str, str], str, bytes] = None,
        json=None,
        data: Union[dict[str, str], BinaryIO] = None,
        files: dict[str, str] = None,
        headers: dict[str, str] = None,
        cookies: dict[str, str] = None,
        http_version: Literal["auto", "1", "1.1", "2", "3"] = None,
        tls_version: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        tls_version_max: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        timeout: tuple = None,
        allow_redirects: Union[bool, int] = True,
        proxy_url: str = "",
        no_proxy: str = None,
        interface: str = None,
        ip_version: Literal["any", "4", "6"] = None,
        verify: bool = True,
        auth: Union[tuple, str] = None,
        cert: str = None,
        stream_callback: StreamCallback = None,
        progress_callback: ProgressCallback = None,
        verbose: bool = False,
        keep_alive: bool = None,
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

        Args:
            url (``str``):
                The URL to send the PUT request to or path if ``base_url`` is specified in ``Client``

            params (``dict[str, str]`` | ``tuple[str, str]`` | ``str`` | ``bytes``, *optional*):
                Query parameters to include in the request. Default is ``None``

            json (``Any``, *optional*):
                JSON data to send in the request body. Default is ``None``

            data (``dict`` | ``list[tuple]`` | ``bytes`` | ``str`` | ``BinaryIO``, *optional*):
                Data to send in the body of the Request.
                - If a **dict** or **list of tuples**: Sends as ``application/x-www-form-urlencoded``.
                - If **bytes** or **str**: Sends as raw body.
                - If a **file-like object** (has ``readinto``): Streams the data.
                - If ``files`` is provided, ``data`` constitutes the non-file fields of the multipart request.
                Default is ``None``

            files (``dict``, *optional*):
                Dictionary of ``name': file-val`` for multipart encoding upload.
                ``file-val`` can be
                - A **string** (file path).
                - **bytes** (file content).
                - A **file-like object** (stream).
                - A **tuple** in the format
                    - ``('filename', file-val)``
                    - ``('filename', file-val, 'content_type')``
                    - ``('filename', file-val, 'content_type', custom_headers)``
                        where ``custom_headers`` is a ``dict`` containing additional headers for the file part.
                Default is ``None``

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            cookies (``dict[str, str]``, *optional*):
                Cookies to include in the request. Default is ``None``

            http_version (``auto`` | ``1`` | ``1.1`` | ``2`` | ``3``, *optional*):
                Preferred HTTP version to attempt; libcurl may downgrade version as needed. Default is ``3``

            tls_version (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Minimum TLS version (this version or later). ``default`` leaves the floor to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            tls_version_max (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Maximum TLS version. ``default`` leaves the cap to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirects (``bool`` | ``int``, *optional*):
                Whether to follow HTTP redirects. ``True`` enables redirects with a default limit of ``30``.
                ``int`` sets a custom limit, ``False`` disables redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy server URL to use for the request (e.g., ``http://user:pass@host:port``).

            no_proxy (``str``, *optional*):
                Comma-separated hosts that skip the proxy and connect directly.
                ``*`` skips the proxy for every host. ``""`` proxies every host and ignores
                the ``no_proxy`` environment variable. When ``None``, uses the client-level default.
                Default is ``None``

            interface (``str``, *optional*):
                Local interface name or IP address for outgoing connections.
                ``if!``, ``host!``, and ``ifhost!`` prefixes are passed through to libcurl.
                When ``None``, uses the client-level default. ``""`` does not bind for this request.
                Default is ``None``

            ip_version (``any`` | ``4`` | ``6``, *optional*):
                Which addresses of a hostname may be used. A numeric address in the URL is used as written.
                When ``None``, uses the client-level default. Default is ``None``

            auth (``tuple`` | ``str``, *optional*):
                A tuple of ``(username, password)`` or ``(username, password, type)`` for HTTP authentication or a string for Bearer authentication.
                Supported types are: ``basic``, ``digest``, ``digest_ie``, ``ntlm`` and ``any``. Default is ``basic``

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            cert (``str``, *optional*):
                Path to a CA certificate bundle file for SSL/TLS verification. Default is ``None``, which uses the trustifi CA bundle

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            progress_callback (:class:`redc.ProgressCallback`, *optional*):
                Callback for tracking upload and download progress. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

            keep_alive (``bool``, *optional*):
                Whether to keep the underlying TCP connection alive after the request completes.
                When ``None``, uses the client-level default. Default is ``None``

        Returns:
            :class:`redc.Response`
        """

        return await self.request(
            method="PUT",
            url=url,
            params=params,
            json=json,
            data=data,
            files=files,
            headers=headers,
            cookies=cookies,
            http_version=http_version or self.__default_http_version,
            tls_version=tls_version,
            tls_version_max=tls_version_max,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxy_url=proxy_url,
            no_proxy=no_proxy,
            interface=interface,
            ip_version=ip_version,
            auth=auth,
            verify=verify,
            cert=cert,
            stream_callback=stream_callback,
            progress_callback=progress_callback,
            verbose=verbose,
            keep_alive=keep_alive,
        )

    async def patch(
        self,
        url: str,
        params: Union[dict[str, str], tuple[str, str], str, bytes] = None,
        json=None,
        data: Union[dict[str, str], BinaryIO] = None,
        files: dict[str, str] = None,
        headers: dict[str, str] = None,
        cookies: dict[str, str] = None,
        http_version: Literal["auto", "1", "1.1", "2", "3"] = None,
        tls_version: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        tls_version_max: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        timeout: tuple = None,
        allow_redirects: Union[bool, int] = True,
        proxy_url: str = "",
        no_proxy: str = None,
        interface: str = None,
        ip_version: Literal["any", "4", "6"] = None,
        verify: bool = True,
        auth: Union[tuple, str] = None,
        cert: str = None,
        stream_callback: StreamCallback = None,
        progress_callback: ProgressCallback = None,
        verbose: bool = False,
        keep_alive: bool = None,
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

        Args:
            url (``str``):
                The URL to send the PATCH request to or path if ``base_url`` is specified in ``Client``

            params (``dict[str, str]`` | ``tuple[str, str]`` | ``str`` | ``bytes``, *optional*):
                Query parameters to include in the request. Default is ``None``

            json (``Any``, *optional*):
                JSON data to send in the request body. Default is ``None``

            data (``dict`` | ``list[tuple]`` | ``bytes`` | ``str`` | ``BinaryIO``, *optional*):
                Data to send in the body of the Request.
                - If a **dict** or **list of tuples**: Sends as ``application/x-www-form-urlencoded``.
                - If **bytes** or **str**: Sends as raw body.
                - If a **file-like object** (has ``readinto``): Streams the data.
                - If ``files`` is provided, ``data`` constitutes the non-file fields of the multipart request.
                Default is ``None``

            files (``dict``, *optional*):
                Dictionary of ``name': file-val`` for multipart encoding upload.
                ``file-val`` can be
                - A **string** (file path).
                - **bytes** (file content).
                - A **file-like object** (stream).
                - A **tuple** in the format
                    - ``('filename', file-val)``
                    - ``('filename', file-val, 'content_type')``
                    - ``('filename', file-val, 'content_type', custom_headers)``
                        where ``custom_headers`` is a ``dict`` containing additional headers for the file part.
                Default is ``None``

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            cookies (``dict[str, str]``, *optional*):
                Cookies to include in the request. Default is ``None``

            http_version (``auto`` | ``1`` | ``1.1`` | ``2`` | ``3``, *optional*):
                Preferred HTTP version to attempt; libcurl may downgrade version as needed. Default is ``3``

            tls_version (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Minimum TLS version (this version or later). ``default`` leaves the floor to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            tls_version_max (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Maximum TLS version. ``default`` leaves the cap to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirects (``bool`` | ``int``, *optional*):
                Whether to follow HTTP redirects. ``True`` enables redirects with a default limit of ``30``.
                ``int`` sets a custom limit, ``False`` disables redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy server URL to use for the request (e.g., ``http://user:pass@host:port``).

            no_proxy (``str``, *optional*):
                Comma-separated hosts that skip the proxy and connect directly.
                ``*`` skips the proxy for every host. ``""`` proxies every host and ignores
                the ``no_proxy`` environment variable. When ``None``, uses the client-level default.
                Default is ``None``

            interface (``str``, *optional*):
                Local interface name or IP address for outgoing connections.
                ``if!``, ``host!``, and ``ifhost!`` prefixes are passed through to libcurl.
                When ``None``, uses the client-level default. ``""`` does not bind for this request.
                Default is ``None``

            ip_version (``any`` | ``4`` | ``6``, *optional*):
                Which addresses of a hostname may be used. A numeric address in the URL is used as written.
                When ``None``, uses the client-level default. Default is ``None``

            auth (``tuple`` | ``str``, *optional*):
                A tuple of ``(username, password)`` or ``(username, password, type)`` for HTTP authentication or a string for Bearer authentication.
                Supported types are: ``basic``, ``digest``, ``digest_ie``, ``ntlm`` and ``any``. Default is ``basic``

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            cert (``str``, *optional*):
                Path to a CA certificate bundle file for SSL/TLS verification. Default is ``None``, which uses the trustifi CA bundle

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            progress_callback (:class:`redc.ProgressCallback`, *optional*):
                Callback for tracking upload and download progress. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

            keep_alive (``bool``, *optional*):
                Whether to keep the underlying TCP connection alive after the request completes.
                When ``None``, uses the client-level default. Default is ``None``

        Returns:
            :class:`redc.Response`
        """

        return await self.request(
            method="PATCH",
            url=url,
            params=params,
            json=json,
            data=data,
            files=files,
            headers=headers,
            cookies=cookies,
            http_version=http_version or self.__default_http_version,
            tls_version=tls_version,
            tls_version_max=tls_version_max,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxy_url=proxy_url,
            no_proxy=no_proxy,
            interface=interface,
            ip_version=ip_version,
            auth=auth,
            verify=verify,
            cert=cert,
            stream_callback=stream_callback,
            progress_callback=progress_callback,
            verbose=verbose,
            keep_alive=keep_alive,
        )

    async def delete(
        self,
        url: str,
        params: Union[dict[str, str], tuple[str, str], str, bytes] = None,
        headers: dict[str, str] = None,
        cookies: dict[str, str] = None,
        http_version: Literal["auto", "1", "1.1", "2", "3"] = None,
        tls_version: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        tls_version_max: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        timeout: tuple = None,
        allow_redirects: Union[bool, int] = True,
        proxy_url: str = "",
        no_proxy: str = None,
        interface: str = None,
        ip_version: Literal["any", "4", "6"] = None,
        verify: bool = True,
        auth: Union[tuple, str] = None,
        cert: str = None,
        stream_callback: StreamCallback = None,
        progress_callback: ProgressCallback = None,
        verbose: bool = False,
        keep_alive: bool = None,
    ):
        """
        Make a DELETE request

        Example:
            .. code-block:: python

                >>> response = await client.delete("/api/data/1", headers={"Authorization": "Bearer token"})

        Args:
            url (``str``):
                The URL to send the DELETE request to or path if ``base_url`` is specified in ``Client``

            params (``dict[str, str]`` | ``tuple[str, str]`` | ``str`` | ``bytes``, *optional*):
                Query parameters to include in the request. Default is ``None``

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            cookies (``dict[str, str]``, *optional*):
                Cookies to include in the request. Default is ``None``

            http_version (``auto`` | ``1`` | ``1.1`` | ``2`` | ``3``, *optional*):
                Preferred HTTP version to attempt; libcurl may downgrade version as needed. Default is ``3``

            tls_version (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Minimum TLS version (this version or later). ``default`` leaves the floor to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            tls_version_max (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Maximum TLS version. ``default`` leaves the cap to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirects (``bool`` | ``int``, *optional*):
                Whether to follow HTTP redirects. ``True`` enables redirects with a default limit of ``30``.
                ``int`` sets a custom limit, ``False`` disables redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy server URL to use for the request (e.g., ``http://user:pass@host:port``).

            no_proxy (``str``, *optional*):
                Comma-separated hosts that skip the proxy and connect directly.
                ``*`` skips the proxy for every host. ``""`` proxies every host and ignores
                the ``no_proxy`` environment variable. When ``None``, uses the client-level default.
                Default is ``None``

            interface (``str``, *optional*):
                Local interface name or IP address for outgoing connections.
                ``if!``, ``host!``, and ``ifhost!`` prefixes are passed through to libcurl.
                When ``None``, uses the client-level default. ``""`` does not bind for this request.
                Default is ``None``

            ip_version (``any`` | ``4`` | ``6``, *optional*):
                Which addresses of a hostname may be used. A numeric address in the URL is used as written.
                When ``None``, uses the client-level default. Default is ``None``

            auth (``tuple`` | ``str``, *optional*):
                A tuple of ``(username, password)`` or ``(username, password, type)`` for HTTP authentication or a string for Bearer authentication.
                Supported types are: ``basic``, ``digest``, ``digest_ie``, ``ntlm`` and ``any``. Default is ``basic``

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            cert (``str``, *optional*):
                Path to a CA certificate bundle file for SSL/TLS verification. Default is ``None``, which uses the trustifi CA bundle

            stream_callback (:class:`redc.StreamCallback`, *optional*):
                Callback for streaming response data. Default is ``None``

            progress_callback (:class:`redc.ProgressCallback`, *optional*):
                Callback for tracking upload and download progress. Default is ``None``

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

            keep_alive (``bool``, *optional*):
                Whether to keep the underlying TCP connection alive after the request completes.
                When ``None``, uses the client-level default. Default is ``None``

        Returns:
            :class:`redc.Response`
        """

        return await self.request(
            method="DELETE",
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            http_version=http_version or self.__default_http_version,
            tls_version=tls_version,
            tls_version_max=tls_version_max,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxy_url=proxy_url,
            no_proxy=no_proxy,
            interface=interface,
            ip_version=ip_version,
            auth=auth,
            verify=verify,
            cert=cert,
            stream_callback=stream_callback,
            progress_callback=progress_callback,
            verbose=verbose,
            keep_alive=keep_alive,
        )

    async def options(
        self,
        url: str,
        params: Union[dict[str, str], tuple[str, str], str, bytes] = None,
        headers: dict[str, str] = None,
        cookies: dict[str, str] = None,
        http_version: Literal["auto", "1", "1.1", "2", "3"] = None,
        tls_version: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        tls_version_max: Literal["default", "1.0", "1.1", "1.2", "1.3"] = None,
        timeout: tuple = None,
        allow_redirects: Union[bool, int] = True,
        proxy_url: str = "",
        no_proxy: str = None,
        interface: str = None,
        ip_version: Literal["any", "4", "6"] = None,
        verify: bool = True,
        auth: Union[tuple, str] = None,
        cert: str = None,
        verbose: bool = False,
        keep_alive: bool = None,
    ):
        """
        Make an OPTIONS request

        Example:
            .. code-block:: python

                >>> response = await client.options("/api/data", headers={"Authorization": "Bearer token"})

        Args:
            url (``str``):
                The URL to send the OPTIONS request to or path if ``base_url`` is specified in ``Client``

            params (``dict[str, str]`` | ``tuple[str, str]`` | ``str`` | ``bytes``, *optional*):
                Query parameters to include in the request. Default is ``None``

            headers (``dict[str, str]``, *optional*):
                Headers to include in the request. Default is ``None``

            cookies (``dict[str, str]``, *optional*):
                Cookies to include in the request. Default is ``None``

            http_version (``auto`` | ``1`` | ``1.1`` | ``2`` | ``3``, *optional*):
                Preferred HTTP version to attempt; libcurl may downgrade version as needed. Default is ``3``

            tls_version (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Minimum TLS version (this version or later). ``default`` leaves the floor to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            tls_version_max (``default`` | ``1.0`` | ``1.1`` | ``1.2`` | ``1.3``, *optional*):
                Maximum TLS version. ``default`` leaves the cap to libcurl.
                When ``None``, uses the client-level default. Default is ``None``

            timeout (``tuple``, *optional*):
                A tuple of ``(total_timeout, connect_timeout)`` in seconds to override the default timeout.
                If ``None``, the default timeout specified in ``Client`` is used.

            allow_redirects (``bool`` | ``int``, *optional*):
                Whether to follow HTTP redirects. ``True`` enables redirects with a default limit of ``30``.
                ``int`` sets a custom limit, ``False`` disables redirects. Default is ``True``

            proxy_url (``str``, *optional*):
                The proxy server URL to use for the request (e.g., ``http://user:pass@host:port``).

            no_proxy (``str``, *optional*):
                Comma-separated hosts that skip the proxy and connect directly.
                ``*`` skips the proxy for every host. ``""`` proxies every host and ignores
                the ``no_proxy`` environment variable. When ``None``, uses the client-level default.
                Default is ``None``

            interface (``str``, *optional*):
                Local interface name or IP address for outgoing connections.
                ``if!``, ``host!``, and ``ifhost!`` prefixes are passed through to libcurl.
                When ``None``, uses the client-level default. ``""`` does not bind for this request.
                Default is ``None``

            ip_version (``any`` | ``4`` | ``6``, *optional*):
                Which addresses of a hostname may be used. A numeric address in the URL is used as written.
                When ``None``, uses the client-level default. Default is ``None``

            auth (``tuple`` | ``str``, *optional*):
                A tuple of ``(username, password)`` or ``(username, password, type)`` for HTTP authentication or a string for Bearer authentication.
                Supported types are: ``basic``, ``digest``, ``digest_ie``, ``ntlm`` and ``any``. Default is ``basic``

            verify (``bool``, *optional*):
                Whether to verify SSL certificates. Default is ``True``

            cert (``str``, *optional*):
                Path to a CA certificate bundle file for SSL/TLS verification. Default is ``None``, which uses the trustifi CA bundle

            verbose (``bool``, *optional*):
                Whether to enable verbose output for the request. Default is ``False``

            keep_alive (``bool``, *optional*):
                Whether to keep the underlying TCP connection alive after the request completes.
                When ``None``, uses the client-level default. Default is ``None``

        Returns:
            :class:`redc.Response`
        """

        return await self.request(
            method="OPTIONS",
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            http_version=http_version or self.__default_http_version,
            tls_version=tls_version,
            tls_version_max=tls_version_max,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxy_url=proxy_url,
            no_proxy=no_proxy,
            interface=interface,
            ip_version=ip_version,
            auth=auth,
            verify=verify,
            cert=cert,
            verbose=verbose,
            keep_alive=keep_alive,
        )

    async def close(self):
        """
        Close the RedC client and free up resources.

        This method must be called when the client is no longer needed to avoid memory leaks
        or unexpected behavior
        """

        return await self.__loop.run_in_executor(None, self.__redc_ext.close)

    def __build_headers(self, headers):
        if headers is None:
            return self.__default_headers_list

        h = dict(self.__default_headers_lc)
        empty = self.__empty_set

        if not isinstance(headers, dict):
            raise TypeError("headers must be a dict")

        for k, v in headers.items():
            if not isinstance(k, (str, bytes)):
                raise TypeError(
                    f"header name must be str or bytes, got {type(k).__name__}"
                )

            if isinstance(k, bytes):
                k = k.decode("latin-1")

            k = k.strip().lower()
            if not k:
                raise ValueError("header name cannot be empty")

            if v is None:
                pass
            elif isinstance(v, bytes):
                v = v.decode("latin-1")
            elif isinstance(v, str):
                pass
            else:
                raise TypeError(
                    f"header value for '{k}' must be str or bytes, "
                    f"got {type(v).__name__}"
                )

            h[k] = v

        return [f"{k};" if v in empty else f"{k}: {v}" for k, v in h.items()]

    def __set_default_headers(self):
        if "user-agent" not in self.__default_headers:
            self.__default_headers["user-agent"] = f"redc/{redc.__version__}"

        self.__default_headers_lc = {
            k.lower(): v for k, v in self.__default_headers.items()
        }
        empty = self.__empty_set
        self.__default_headers_list = [
            f"{k};" if v in empty else f"{k}: {v}"
            for k, v in self.__default_headers_lc.items()
        ]
