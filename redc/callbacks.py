import inspect
from typing import Callable


class StreamCallback:
    """A class for creating a stream callback"""

    def __init__(self, callback: Callable[[bytes, int], None]):
        """A callback handler for streaming data

        Example:
            .. code-block:: python

                >>> def callback(data: bytes, data_size: int):
                ...     print(f"Received {len(data)}")
                >>> stream_callback = StreamCallback(callback)
                >>> client.get("https://example.com/", stream_callback=stream_callback)

        Parameters:
            callback (``Callable[[bytes, int], None]``):
                A function that accepts two arguments: data (``bytes``) and data_size (``int``)
                The function cannot be asynchronous
        """

        self.callback = callback
        self._validate_callback()

    def _validate_callback(self):
        if inspect.iscoroutinefunction(self.callback):
            raise TypeError("Callback function cannot be asynchronous")

        signature = inspect.signature(self.callback)

        parameters = signature.parameters
        num_parameters = len(parameters)

        if num_parameters != 2:
            raise TypeError(
                f"Callback function must accept two arguments only callback(data: bytes, data_size: int) but it accepts {num_parameters}."
            )


class ProgressCallback:
    """A class for creating a progress callback"""

    def __init__(self, callback: Callable[[int, int, int, int], None]):
        """A callback handler for progress updates

        Example:
            .. code-block:: python

                >>> def callback(dltotal: int, dlnow: int, ultotal: int, ulnow: int):
                ...     print(f"Downloaded {dlnow}/{dltotal}, Uploaded {ulnow}/{ultotal}")
                >>> progress_callback = ProgressCallback(callback)
                >>> client.get("https://example.com/", progress_callback=progress_callback)

        Parameters:
            callback (``Callable[[int, int, int, int], None]``):
                A function that accepts four arguments:
                - dltotal (``int``): Total bytes expected to be downloaded
                - dlnow (``int``): Bytes downloaded so far
                - ultotal (``int``): Total bytes expected to be uploaded
                - ulnow (``int``): Bytes uploaded so far
                The function cannot be asynchronous.
        """

        self.callback = callback
        self._validate_callback()

    def _validate_callback(self):
        if inspect.iscoroutinefunction(self.callback):
            raise TypeError("Callback function cannot be asynchronous")

        signature = inspect.signature(self.callback)
        parameters = signature.parameters
        num_parameters = len(parameters)

        if num_parameters != 4:
            raise TypeError(
                f"Callback function must accept exactly four arguments (dltotal: int, dlnow: int, ultotal: int, ulnow: int) but it accepts {num_parameters}."
            )
