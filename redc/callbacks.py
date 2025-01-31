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
