import inspect
from typing import Callable


class Callback:
    def __init__(self, callback: Callable[[bytes, int], None]):
        self.callback = callback
        self._validate_callback()

    def _validate_callback(self):
        signature = inspect.signature(self.callback)

        parameters = signature.parameters
        num_parameters = len(parameters)

        if num_parameters != 2:
            raise TypeError(
                f"Callback function must accept two arguments only callback(data: bytes, total_size: int), but it accepts {num_parameters}."
            )
