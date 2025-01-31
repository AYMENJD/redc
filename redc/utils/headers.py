def check_key_dict(key: str, data: dict):
    key = key.lower()
    for k in data.keys():
        if key == k.lower():
            return True

    return False


class Headers(dict):
    def __init__(self, *args, **kwargs):
        super().__init__()
        self.update(*args, **kwargs)

    def __setitem__(self, key, value):
        super().__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super().__getitem__(key.lower())

    def __delitem__(self, key):
        super().__delitem__(key.lower())

    def __contains__(self, key):
        return super().__contains__(key.lower())

    def get(self, key, default=None):
        return super().get(key.lower(), default)

    def pop(self, key, default=None):
        return super().pop(key.lower(), default)

    def setdefault(self, key, default=None):
        return super().setdefault(key.lower(), default)

    def update(self, *args, **kwargs):
        if args:
            if len(args) > 1:
                raise TypeError(f"update expected at most 1 arguments, got {len(args)}")
            other = args[0]
            if isinstance(other, dict):
                for key, value in other.items():
                    self[key] = value
            elif hasattr(other, "__iter__"):
                for key, value in other:
                    self[key] = value
            else:
                raise TypeError(f"'dict' object expected, got {type(other).__name__}")
        for key, value in kwargs.items():
            self[key] = value

    @staticmethod
    def parse_headers(headers_str: bytes):
        lines = headers_str.decode().splitlines()
        headers = Headers()
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key] = value.strip()
        return headers
