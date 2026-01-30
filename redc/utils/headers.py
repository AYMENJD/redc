import re


LINK_SPLITTER = re.compile(r",(?=\s*<)")
LINK_MATCHER = re.compile(r"\s*<([^>]+)>\s*(.*)")
PARAM_MATCHER = re.compile(r';\s*([a-zA-Z0-9\-\*]+)\s*=\s*(?:"([^"]*)"|([^,;]*))')


def check_key_dict(key: str, data: dict):
    key = key.lower()
    for k in data.keys():
        if key == k.lower():
            return True

    return False


def parse_link_header(header):
    if not header:
        return None

    links = []

    for part in LINK_SPLITTER.split(header):
        link = LINK_MATCHER.match(part)
        if not link:
            continue

        data = {"url": link.group(1)}

        for p in PARAM_MATCHER.finditer(link.group(2)):
            key = p.group(1).lower()
            value = p.group(2) if p.group(2) is not None else p.group(3)

            data[key] = value

        links.append(data)

    return links


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
    def parse_history(raw_headers: bytes) -> list["History"]:
        text = raw_headers.decode("iso-8859-1")
        blocks = text.split("\r\n\r\n")

        history = []

        for block in blocks:
            if not block.strip():
                continue

            lines = block.splitlines()
            if not lines:
                continue

            status_line = lines[0]
            parts = status_line.split(" ", 2)
            if len(parts) < 2:
                continue

            http_version = parts[0].replace("HTTP/", "")
            try:
                status_code = int(parts[1])
            except ValueError:
                continue

            headers = Headers()
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k] = v.strip()

            history.append(
                History(
                    url=headers.get("location"),
                    http_version=http_version,
                    headers=headers,
                    status_code=status_code,
                )
            )

        return history


class History:
    __slots__ = ("url", "http_version", "headers", "status_code")

    def __init__(
        self,
        *,
        url: str,
        http_version: str,
        headers: Headers,
        status_code: int,
    ):
        self.url = url
        self.http_version = http_version
        self.headers = headers
        self.status_code = status_code

    def __repr__(self):
        return (
            f"<History [{self.status_code}] HTTP/{self.http_version} url={self.url!r}>"
        )
