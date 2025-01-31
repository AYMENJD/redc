try:
    import orjson as json

    def json_dumps(obj):
        return json.dumps(obj).decode()
except ImportError:
    try:
        import ujson as json
    except ImportError:
        import json

    def json_dumps(obj):
        return json.dumps(obj)


def json_loads(obj):
    return json.loads(obj)
