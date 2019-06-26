# Borrowed code from werkzeug: https://github.com/pallets/werkzeug
import hmac

_builtin_safe_str_cmp = getattr(hmac, "compare_digest", None)


def safe_str_cmp(a, b):
    """This function compares strings in somewhat constant time.  This
    requires that the length of at least one string is known in advance.
    Returns `True` if the two strings are equal, or `False` if they are not.
    .. versionadded:: 0.7
    """
    if isinstance(a, text_type):
        a = a.encode("utf-8")
    if isinstance(b, text_type):
        b = b.encode("utf-8")

    if _builtin_safe_str_cmp is not None:
        return _builtin_safe_str_cmp(a, b)

    if len(a) != len(b):
        return False

    rv = 0
    if PY2:
        for x, y in izip(a, b):
            rv |= ord(x) ^ ord(y)
    else:
        for x, y in izip(a, b):
            rv |= x ^ y

    return rv == 0


class Authorization(object):
    def __init__(self, auth_type, auth_options):
        if auth_type.lower() == "bearer":
            raise NotImplementedError(f"Auth scheme not implemented: {auth_type}")

        self.type = auth_type
        self.options = auth_options or {}

        self.realm = self.options.get("realm")
        self.username = self.options.get("realm")
        self.password = self.options.get("realm")

    def get(self, key):
        return self.options.get(key)

    def __getitem__(self, key):
        return self.options[key]

    def __setitem__(self, key, value):
        raise NotImplementedError()


def make_response(res):
    if isinstance(res, sanic.response.BaseHTTPResponse):
        return res
    elif isinstance(res, tuple) or isinstance(res, list):
        return sanic.response.HTTPResponse(*res)
    else:
        return sanic.response.HTTPResponse(res)
