import requests
import urllib3
from requests.exceptions import InvalidURL
from urllib.parse import quote


# The unreserved URI characters (RFC 3986)
UNRESERVED_SET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" + "0123456789-._~")


def unquote_unreserved(uri):
    """Un-escape any percent-escape sequences in a URI that are unreserved
    characters. This leaves all reserved, illegal and non-ASCII bytes encoded.
    :rtype: str
    """
    parts = uri.split('%')
    for i in range(1, len(parts)):
        h = parts[i][0:2]
        if len(h) == 2 and h.isalnum():
            try:
                c = chr(int(h, 16))
            except ValueError:
                raise InvalidURL("Invalid percent-escape sequence: '%s'" % h)

            if c in UNRESERVED_SET:
                parts[i] = c + parts[i][2:]
            else:
                parts[i] = '%' + parts[i]
        else:
            parts[i] = '%' + parts[i]
    return ''.join(parts)


def patched_requote_uri(uri):
    """Re-quote the given URI.
    This function passes the given URI through an unquote/quote cycle to
    ensure that it is fully and consistently quoted.
    :rtype: str
    """
    safe_with_percent = "!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~"
    safe_without_percent = "!\"#$&\'()*+,-./:;<=>?@[\\]^_`{|}~"
    try:
        # Unquote only the unreserved characters
        # Then quote only illegal characters (do not quote reserved,
        # unreserved, or '%')
        return quote(unquote_unreserved(uri), safe=safe_with_percent)
    except InvalidURL:
        # We couldn't unquote the given URI, so let's try quoting it, but
        # there may be unquoted '%'s in the URI. We need to make sure they're
        # properly quoted so they do not cause issues elsewhere.
        return quote(uri, safe=safe_without_percent)


def patched_encode_target(target):
    return target


def unquote_request_uri():
    try:
        requests.utils.requote_uri.__code__ = patched_requote_uri.__code__
    except Exception:
        pass

    try:
        urllib3.util.url._encode_target.__code__ = patched_encode_target.__code__
    except Exception:
        pass
