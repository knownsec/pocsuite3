import requests
from requests._internal_utils import to_native_string
from requests.compat import is_py3


def get_redirect_target(self, resp):
    """hook requests.Session.get_redirect_target method"""
    if resp.is_redirect:
        location = resp.headers['location']
        if is_py3:
            location = location.encode('latin1')

        # fix https://github.com/psf/requests/issues/4926
        encoding_list = ['utf-8']
        if resp.encoding and resp.encoding not in encoding_list:
            encoding_list.append(resp.encoding)
        if resp.apparent_encoding and resp.apparent_encoding not in encoding_list:
            encoding_list.append(resp.apparent_encoding)
        encoding_list.append('latin1')

        for encoding in encoding_list:
            try:
                return to_native_string(location, encoding)
            except Exception:
                pass
    return None


def patch_redirect():
    requests.Session.get_redirect_target = get_redirect_target
