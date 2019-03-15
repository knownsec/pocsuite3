import requests
from requests._internal_utils import to_native_string
from requests.compat import is_py3


def get_redirect_target(self, resp):
    """hook requests.Session.get_redirect_target method"""
    if resp.is_redirect:
        location = resp.headers['location']
        if is_py3:
            location = location.encode('latin1')
        encoding = resp.encoding if resp.encoding else 'utf-8'
        return to_native_string(location, encoding)
    return None


def patch_redirect():
    requests.Session.get_redirect_target = get_redirect_target
