import requests

from pocsuite3.lib.request.patch.remove_ssl_verify import remove_ssl_verify
from pocsuite3.lib.request.patch.remove_warnings import disable_warnings
from pocsuite3.lib.request.patch.add_httpraw import patch_addraw
from pocsuite3.lib.request.patch.hook_request_redirect import patch_redirect
from pocsuite3.lib.request.patch.hook_urllib3_parse_url import patch_urllib3_parse_url
from pocsuite3.lib.request.patch.unquote_request_uri import unquote_request_uri


def patch_requests():
    # fix https://github.com/urllib3/urllib3/issues/1790
    patch_urllib3_parse_url()
    unquote_request_uri()
    disable_warnings()
    remove_ssl_verify()
    patch_addraw()
    patch_redirect()


patch_requests()
