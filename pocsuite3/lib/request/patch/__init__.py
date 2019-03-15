from .remove_ssl_verify import remove_ssl_verify
from .remove_warnings import disable_warnings
from .hook_request import patch_session
from .add_httpraw import patch_addraw
from .hook_request_redirect import patch_redirect

def patch_all():
    disable_warnings()
    remove_ssl_verify()
    patch_session()
    patch_addraw()
    patch_redirect()