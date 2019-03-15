import requests
from requests import Session
from requests_toolbelt.cookies.forgetful import ForgetfulCookieJar
from requests_toolbelt.multipart import MultipartDecoder
from requests_toolbelt.utils.dump import dump_response
from requests_toolbelt.utils.dump import dump_all
from .patch import patch_all

__all__ = (requests, Session, ForgetfulCookieJar, MultipartDecoder, dump_response, dump_all, patch_all)

# patch requests
patch_all()

# compatible older pocsutie
req = requests
