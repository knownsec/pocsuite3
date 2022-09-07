from pocsuite3.lib.core.data import conf
from pocsuite3.lib.core.enums import HTTP_HEADER
from pocsuite3.lib.utils import generate_random_user_agent, urlparse
from requests.models import Request
from requests.sessions import Session
from requests.sessions import merge_cookies
from requests.cookies import RequestsCookieJar
from requests.utils import get_encodings_from_content, to_key_val_list
from requests.compat import OrderedDict, Mapping


def session_request(self, method, url,
                    params=None, data=None, headers=None, cookies=None, files=None, auth=None,
                    timeout=None,
                    allow_redirects=True, proxies=None, hooks=None, stream=None, verify=False, cert=None, json=None):
    # In order to remove headers that are set to None
    def _merge_retain_none(request_setting, session_setting, dict_class=OrderedDict):

        if session_setting is None:
            return request_setting

        if request_setting is None:
            return session_setting

        # Bypass if not a dictionary (e.g. verify)
        if not (
                isinstance(session_setting, Mapping) and
                isinstance(request_setting, Mapping)
        ):
            return request_setting

        merged_setting = dict_class(to_key_val_list(session_setting))
        merged_setting.update(to_key_val_list(request_setting))

        return merged_setting

    # Create the Request.
    if conf.get('http_headers', {}) == {}:
        conf.http_headers = {}

    merged_cookies = merge_cookies(merge_cookies(RequestsCookieJar(), self.cookies),
                                   cookies or conf.get('cookie', None))
    if not conf.get('agent', '') and HTTP_HEADER.USER_AGENT not in conf.get('http_headers', {}):
        conf.http_headers[HTTP_HEADER.USER_AGENT] = generate_random_user_agent()

    # Fix no connection adapters were found
    pr = urlparse(url)
    if pr.scheme.lower() not in ['http', 'https']:
        url = pr._replace(scheme='https' if str(pr.port).endswith('443') else 'http').geturl()

    req = Request(
        method=method.upper(),
        url=url,
        headers=_merge_retain_none(headers, conf.get('http_headers', {})),
        files=files,
        data=data or {},
        json=json,
        params=params or {},
        auth=auth,
        cookies=merged_cookies,
        hooks=hooks,
    )
    prep = self.prepare_request(req)

    if proxies is None:
        proxies = conf.get('proxies', {})

    settings = self.merge_environment_settings(
        prep.url, proxies, stream, verify, cert
    )

    timeout = timeout or conf.get("timeout", 10)
    if timeout:
        timeout = float(timeout)

    # Send the request.
    send_kwargs = {
        'timeout': timeout,
        'allow_redirects': allow_redirects,
    }
    send_kwargs.update(settings)
    resp = self.send(prep, **send_kwargs)

    if resp.encoding == 'ISO-8859-1':
        encodings = get_encodings_from_content(resp.text)
        if encodings:
            encoding = encodings[0]
        else:
            encoding = resp.apparent_encoding

        resp.encoding = encoding

    return resp


def patch_session():
    Session.request = session_request
