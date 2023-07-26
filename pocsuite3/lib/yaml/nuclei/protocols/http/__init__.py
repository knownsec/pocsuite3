from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Union, List, Optional

from requests_toolbelt.utils import dump

from pocsuite3.lib.core.data import AttribDict
from pocsuite3.lib.core.log import LOGGER as logger
from pocsuite3.lib.request import requests
from pocsuite3.lib.yaml.nuclei.model import CaseInsensitiveEnum
from pocsuite3.lib.yaml.nuclei.operators import (Extractor, ExtractorType,
                                                 Matcher, MatcherType,
                                                 extract_dsl, extract_json,
                                                 extract_kval, extract_regex,
                                                 extract_xpath, match_binary,
                                                 match_dsl, match_regex,
                                                 match_size, match_status_code,
                                                 match_words)
from pocsuite3.lib.yaml.nuclei.protocols.common.generators import AttackType, payload_generator
from pocsuite3.lib.yaml.nuclei.protocols.common.interactsh import InteractshClient
from pocsuite3.lib.yaml.nuclei.protocols.common.replacer import (
    UnresolvedVariableException, UNRESOLVED_VARIABLE, marker_replace, Marker)


class HTTPMethod(CaseInsensitiveEnum):
    HTTPGet = "GET"
    HTTPHead = "HEAD"
    HTTPPost = "POST"
    HTTPPut = "PUT"
    HTTPDelete = "DELETE"
    HTTPConnect = "CONNECT"
    HTTPOptions = "OPTIONS"
    HTTPTrace = "TRACE"
    HTTPPatch = "PATCH"
    HTTPPurge = "PURGE"
    HTTPDebug = "DEBUG"


@dataclass
class HttpRequest:
    """HttpRequest contains a http request to be made from a template
    """

    # Operators for the current request go here.
    matchers: List[Matcher] = field(default_factory=list)
    extractors: List[Extractor] = field(default_factory=list)
    matchers_condition: str = 'or'

    # Path contains the path/s for the HTTP requests. It supports variables as placeholders.
    path: List[str] = field(default_factory=list)

    # Raw contains HTTP Requests in Raw format.
    raw: List[str] = field(default_factory=list)

    # ID is the optional id of the request
    id: str = ''

    name: str = ''
    # Attack is the type of payload combinations to perform.
    attack: AttackType = AttackType.BatteringRamAttack

    # Method is the HTTP Request Method.
    method: Optional[HTTPMethod] = HTTPMethod.HTTPGet

    # Body is an optional parameter which contains HTTP Request body.
    body: str = ''

    # Payloads contains any payloads for the current request.
    payloads: dict = field(default_factory=dict)

    # Headers contains HTTP Headers to send with the request.
    headers: dict = field(default_factory=dict)

    # RaceCount is the number of times to send a request in Race Condition Attack.
    race_count: int = 0

    # MaxRedirects is the maximum number of redirects that should be followed.
    max_redirects: int = 0

    # PipelineConcurrentConnections is number of connections to create during pipelining.
    pipeline_concurrent_connections: int = 0

    # PipelineRequestsPerConnection is number of requests to send per connection when pipelining.
    pipeline_requests_per_connection: int = 0

    # Threads specifies number of threads to use sending requests. This enables Connection Pooling.
    threads: int = 0

    # MaxSize is the maximum size of http response body to read in bytes.
    max_size: int = 0

    cookie_reuse: bool = False

    read_all: bool = False
    redirects: bool = False
    host_redirects: bool = False
    pipeline: bool = False
    unsafe: bool = False
    race: bool = False

    # Request condition allows checking for condition between multiple requests for writing complex checks and
    # exploits involving multiple HTTP request to complete the exploit chain.
    req_condition: bool = False

    stop_at_first_match: bool = True
    skip_variables_check: bool = False
    iterate_all: bool = False
    digest_username: str = ''
    digest_password: str = ''


def http_response_to_dsl_map(resp: requests.Response):
    """Converts an HTTP response to a map for use in DSL matching
    """
    data = AttribDict()
    if not isinstance(resp, requests.Response):
        return data

    for k, v in resp.cookies.items():
        data[k.lower()] = v
    for k, v in resp.headers.items():
        data[k.lower().replace('-', '_')] = v

    req_headers_raw = '\n'.join(f'{k}: {v}' for k, v in resp.request.headers.items())
    req_body = resp.request.body
    if not req_body:
        req_body = b''
    if not isinstance(req_body, bytes):
        req_body = req_body.encode()
    resp_headers_raw = '\n'.join(f'{k}: {v}' for k, v in resp.headers.items())
    resp_body = resp.content

    data['request'] = req_headers_raw.encode() + b'\n\n' + req_body
    data['response'] = resp_headers_raw.encode() + b'\n\n' + resp_body
    data['status_code'] = resp.status_code
    data['body'] = resp_body
    data['all_headers'] = resp_headers_raw
    data['header'] = resp_headers_raw
    data['kval_extractor_dict'] = {}
    data['kval_extractor_dict'].update(resp.cookies)
    data['kval_extractor_dict'].update(resp.headers)

    return data


def http_get_match_part(part: str, resp_data: dict, return_bytes: bool = False) -> str:
    result = ''
    if part == '':
        part = 'body'

    if part in resp_data:
        result = resp_data[part]

    if return_bytes and not isinstance(result, bytes):
        result = str(result).encode()
    elif not return_bytes and isinstance(result, bytes):
        try:
            result = result.decode()
        except UnicodeDecodeError:
            result = str(result)
    return result


def http_match(request: HttpRequest, resp_data: dict, interactsh=None):
    matchers = request.matchers
    matchers_result = []

    if 'interactsh_' in str(matchers) and isinstance(interactsh, InteractshClient):
        interactsh.poll()
        resp_data['interactsh_protocol'] = '\n'.join(interactsh.interactsh_protocol)
        resp_data['interactsh_request'] = '\n'.join(interactsh.interactsh_request)
        resp_data['interactsh_response'] = '\n'.join(interactsh.interactsh_response)
    else:
        resp_data['interactsh_protocol'] = ''
        resp_data['interactsh_request'] = ''
        resp_data['interactsh_response'] = ''

    for i, matcher in enumerate(matchers):
        matcher_res = False
        item = http_get_match_part(matcher.part, resp_data, matcher.type == MatcherType.BinaryMatcher)

        if matcher.type == MatcherType.StatusMatcher:
            matcher_res = match_status_code(matcher, resp_data.get('status_code', 0))

        elif matcher.type == MatcherType.SizeMatcher:
            matcher_res = match_size(matcher, len(item))

        elif matcher.type == MatcherType.WordsMatcher:
            matcher_res, _ = match_words(matcher, item, resp_data)

        elif matcher.type == MatcherType.RegexMatcher:
            matcher_res, _ = match_regex(matcher, item)

        elif matcher.type == MatcherType.BinaryMatcher:
            matcher_res, _ = match_binary(matcher, item)

        elif matcher.type == MatcherType.DSLMatcher:
            matcher_res = match_dsl(matcher, resp_data)

        if matcher.negative:
            matcher_res = not matcher_res

        logger.debug(f'[+] {matcher} -> {matcher_res}')

        if not matcher_res:
            if request.matchers_condition == 'and':
                return False
            elif request.matchers_condition == 'or':
                continue

        if request.matchers_condition == 'or':
            return True

        matchers_result.append(matcher_res)

        if len(matchers) - 1 == i:
            return True

    return False


def http_extract(request: HttpRequest, resp_data: dict):
    extractors = request.extractors
    extractors_result = {'internal': {}, 'external': {}, 'extra_info': []}

    for extractor in extractors:
        item = http_get_match_part(extractor.part, resp_data)

        res = None
        if extractor.type == ExtractorType.RegexExtractor:
            res = extract_regex(extractor, item)
        elif extractor.type == ExtractorType.KValExtractor:
            res = extract_kval(extractor, resp_data.get('kval_extractor_dict', {}))
        elif extractor.type == ExtractorType.XPathExtractor:
            res = extract_xpath(extractor, item)
        elif extractor.type == ExtractorType.JSONExtractor:
            res = extract_json(extractor, item)
        elif extractor.type == ExtractorType.DSLExtractor:
            res = extract_dsl(extractor, resp_data)

        logger.debug(f'[+] {extractor} -> {res}')
        extractors_result['internal'].update(res['internal'])
        extractors_result['external'].update(res['external'])
        extractors_result['extra_info'] += res['extra_info']
    return extractors_result


def extract_dict(text, line_sep='\n', kv_sep='='):
    """Split the string into a dictionary according to the split method
    """
    _dict = OrderedDict([i.split(kv_sep, 1) for i in text.split(line_sep)])
    return _dict


def http_request_generator(request: HttpRequest, dynamic_values: OrderedDict):
    request_count = len(request.path + request.raw)
    for payload_instance in payload_generator(request.payloads, request.attack):
        current_index = 0
        dynamic_values.update(payload_instance)
        for path in request.path + request.raw:
            current_index += 1
            method, url, headers, data, kwargs = '', '', '', '', OrderedDict()
            # base request
            username, password = request.digest_username, request.digest_password
            if path.startswith(Marker.ParenthesisOpen):
                method = request.method.value
                headers = request.headers
                data = request.body
                url = path

            # raw
            else:
                raw = path.strip()
                raws = list(map(lambda x: x.strip(), raw.splitlines()))
                method, path, _ = raws[0].split(' ')
                url = f'{Marker.ParenthesisOpen}BaseURL{Marker.ParenthesisClose}{path}'

                if method == "POST":
                    index = 0
                    for i in raws:
                        index += 1
                        if i.strip() == "":
                            break
                    if len(raws) == index:
                        raise Exception

                    headers = raws[1:index - 1]
                    headers = extract_dict('\n'.join(headers), '\n', ": ")
                    data = '\n'.join(raws[index:])
                else:
                    headers = extract_dict('\n'.join(raws[1:]), '\n', ": ")

            kwargs.setdefault('allow_redirects', request.redirects)
            kwargs.setdefault('data', data)
            kwargs.setdefault('headers', headers)
            if username or password:
                kwargs.setdefault('auth', (username, password))
            try:
                url = marker_replace(url, dynamic_values)
                kwargs = marker_replace(kwargs, dynamic_values)
            except UnresolvedVariableException:
                continue

            if 'auth' in kwargs:
                kwargs['auth'] = tuple(kwargs['auth'])
            yield method, url, kwargs, payload_instance, request_count, current_index


def execute_http_request(request: HttpRequest, dynamic_values, interactsh) -> Union[bool, list]:
    results = []
    resp_data_all = {}
    with requests.Session() as session:
        try:
            for (method, url, kwargs, payload, request_count, current_index) in http_request_generator(
                    request, dynamic_values):
                try:
                    # Redirection conditions can be specified per each template. By default, redirects are not
                    # followed. However, if desired, they can be enabled with redirects: true in request details. 10
                    # redirects are followed at maximum by default which should be good enough for most use cases.
                    # More fine grained control can be exercised over number of redirects followed by using
                    # max-redirects field.

                    if request.max_redirects:
                        session.max_redirects = request.max_redirects
                    else:
                        session.max_redirects = 10
                    response = session.request(method=method, url=url, **kwargs)
                    # for debug purpose
                    try:
                        logger.debug(dump.dump_all(response).decode('utf-8'))
                    except UnicodeDecodeError:
                        logger.debug(dump.dump_all(response))

                except Exception:
                    import traceback
                    traceback.print_exc()
                    response = None

                resp_data = http_response_to_dsl_map(response)
                if response:
                    response.close()

                extractor_res = http_extract(request, resp_data)
                for k, v in extractor_res['internal'].items():
                    if v == UNRESOLVED_VARIABLE and k in dynamic_values:
                        continue
                    else:
                        dynamic_values[k] = v

                if request.req_condition:
                    resp_data_all.update(resp_data)
                    for k, v in resp_data.items():
                        resp_data_all[f'{k}_{current_index}'] = v
                    if current_index == request_count:
                        resp_data_all.update(dynamic_values)
                        match_res = http_match(request, resp_data_all, interactsh)
                        resp_data_all = {}
                        if match_res:
                            output = {}
                            output.update(extractor_res['external'])
                            output.update(payload)
                            output['extra_info'] = extractor_res['extra_info']
                            results.append(output)
                            if request.stop_at_first_match:
                                return results
                else:
                    resp_data.update(dynamic_values)
                    match_res = http_match(request, resp_data, interactsh)
                    if match_res:
                        output = {}
                        output.update(extractor_res['external'])
                        output.update(payload)
                        output['extra_info'] = extractor_res['extra_info']
                        results.append(output)
                        if request.stop_at_first_match:
                            return results
        except Exception:
            import traceback
            traceback.print_exc()
        if results and any(results):
            return results
        else:
            return False
