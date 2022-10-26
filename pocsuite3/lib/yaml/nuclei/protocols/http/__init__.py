import itertools
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum

import requests

from pocsuite3.lib.core.common import check_file, get_file_items
from pocsuite3.lib.core.log import LOGGER as logger
from pocsuite3.lib.yaml.nuclei.operators import (ExtractDSL, ExtractJSON,
                                                 ExtractKval, Extractor,
                                                 ExtractorType, ExtractRegex,
                                                 ExtractXPath, MatchBinary,
                                                 MatchDSL, Matcher,
                                                 MatcherType, MatchRegex,
                                                 MatchSize, MatchStatusCode,
                                                 MatchWords)
from pocsuite3.lib.yaml.nuclei.protocols.common.replacer import marker_replace


class AttackType(Enum):
    BatteringRamAttack = "batteringram"
    PitchForkAttack = "pitchfork"
    ClusterBombAttack = "clusterbomb"


class HTTPMethod(Enum):
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


# HttpRequest contains a http request to be made from a template
@dataclass
class HttpRequest:
    # Operators for the current request go here.
    matchers: list[Matcher] = field(default_factory=list)
    extractors: list[Extractor] = field(default_factory=list)
    matchers_condition:  str = 'or'

    # Path contains the path/s for the HTTP requests. It supports variables as placeholders.
    path: list[str] = field(default_factory=list)

    # Raw contains HTTP Requests in Raw format.
    raw: list[str] = field(default_factory=list)

    # ID is the optional id of the request
    id: str = ''

    name: str = ''
    # Attack is the type of payload combinations to perform.
    attack: AttackType = 'batteringram'

    # Method is the HTTP Request Method.
    method: HTTPMethod = 'GET'

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
    pipeline_concurrent_connections = 0

    # PipelineRequestsPerConnection is number of requests to send per connection when pipelining.
    pipeline_requests_per_connection = 0

    # Threads specifies number of threads to use sending requests. This enables Connection Pooling.
    threads: int = 0

    # MaxSize is the maximum size of http response body to read in bytes.
    max_size: int = 0

    # TODO
    # cookie-reuse accepts boolean input and false as default, This option not work on pocsuite3
    cookie_reuse: bool = False

    read_all: bool = False
    redirects: bool = False
    pipeline: bool = False
    unsafe: bool = False
    race: bool = False

    # TODO
    # Request condition allows checking for condition between multiple requests for writing complex checks and
    # exploits involving multiple HTTP request to complete the exploit chain.

    req_condition: bool = False

    stop_at_first_match: bool = True
    skip_variables_check: bool = False
    iterate_all: bool = False
    digest_username: str = ''
    digest_password: str = ''


def getMatchPart(part: str, response: requests.Response, return_bytes: bool = False) -> str:
    result = b''
    headers = '\n'.join(f'{k}: {v}' for k, v in response.headers.items()).encode('utf-8')

    if part == 'all':
        result = headers + b'\n\n' + response.content
    elif part in ['', 'body']:
        result = response.content
    elif part in ['header', 'all_headers']:
        result = headers

    return result if return_bytes else result.decode('utf-8')


def HttpMatch(request: HttpRequest, response: requests.Response):
    matchers = request.matchers
    matchers_result = []

    for i, matcher in enumerate(matchers):
        matcher_res = False
        item = getMatchPart(matcher.part, response, return_bytes=matcher.type == MatcherType.BinaryMatcher)

        if matcher.type == MatcherType.StatusMatcher:
            matcher_res = MatchStatusCode(matcher, response.status_code)
            logger.debug(f'matcher: {matcher}, result: {matcher_res}')

        elif matcher.type == MatcherType.SizeMatcher:
            matcher_res = MatchSize(matcher, len(item))
            logger.debug(f'matcher: {matcher}, result: {matcher_res}')

        elif matcher.type == MatcherType.WordsMatcher:
            matcher_res, _ = MatchWords(matcher, item, {})
            logger.debug(f'matcher: {matcher}, result: {matcher_res}')

        elif matcher.type == MatcherType.RegexMatcher:
            matcher_res, _ = MatchRegex(matcher, item)
            logger.debug(f'matcher: {matcher}, result: {matcher_res}')

        elif matcher.type == MatcherType.BinaryMatcher:
            matcher_res, _ = MatchBinary(matcher, item)
            logger.debug(f'matcher: {matcher}, result: {matcher_res}')

        elif matcher.type == MatcherType.DSLMatcher:
            matcher_res = MatchDSL(matcher, {})
            logger.debug(f'matcher: {matcher}, result: {matcher_res}')

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


def HttpExtract(request: HttpRequest, response: requests.Response):
    extractors = request.extractors
    extractors_result = []

    for extractor in extractors:
        item = getMatchPart(extractor.part, response)

        res = None
        if extractor.type == ExtractorType.RegexExtractor:
            res = ExtractRegex(extractor, item)
            logger.debug(f'extractor: {extractor}, result: {res}')
        elif extractor.type == ExtractorType.KValExtractor:
            res = ExtractKval(extractor, response.headers)
            logger.debug(f'extractor: {extractor}, result: {res}')
        elif extractor.type == ExtractorType.XPathExtractor:
            res = ExtractXPath(extractor, item)
            logger.debug(f'extractor: {extractor}, result: {res}')
        elif extractor.type == ExtractorType.JSONExtractor:
            res = ExtractJSON(extractor, item)
            logger.debug(f'extractor: {extractor}, result: {res}')
        elif ExtractorType.type == ExtractorType.DSLExtractor:
            res = ExtractDSL(extractor, {})
            logger.debug(f'extractor: {extractor}, result: {res}')

        if res:
            extractors_result.append(res)
    return extractors_result


def extract_dict(text, line_sep='\n', kv_sep='='):
    """Split the string into a dictionary according to the split method
    """
    _dict = OrderedDict([i.split(kv_sep, 1) for i in text.split(line_sep)])
    return _dict


def payloadGenerator(request: HttpRequest) -> OrderedDict:
    payloads = OrderedDict()
    payloads.update(request.payloads)

    for k, v in payloads.items():
        if isinstance(v, str) and check_file(v):
            payloads[k] = get_file_items(v)

    payload_keys, payload_vals = payloads.keys(), payloads.values()
    payload_vals = [i if isinstance(i, list) else [i] for i in payload_vals]

    if request.attack == AttackType.PitchForkAttack:
        for instance in zip(*payload_vals):
            yield dict(zip(payload_keys, instance))
    else:
        for instance in itertools.product(*payload_vals):
            yield dict(zip(payload_keys, instance))


def httpRequestGenerator(request: HttpRequest, dynamic_values: OrderedDict):
    for payload_instance in payloadGenerator(request):
        payload_instance.update(dynamic_values)

        for path in request.path + request.raw:

            method, url, headers, data, kwargs = '', '', '', '', OrderedDict()
            # base request
            if path.startswith('{{'):
                method = request.method.value
                headers = request.headers
                data = request.body
                url = path

            # raw
            else:
                raw = path.strip()
                raws = list(map(lambda x: x.strip(), raw.splitlines()))
                method, path, _ = raws[0].split(' ')
                url = f'{{{{BaseURL}}}}{path}'

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
                    data = raws[index]
                else:
                    headers = extract_dict('\n'.join(raws[1:]), '\n', ": ")

            kwargs.setdefault('allow_redirects', request.redirects)
            kwargs.setdefault('data', data)
            kwargs.setdefault('headers', headers)

            yield (method, marker_replace(url, payload_instance), marker_replace(kwargs, payload_instance))
