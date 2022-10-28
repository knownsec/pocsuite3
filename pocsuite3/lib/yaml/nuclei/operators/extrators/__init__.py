import re
from dataclasses import dataclass, field
from enum import Enum

import jq
import lxml
from requests.structures import CaseInsensitiveDict

from pocsuite3.lib.yaml.nuclei.protocols.common.expressions import Evaluate


class ExtractorType(Enum):
    RegexExtractor = "regex"
    KValExtractor = "kval"
    XPathExtractor = "xpath"
    JSONExtractor = "json"
    DSLExtractor = "dsl"


# Extractor is used to extract part of response using a regex.
@dataclass
class Extractor:
    # Name of the extractor. Name should be lowercase and must not contain spaces or underscores (_).
    name: str = ''

    # Type is the type of the extractor.
    type: ExtractorType = 'regex'

    # Regex contains the regular expression patterns to extract from a part.
    regex: list[str] = field(default_factory=list)

    # Group specifies a numbered group to extract from the regex.
    group: int = 0

    # kval contains the key-value pairs present in the HTTP response header.
    kval: list[str] = field(default_factory=list)

    # JSON allows using jq-style syntax to extract items from json response
    json: list[str] = field(default_factory=list)

    # XPath allows using xpath expressions to extract items from html response
    xpath: list[str] = field(default_factory=list)

    # Attribute is an optional attribute to extract from response XPath.
    attribute: str = ''

    # Part is the part of the request response to extract data from.
    part: str = ''

    # Internal, when set to true will allow using the value extracted in the next request for some protocols (like HTTP).
    internal: bool = False

    # CaseInsensitive enables case-insensitive extractions. Default is false.
    case_insensitive: bool = False


def ExtractRegex(e: Extractor, corpus: str) -> dict:
    """Extract data from response based on a Regular Expression.
    """
    results = {'internal': {}, 'external': {}, 'extraInfo': []}
    for regex in e.regex:
        matches = re.search(regex, corpus)
        if not matches:
            continue

        lastindex = matches.lastindex

        group = e.group if lastindex and lastindex >= e.group else 0
        res = matches.group(group)
        if not res:
            continue

        if e.name:
            if e.internal:
                results['internal'][e.name] = res
            else:
                results['external'][e.name] = res
            return results
        else:
            results['extraInfo'].append(res)
    return results


def ExtractKval(e: Extractor, headers: CaseInsensitiveDict) -> dict:
    """Extract key: value/key=value formatted data from Response Header/Cookie
    """
    if not isinstance(headers, CaseInsensitiveDict):
        headers = CaseInsensitiveDict(headers)

    results = {'internal': {}, 'external': {}, 'extraInfo': []}
    for k in e.kval:
        res = ''
        if k in headers:
            res = headers[k]
        # kval extractor does not accept dash (-) as input and must be substituted with underscore (_)
        elif k.replace('_', '-') in headers:
            res = headers[k.replace('_', '-')]
        if not res:
            continue

        if e.name:
            if e.internal:
                results['internal'][e.name] = res
            else:
                results['external'][e.name] = res
            return results
        else:
            results['extraInfo'].append(res)
    return results


def ExtractXPath(e: Extractor, corpus: str) -> dict:
    """A xpath extractor example to extract value of href attribute from HTML response
    """
    results = {'internal': {}, 'external': {}, 'extraInfo': []}
    if corpus.startswith('<?xml'):
        doc = lxml.etree.XML(corpus)
    else:
        doc = lxml.etree.HTML(corpus)

    for x in e.xpath:
        nodes = doc.xpath(x)
        for n in nodes:
            res = ''
            if e.attribute:
                res = n.attrib[e.attribute]
            else:
                res = n.text
            if not res:
                continue

            if e.name:
                if e.internal:
                    results['internal'][e.name] = res
                else:
                    results['external'][e.name] = res
                return results
            else:
                results['extraInfo'].append(res)
    return results


def ExtractJSON(e: Extractor, corpus: str) -> dict:
    """Extract data from JSON based response in JQ like syntax
    """
    results = {'internal': {}, 'external': {}, 'extraInfo': []}
    for j in e.json:
        res = jq.compile(j).input(corpus).all()
        if not res:
            continue

        if e.name:
            if e.internal:
                results['internal'][e.name] = res
            else:
                results['external'][e.name] = res
            return results
        else:
            results['extraInfo'].append(res)
    return results


def ExtractDSL(e: Extractor, data: dict) -> dict:
    """Extract data from the response based on a DSL expressions
    """
    results = {'internal': {}, 'external': {}, 'extraInfo': []}
    for expression in e.dsl:
        res = Evaluate('{{%s}}' % expression, data)
        if res == expression:
            continue
        if e.name:
            if e.internal:
                results['internal'][e.name] = res
            else:
                results['external'][e.name] = res
            return results
        else:
            results['extraInfo'].append(res)
    return results
