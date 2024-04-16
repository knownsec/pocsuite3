import binascii
import re
from dataclasses import dataclass, field
from lxml import html
from typing import List

from pocsuite3.lib.yaml.nuclei.model import CaseInsensitiveEnum
from pocsuite3.lib.yaml.nuclei.protocols.common.expressions import evaluate, Marker


class MatcherType(CaseInsensitiveEnum):
    StatusMatcher = "status"
    SizeMatcher = "size"
    WordsMatcher = "word"
    RegexMatcher = "regex"
    BinaryMatcher = "binary"
    DSLMatcher = "dsl"
    XpathMatcher = "xpath"


@dataclass
class Matcher:
    """Matcher is used to match a part in the output from a protocol.
    """

    # Type is the type of the matcher.
    type: MatcherType = MatcherType.WordsMatcher

    # Condition is the optional condition between two matcher variables. By default, the condition is assumed to be OR.
    condition: str = 'or'

    # Part is the part of the request response to match data from. Each protocol exposes a lot of different parts.
    # default matched part is body if not defined.
    part: str = 'body'

    # Negative specifies if the match should be reversed. It will only match if the condition is not true.
    negative: bool = False

    # Name of the matcher. Name should be lowercase and must not contain spaces or underscores (_).
    name: str = ''

    # Status are the acceptable status codes for the response.
    status: List[int] = field(default_factory=list)

    # Size is the acceptable size for the response
    size: List[int] = field(default_factory=list)

    # Words contains word patterns required to be present in the response part.
    words: List[str] = field(default_factory=list)

    # Regex contains Regular Expression patterns required to be present in the response part.
    regex: List[str] = field(default_factory=list)

    # Xpath contains xpath patterns required to be present in the response part.
    xpath: List[str] = field(default_factory=list)

    # Binary are the binary patterns required to be present in the response part.
    binary: List[str] = field(default_factory=list)

    # DSL are the dsl expressions that will be evaluated as part of nuclei matching rules.
    dsl: List[str] = field(default_factory=list)

    # Encoding specifies the encoding for the words field if any.
    encoding: str = ''

    # CaseInsensitive enables case-insensitive matches. Default is false.
    case_insensitive: bool = False

    # MatchAll enables matching for all matcher values. Default is false.
    match_all: bool = False


def match_status_code(matcher: Matcher, status_code: int):
    """Matches a status code check against a corpus
    """
    return status_code in matcher.status


def match_size(matcher: Matcher, length: int):
    """Matches a size check against a corpus
    """
    return length in matcher.size


def match_words(matcher: Matcher, corpus: str, data: dict) -> (bool, list):
    """Matches a word check against a corpus
    """
    if matcher.case_insensitive:
        corpus = corpus.lower()

    matched_words = []
    for i, word in enumerate(matcher.words):
        word = evaluate(word, data)
        if matcher.encoding == 'hex':
            try:
                word = binascii.unhexlify(word).decode()
            except (ValueError, UnicodeDecodeError):
                pass
        if matcher.case_insensitive:
            word = word.lower()

        if word not in corpus:
            if matcher.condition == 'and':
                return False, []
            elif matcher.condition == 'or':
                continue

        if matcher.condition == 'or' and not matcher.match_all:
            return True, [word]

        matched_words.append(word)

        if len(matcher.words) - 1 == i and not matcher.match_all:
            return True, matched_words

    if len(matched_words) > 0 and matcher.match_all:
        return True, matched_words

    return False, []


def match_regex(matcher: Matcher, corpus: str) -> (bool, list):
    """Matches a regex check against a corpus
    """
    matched_regexes = []
    for i, regex in enumerate(matcher.regex):
        if not re.search(regex, corpus):
            if matcher.condition == 'and':
                return False, []
            elif matcher.condition == 'or':
                continue

        current_matches = re.findall(regex, corpus)
        if matcher.condition == 'or' and not matcher.match_all:
            return True, matched_regexes

        matched_regexes = matched_regexes + current_matches
        if len(matcher.regex) - 1 == i and not matcher.match_all:
            return True, matched_regexes

    if len(matched_regexes) > 0 and matcher.match_all:
        return True, matched_regexes

    return False, []


def match_binary(matcher: Matcher, corpus: bytes) -> (bool, list):
    """Matches a binary check against a corpus
    """
    matched_binary = []
    for i, binary in enumerate(matcher.binary):
        binary = binascii.unhexlify(binary)
        if binary not in corpus:
            if matcher.condition == 'and':
                return False, []
            elif matcher.condition == 'or':
                continue

        if matcher.condition == 'or':
            return True, [binary]

        matched_binary.append(binary)
        if len(matcher.binary) - 1 == i:
            return True, matched_binary

    return False, []


def match_dsl(matcher: Matcher, data: dict) -> bool:
    """Matches on a generic map result
    """
    for i, expression in enumerate(matcher.dsl):
        result = evaluate(f'{Marker.ParenthesisOpen}{expression}{Marker.ParenthesisClose}', data)
        if not isinstance(result, bool):
            if matcher.condition == 'and':
                return False
            elif matcher.condition == 'or':
                continue

        if result is False:
            if matcher.condition == 'and':
                return False
            elif matcher.condition == 'or':
                continue

        if len(matcher.dsl) - 1 == i:
            return True
    return False


def match_xpath(matcher: Matcher, body: str) -> (bool, list):
    """Matches xpath check against a body.
    """
    # Convert the body string to etree.HTML object for xpath manipulations
    if body is None:
        return False
    body_tree = html.fromstring(body)
    matched_xpaths = []

    for i, xpath_pattern in enumerate(matcher.xpath):
        try:
            # Applying xpath on the HTML and capturing the result
            result = body_tree.xpath(xpath_pattern)
            if not result:
                # If result is empty, the xpath expression did not match anything in the HTML body
                if matcher.condition == 'and':
                    return False, []
                elif matcher.condition == 'or':
                    continue

            if matcher.condition == 'or' and not matcher.match_all:
                return True, [result]

            matched_xpaths.append(result)

            if len(matcher.xpath) - 1 == i and not matcher.match_all:
                return True, matched_xpaths

        except Exception as e:
            print(f"Error while matching with XPath {xpath_pattern}. Error: {str(e)}")

    if len(matched_xpaths) > 0 and matcher.match_all:
        return True, matched_xpaths

    return False, []
