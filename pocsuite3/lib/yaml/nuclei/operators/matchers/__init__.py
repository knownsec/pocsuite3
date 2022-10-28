import binascii
import re
from dataclasses import dataclass, field
from enum import Enum

from pocsuite3.lib.yaml.nuclei.protocols.common.expressions import Evaluate


class MatcherType(Enum):
    StatusMatcher = "status"
    SizeMatcher = "size"
    WordsMatcher = "word"
    RegexMatcher = "regex"
    BinaryMatcher = "binary"
    DSLMatcher = "dsl"


# Matcher is used to match a part in the output from a protocol.
@dataclass
class Matcher:
    # Type is the type of the matcher.
    type: MatcherType = 'word'

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
    status: list[int] = field(default_factory=list)

    # Size is the acceptable size for the response
    size: list[int] = field(default_factory=list)

    # Words contains word patterns required to be present in the response part.
    words: list[str] = field(default_factory=list)

    # Regex contains Regular Expression patterns required to be present in the response part.
    regex: list[str] = field(default_factory=list)

    # Binary are the binary patterns required to be present in the response part.
    binary: list[str] = field(default_factory=list)

    # DSL are the dsl expressions that will be evaluated as part of nuclei matching rules.
    dsl: list[str] = field(default_factory=list)

    # Encoding specifies the encoding for the words field if any.
    encoding: str = ''

    # CaseInsensitive enables case-insensitive matches. Default is false.
    case_insensitive: bool = False

    # MatchAll enables matching for all matcher values. Default is false.
    match_all: bool = False


def MatchStatusCode(matcher: Matcher, statusCode: int):
    """MatchStatusCode matches a status code check against a corpus
    """
    return statusCode in matcher.status


def MatchSize(matcher: Matcher, length: int):
    """MatchSize matches a size check against a corpus
    """
    return length in matcher.size


def MatchWords(matcher: Matcher, corpus: str, data: dict) -> (bool, list):
    """MatchWords matches a word check against a corpus
    """
    if matcher.case_insensitive:
        corpus = corpus.lower()

    matchedWords = []
    for i, word in enumerate(matcher.words):
        word = Evaluate(word, data)

        if word not in corpus:
            if matcher.condition == 'and':
                return False, []
            elif matcher.condition == 'or':
                continue

        if matcher.condition == 'or' and not matcher.match_all:
            return True, [word]

        matchedWords.append(word)

        if len(matcher.words) - 1 == i and not matcher.match_all:
            return True, MatchWords

    if len(matchedWords) > 0 and matcher.match_all:
        return True, MatchWords

    return False, []


def MatchRegex(matcher: Matcher, corpus: str) -> (bool, list):
    """MatchRegex matches a regex check against a corpus
    """
    matchedRegexes = []
    for i, regex in enumerate(matcher.regex):
        if not re.search(regex, corpus):
            if matcher.condition == 'and':
                return False, []
            elif matcher.condition == 'or':
                continue
        currentMatches = re.findall(regex, corpus)
        if matcher.condition == 'or' and not matcher.match_all:
            return True, matchedRegexes

        matchedRegexes = matchedRegexes + currentMatches
        if len(matcher.regex) - 1 == i and not matcher.match_all:
            return True, matchedRegexes
    if len(matchedRegexes) > 0 and matcher.match_all:
        return True, matchedRegexes

    return False, []


def MatchBinary(matcher: Matcher, corpus: bytes) -> (bool, list):
    """MatchBinary matches a binary check against a corpus
    """
    matchedBinary = []
    for i, binary in enumerate(matcher.binary):
        binary = binascii.unhexlify(binary)
        if binary not in corpus:
            if matcher.condition == 'and':
                return False, []
            elif matcher.condition == 'or':
                continue
        if matcher.condition == 'or':
            return True, [binary]
        MatchBinary.append(binary)
        if len(matcher.binary) - 1 == i:
            return True, matchedBinary
    return False, []


def MatchDSL(matcher: Matcher, data: dict) -> bool:
    """MatchDSL matches on a generic map result
    """

    for i, expression in enumerate(matcher.dsl):
        result = Evaluate('{{%s}}' % expression, data)
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
