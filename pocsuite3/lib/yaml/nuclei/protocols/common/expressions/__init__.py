import base64 as py_built_in_base64
import binascii
import datetime
import gzip as py_built_in_gzip
import hashlib
import hmac as py_hmac
import html
import inspect
import random
import re
import string
import time
import urllib.parse
import zlib as py_built_in_zlib
from functools import wraps
from typing import get_type_hints, Union

import chardet
from pkg_resources import parse_version
from pocsuite3.lib.core.log import LOGGER as logger
from pocsuite3.lib.yaml.nuclei.protocols.common.expressions.safe_eval import safe_eval

UNRESOLVED_VARIABLE = '---UNRESOLVED-VARIABLE---'


class Marker:
    # General marker (open/close)
    General = "§"
    # ParenthesisOpen marker - begin of a placeholder
    ParenthesisOpen = "{{"
    # ParenthesisClose marker - end of a placeholder
    ParenthesisClose = "}}"


def auto_convert_types(func):
    @wraps(func)
    def check_and_convert_args(*args, **kwargs):
        # Get the function's parameter names and types
        signature = inspect.signature(func)
        parameter_types = get_type_hints(func)

        # Convert args to a list so we can modify its elements
        args_list = list(args)

        # Check and convert positional arguments
        for i, (arg_name, arg_value) in enumerate(zip(signature.parameters.keys(), args)):
            arg_type = parameter_types.get(arg_name)
            if arg_type and not isinstance(arg_value, arg_type):
                try:
                    if arg_type is str and isinstance(arg_value, bytes):
                        try:
                            encoding = chardet.detect(arg_value)['encoding'] or 'utf-8'
                            args_list[i] = arg_value.decode(encoding)
                        except Exception:
                            args_list[i] = str(arg_value)
                    elif arg_type is bytes and isinstance(arg_value, str):
                        args_list[i] = arg_value.encode('utf-8')
                except ValueError:
                    pass
        # Check and convert keyword arguments
        for arg_name, arg_value in kwargs.items():
            arg_type = parameter_types.get(arg_name)
            if arg_type and not isinstance(arg_value, arg_type):
                try:
                    if arg_type is str and isinstance(arg_value, bytes):
                        try:
                            encoding = chardet.detect(arg_value)['encoding'] or 'utf-8'
                            kwargs[arg_name] = arg_value.decode(encoding)
                        except Exception:
                            kwargs[arg_name] = str(arg_value)
                    elif arg_type is bytes and isinstance(arg_value, str):
                        kwargs[arg_name] = arg_value.encode('utf-8')
                except ValueError:
                    pass
        # Call the original function with the potentially converted arguments
        return func(*args_list, **kwargs)

    return check_and_convert_args


def aes_gcm(key: Union[bytes, str], plaintext: Union[bytes, str]) -> bytes:
    """
    AES GCM encrypts a string with key

    Example:
        Input: {{hex_encode(aes_gcm("AES256Key-32Characters1234567890", "exampleplaintext"))}}
        Output: ec183a153b8e8ae7925beed74728534b57a60920c0b009eaa7608a34e06325804c096d7eebccddea3e5ed6c4
    """
    # TODO
    raise NotImplementedError


def base64(src: Union[bytes, str]) -> str:
    """Base64 encodes a string

    Example:
        Input: base64("Hello")
        Output: SGVsbG8=
    """
    if not isinstance(src, bytes):
        src = src.encode('utf-8')
    return py_built_in_base64.b64encode(src).decode('utf-8')


def base64_decode(src: Union[bytes, str]) -> bytes:
    """
    Base64 decodes a string

    Example:
        Input: base64_decode("SGVsbG8=")
        Output: b"Hello"
    """
    return py_built_in_base64.b64decode(src)


def base64_py(src: Union[bytes, str]) -> str:
    """
    Encodes string to base64 like python (with new lines)

    Example:
        Input: base64_py("Hello")
        Output: "SGVsbG8=\n"
    """
    if not isinstance(src, bytes):
        src = src.encode('utf-8')
    return py_built_in_base64.encodebytes(src).decode('utf-8')


@auto_convert_types
def concat(*arguments: str) -> str:
    """
    Concatenates the given number of arguments to form a string

    Example:
        Input: concat("Hello", 123, "world)
        Output: Hello123world
    """
    return ''.join(map(str, arguments))


@auto_convert_types
def compare_versions(version_to_check: str, *constraints: str) -> bool:
    """
    Compares the first version argument with the provided constraints

    Example:
        Input: compare_versions('v1.0.0', '>v0.0.1', '<v1.0.1')
        Output: True
    """
    v1 = parse_version(version_to_check)
    for constraint in constraints:
        constraint = constraint.replace('==', '=')
        operator = re.findall(r'^[<>=]*', constraint)[0]
        if not operator:
            operator = '='
        v2 = parse_version(constraint.lstrip('<>='))
        if v1 < v2 and operator not in ['<', '<=']:
            return False
        elif v1 == v2 and operator not in ['=', '<=', '>=']:
            return False
        elif v1 > v2 and operator not in ['>', '>=']:
            return False
    return True


@auto_convert_types
def contains(inp: str, substring: str) -> bool:
    """
    Verifies if a string contains a substring

    Example:
        Input: contains("Hello", "lo")
        Output: True
    """
    return substring in inp


@auto_convert_types
def contains_all(inp: str, *substrings: str) -> bool:
    """
    Verify if any input contains all the substrings

    Example:
        Input: contains_all("Hello everyone", "lo", "every")
        Output: True
    """
    return all(map(lambda s: s in inp, substrings))


@auto_convert_types
def contains_any(inp: str, *substrings: str) -> bool:
    """
    Verifies if an input contains any of substrings

    Example:
        Input: contains_any("Hello everyone", "abc", "llo")
        Output: True
    """
    return any(map(lambda s: s in inp, substrings))


def dec_to_hex(number: Union[str, int]) -> str:
    """
    Transforms the input number into hexadecimal format

    Example:
        Input: dec_to_hex(7001)
        Output: 1b59
    """
    if not isinstance(number, int):
        number = int(number)
    return hex(number)[2:]


def hex_to_dec(hex_number: Union[str, int]) -> int:
    """
    Transforms the input hexadecimal number into decimal format

    Example:
        Input: hex_to_dec("ff")
               hex_to_dec("0xff")
        Output: 255
    """
    return int(str(hex_number), 16)


def bin_to_dec(binary_number: Union[str, int]) -> int:
    """
    Transforms the input binary number into a decimal format

    Example:
        Input: bin_to_dec("0b1010")
               bin_to_dec(1010)
        Output: 10
    """
    return int(str(binary_number), 2)


def oct_to_dec(octal_number: Union[str, int]) -> int:
    """
    Transforms the input octal number into a decimal format

    Example:
        Input: oct_to_dec("0o1234567")
               oct_to_dec(1234567)
        Output: 342391
    """
    return int(str(octal_number), 8)


def generate_java_gadget(gadget: str, cmd: str, encoding: str) -> str:
    """
    Generates a Java Deserialization Gadget

    Example:
        Input: generate_java_gadget("dns", "{{interactsh-url}}", "base64")
    """
    # TODO
    raise NotImplementedError


def gzip(inp: Union[str, bytes]) -> bytes:
    """
    Compresses the input using GZip

    Example:
        Input: base64(gzip("Hello"))
        Output: H4sIAI9GUGMC//NIzcnJBwCCidH3BQAAAA==
    """
    if not isinstance(inp, bytes):
        inp = inp.encode('utf-8')
    return py_built_in_gzip.compress(inp)


@auto_convert_types
def gzip_decode(inp: bytes) -> bytes:
    """
    Decompresses the input using GZip

    Example:
        Input: gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"))
        Output: b"Hello"
    """
    return py_built_in_gzip.decompress(inp)


def zlib(inp: Union[str, bytes]) -> bytes:
    """
    Compresses the input using Zlib

    Example:
        Input: base64(zlib("Hello"))
        Output: eJzzSM3JyQcABYwB9Q==
    """
    if not isinstance(inp, bytes):
        inp = inp.encode('utf-8')
    return py_built_in_zlib.compress(inp)


@auto_convert_types
def zlib_decode(inp: bytes) -> bytes:
    """
    Decompresses the input using Zlib

    Example:
        Input: zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5"))
        Output: b"Hello"
    """
    return py_built_in_zlib.decompress(inp)


@auto_convert_types
def hex_decode(inp: str) -> bytes:
    """
    Hex decodes the given input

    Example:
        Input: hex_decode("6161")
        Output: b"aa"
    """
    return binascii.unhexlify(inp)


def hex_encode(inp: Union[str, bytes]) -> str:
    """
    Hex encodes the given input

    Example:
        Input: hex_encode("aa")
        Output: 6161
    """
    if not isinstance(inp, bytes):
        inp = inp.encode('utf-8')
    return binascii.hexlify(inp).decode('utf-8')


@auto_convert_types
def html_escape(inp: str) -> str:
    """
    HTML escapes the given input

    Example:
        Input: html_escape("<body>test</body>")
        Output: &lt;body&gt;test&lt;/body&gt;
    """
    return html.escape(inp)


@auto_convert_types
def html_unescape(inp: str) -> str:
    """
    HTML un-escapes the given input

    Example:
        Input: html_unescape("&lt;body&gt;test&lt;/body&gt;")
        Output: <body>test</body>
    """
    return html.unescape(inp)


def md5(inp: Union[str, bytes]) -> str:
    """
    Calculates the MD5 (Message Digest) hash of the input

    Example:
        Input: md5("Hello")
        Output: 8b1a9953c4611296a827abf8c47804d7
    """
    if not isinstance(inp, bytes):
        inp = inp.encode('utf-8')
    m = hashlib.md5()
    m.update(inp)
    return m.hexdigest()


@auto_convert_types
def mmh3(inp: str) -> str:
    """
    Calculates the MMH3 (MurmurHash3) hash of an input

    Example:
        Input: mmh3("Hello")
        Output: "316307400"
    """

    try:
        import mmh3 as py_mmh3
    except ImportError:
        logger.error('Python extension for MurmurHash (MurmurHash3) is not installed. '
                     'Reason: https://github.com/knownsec/pocsuite3/issues/359, '
                     'You can locate the packages here: https://pypi.org/project/mmh3/')
        return "0"

    return str(py_mmh3.hash(inp))


def print_debug(*args) -> None:
    """
    Prints the value of a given input or expression. Used for debugging.

    Example:
        Input: print_debug(1+2, "Hello")
        Output: 3 Hello
    """
    # TODO
    raise NotImplementedError


def rand_base(length: int, optional_charset: str = string.ascii_letters + string.digits) -> str:
    """
    Generates a random sequence of given length string from an optional charset (defaults to letters and numbers)

    Example:
        Input: rand_base(5, "abc")
        Output: caccb
    """
    return ''.join(random.choice(optional_charset) for _ in range(length))


def rand_char(optional_charset: str = string.ascii_letters + string.digits) -> str:
    """
    Generates a random character from an optional character set (defaults to letters and numbers)

    Example:
        Input: rand_char("abc")
        Output: a
    """
    return random.choice(optional_charset)


def rand_int(optional_min: int = 0, optional_max: int = 2147483647) -> int:
    """
    Generates a random integer between the given optional limits (defaults to 0 - MaxInt32)

    Example:
        Input: rand_int(1, 10)
        Output: 6
    """
    return random.randint(optional_min, optional_max)


def rand_text_alpha(length: int, optional_bad_chars: str = '') -> str:
    """
    Generates a random string of letters, of given length, excluding the optional cutset characters

    Example:
        Input: rand_text_alpha(10, "abc")
        Output: WKozhjJWlJ
    """
    charset = ''.join(i if i not in optional_bad_chars else '' for i in string.ascii_letters)
    return ''.join(random.choice(charset) for _ in range(length))


def rand_text_alphanumeric(length: int, optional_bad_chars: str = '') -> str:
    """
    Generates a random alphanumeric string, of given length without the optional cutset characters

    Example:
        Input: rand_text_alphanumeric(10, "ab12")
        Output: NthI0IiY8r
    """
    charset = ''.join(i if i not in optional_bad_chars else '' for i in string.ascii_letters + string.digits)
    return ''.join(random.choice(charset) for _ in range(length))


def rand_text_numeric(length: int, optional_bad_numbers: str = '') -> str:
    """
    Generates a random numeric string of given length without the optional set of undesired numbers

    Example:
        Input: rand_text_numeric(10, 123)
        Output: 0654087985
    """
    charset = ''.join(i if i not in optional_bad_numbers else '' for i in string.digits)
    return ''.join(random.choice(charset) for _ in range(length))


@auto_convert_types
def regex(pattern: str, inp: str) -> bool:
    """
    Tests the given regular expression against the input string

    Example:
        Input: regex("H([a-z]+)o", "Hello")
        Output: True
    """
    return list(filter(lambda item: item.strip() != "", re.findall(pattern, inp, re.IGNORECASE))) != []


@auto_convert_types
def remove_bad_chars(inp: str, cutset: str) -> str:
    """
    Removes the desired characters from the input

    Example:
        Input: remove_bad_chars("abcd", "bc")
        Output: ad
    """
    return ''.join(i if i not in cutset else '' for i in inp)


@auto_convert_types
def repeat(inp: str, count: int) -> str:
    """
    Repeats the input string the given amount of times

    Example:
        Input: repeat("../", 5)
        Output: ../../../../../
    """
    return inp * count


@auto_convert_types
def replace(inp: str, old: str, new: str) -> str:
    """
    Replaces a given substring in the given input

    Example:
        Input: replace("Hello", "He", "Ha")
        Output: Hallo
    """
    return inp.replace(old, new)


@auto_convert_types
def replace_regex(source: str, pattern: str, replacement: str) -> str:
    """
    Replaces substrings matching the given regular expression in the input

    Example:
        Input: replace_regex("He123llo", "(\\d+)", "")
        Output: Hello
    """
    return re.sub(pattern, replacement, source)


@auto_convert_types
def reverse(inp: str) -> str:
    """
    Reverses the given input

    Example:
        Input: reverse("abc")
        Output: cba
    """
    return inp[::-1]


def sha1(inp: Union[bytes, str]) -> str:
    """
    Calculates the SHA1 (Secure Hash 1) hash of the input

    Example:
        Input: sha1("Hello")
        Output: f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0
    """
    if not isinstance(inp, bytes):
        inp = inp.encode('utf-8')

    s = hashlib.sha1()
    s.update(inp)
    return s.hexdigest()


def sha256(inp: Union[bytes, str]) -> str:
    """
    Calculates the SHA256 (Secure Hash 256) hash of the input

    Example:
        Input: sha256("Hello")
        Output: 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969
    """
    if not isinstance(inp, bytes):
        inp = inp.encode('utf-8')

    s = hashlib.sha256()
    s.update(inp)
    return s.hexdigest()


@auto_convert_types
def to_lower(inp: str) -> str:
    """
    Transforms the input into lowercase characters

    Example:
        Input: to_lower("HELLO")
        Output: hello
    """
    return inp.lower()


@auto_convert_types
def to_upper(inp: str) -> str:
    """
    Transforms the input into uppercase characters

    Example:
        Input: to_upper("hello")
        Output: HELLO
    """
    return inp.upper()


@auto_convert_types
def trim(inp: str, cutset: str) -> str:
    """
    Returns a slice of the input with all leading and trailing Unicode code points contained in cutset removed

    Example:
        Input: trim("aaaHelloddd", "ad")
        Output: Hello
    """
    return inp.strip(cutset)


@auto_convert_types
def trim_left(inp: str, cutset: str) -> str:
    """
    Returns a slice of the input with all leading Unicode code points contained in cutset removed

    Example:
        Input: trim_left("aaaHelloddd", "ad")
        Output: Helloddd
    """
    return inp.lstrip(cutset)


@auto_convert_types
def trim_prefix(inp: str, prefix: str) -> str:
    """
    Returns the input without the provided leading prefix string

    Example:
        Input: trim_prefix("aaHelloaa", "aa")
        Output: Helloaa
    """
    if inp.startswith(prefix):
        return inp[len(prefix):]
    return inp


@auto_convert_types
def trim_right(inp: str, cutset: str) -> str:
    """
    Returns a string, with all trailing Unicode code points contained in cutset removed

    Example:
        Input: trim_right("aaaHelloddd", "ad")
        Output: aaaHello
    """
    return inp.rstrip(cutset)


@auto_convert_types
def trim_space(inp: str) -> str:
    """
    Returns a string, with all leading and trailing white space removed, as defined by Unicode

    Example:
        Input: trim_space(" Hello ")
        Output: Hello
    """
    return inp.strip()


@auto_convert_types
def trim_suffix(inp: str, suffix: str) -> str:
    """
    Returns input without the provided trailing suffix string

    Example:
        Input: trim_suffix("aaHelloaa", "aa")
        Output: aaHello
    """
    if inp.endswith(suffix):
        return inp[:-len(suffix)]
    return inp


def unix_time(optional_seconds: int = 0) -> int:
    """
    Returns the current Unix time (number of seconds elapsed since January 1, 1970 UTC) with the added optional seconds

    Example:
        Input: unix_time(10)
        Output: 1639568278
    """
    return int(time.time()) + optional_seconds


@auto_convert_types
def url_decode(inp: str) -> str:
    """
    URL decodes the input string
    Example:
        Input: url_decode("https:%2F%2Fprojectdiscovery.io%3Ftest=1")
        Output: https://projectdiscovery.io?test=1
    """
    return urllib.parse.unquote_plus(inp)


@auto_convert_types
def url_encode(inp: str) -> str:
    """
    URL encodes the input string

    Example:
        Input: url_encode("https://projectdiscovery.io/test?a=1")
        Output: https%3A%2F%2Fprojectdiscovery.io%2Ftest%3Fa%3D1
    """
    return urllib.parse.quote_plus(inp)


def wait_for(seconds: int) -> bool:
    """
    Pauses the execution for the given amount of seconds

    Example:
        Input: wait_for(10)
        Output: True
    """
    time.sleep(seconds)
    return True


@auto_convert_types
def join(separator: str, *elements: str) -> str:
    """
    Joins the given elements using the specified separator

    Example:
        Input: join("_", 123, "hello", "world")
        Output: 123_hello_world
    """
    return separator.join(map(str, elements))


def hmac(algorithm: str, data: Union[bytes, str], secret: Union[bytes, str]) -> str:
    """
    hmac function that accepts a hashing function type with data and secret

    Example:
        Input: hmac("sha1", "test", "scrt")
        Output: 8856b111056d946d5c6c92a21b43c233596623c6
    """
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    if not isinstance(secret, bytes):
        secret = secret.encode('utf-8')

    return py_hmac.new(secret, data, algorithm).hexdigest()


def date_time(date_time_format: str, optional_unix_time: int = int(time.time())) -> str:
    """
    Returns the formatted date time using simplified or go style layout for the current or the given unix time

    Example:
        Input: date_time("%Y-%m-%d %H:%M")
               date_time("%Y-%m-%d %H:%M", 1654870680)
        Output: 2022-06-10 14:18
    """
    return datetime.datetime.utcfromtimestamp(optional_unix_time).strftime(date_time_format)


@auto_convert_types
def to_unix_time(inp: str, layout: str = "%Y-%m-%d %H:%M:%S") -> int:
    """
    Parses a string date time using default or user given layouts, then returns its Unix timestamp

    Example:
        Input: to_unix_time("2022-01-13 16:30:10")
        Output: 1642091410
    """
    return int(time.mktime(datetime.datetime.strptime(inp, layout).timetuple()))


@auto_convert_types
def starts_with(inp: str, *prefix: str) -> bool:
    """
    Checks if the string starts with any of the provided substrings

    Example:
        Input: starts_with("Hello", "He")
        Output: True
    """
    return any(inp.startswith(p) for p in prefix)


@auto_convert_types
def line_starts_with(inp: str, *prefix: str) -> bool:
    """
    Checks if any line of the string starts with any of the provided substrings

    Example:
        Input: line_starts_with("Hi\nHello", "He")
        Output: True
    """
    for line in inp.splitlines():
        for p in prefix:
            if line.startswith(p):
                return True
    return False


@auto_convert_types
def ends_with(inp: str, *suffix: str) -> bool:
    """
    Checks if the string ends with any of the provided substrings

    Example:
        Input: ends_with("Hello", "lo")
        Output: True
    """
    return any(inp.endswith(s) for s in suffix)


@auto_convert_types
def line_ends_with(inp: str, *suffix: str) -> bool:
    """
    Checks if any line of the string ends with any of the provided substrings

    Example:
        Input: line_ends_with("Hello\nHi", "lo")
        Output: True
    """
    for line in inp.splitlines():
        for s in suffix:
            if line.endswith(s):
                return True
    return False


def evaluate(inp: str, dynamic_values: dict = None) -> str:
    """
    evaluate checks if the match contains a dynamic variable, for each
    found one we will check if it's an expression and can be compiled,
    it will be evaluated and the results will be returned.
    """

    if dynamic_values is None:
        dynamic_values = {}

    variables = {
        'aes_gcm': aes_gcm,
        'base64': base64,
        'base64_decode': base64_decode,
        'base64_py': base64_py,
        'concat': concat,
        'compare_versions': compare_versions,
        'contains': contains,
        'contains_all': contains_all,
        'contains_any': contains_any,
        'dec_to_hex': dec_to_hex,
        'hex_to_dec': hex_to_dec,
        'bin_to_dec': bin_to_dec,
        'oct_to_dec': oct_to_dec,
        'generate_java_gadget': generate_java_gadget,
        'gzip': gzip,
        'gzip_decode': gzip_decode,
        'zlib': zlib,
        'zlib_decode': zlib_decode,
        'hex_decode': hex_decode,
        'hex_encode': hex_encode,
        'html_escape': html_escape,
        'html_unescape': html_unescape,
        'md5': md5,
        'mmh3': mmh3,
        'print_debug': print_debug,
        'rand_base': rand_base,
        'rand_char': rand_char,
        'rand_int': rand_int,
        'rand_text_alpha': rand_text_alpha,
        'rand_text_alphanumeric': rand_text_alphanumeric,
        'rand_text_numeric': rand_text_numeric,
        'regex': regex,
        'remove_bad_chars': remove_bad_chars,
        'repeat': repeat,
        'replace': replace,
        'replace_regex': replace_regex,
        'reverse': reverse,
        'sha1': sha1,
        'sha256': sha256,
        'to_lower': to_lower,
        'to_upper': to_upper,
        'trim': trim,
        'trim_left': trim_left,
        'trim_prefix': trim_prefix,
        'trim_right': trim_right,
        'trim_space': trim_space,
        'trim_suffix': trim_suffix,
        'unix_time': unix_time,
        'url_decode': url_decode,
        'url_encode': url_encode,
        'wait_for': wait_for,
        'join': join,
        'hmac': hmac,
        'date_time': date_time,
        'to_unix_time': to_unix_time,
        'starts_with': starts_with,
        'line_starts_with': line_starts_with,
        'ends_with': ends_with,
        'line_ends_with': line_ends_with,
    }
    variables.update(dynamic_values)
    open_marker, close_marker = Marker.ParenthesisOpen, Marker.ParenthesisClose
    expressions = {}
    max_iterations, iterations = 250, 0
    data = inp

    while iterations <= max_iterations:
        iterations += 1
        index_open_marker = data.find(open_marker)
        if index_open_marker < 0:
            break

        index_open_marker_offset = index_open_marker + len(open_marker)
        should_search_close_marker = True
        close_marker_found = False
        inner_data = data
        skip = index_open_marker_offset

        while should_search_close_marker:
            index_close_marker = inner_data.find(close_marker, skip)
            if index_close_marker < 0:
                should_search_close_marker = False
                continue
            index_close_marker_offset = index_close_marker + len(close_marker)
            potential_match = inner_data[index_open_marker_offset:index_close_marker]
            try:
                result = safe_eval(potential_match, variables)

                if UNRESOLVED_VARIABLE in str(result):
                    return UNRESOLVED_VARIABLE
                expressions[potential_match] = result
                close_marker_found = True
                should_search_close_marker = False
            except Exception:
                import traceback
                traceback.print_exc()
                skip = index_close_marker_offset

        if close_marker_found:
            data = data[index_close_marker_offset:]
        else:
            data = data[index_open_marker_offset:]

    result = inp
    for k, v in expressions.items():
        logger.debug(f'[+] Expressions: {k} -> {v}')
        k = f'{open_marker}{k}{close_marker}'
        if k == inp:
            return v
        elif isinstance(v, bytes):
            if not isinstance(result, bytes):
                result = result.encode()
            k = k.encode()
            result = result.replace(k, v)
        else:
            result = result.replace(k, str(v))
    return result


if __name__ == '__main__':
    print(evaluate("{{to_lower(rand_base(5))}}"))
    print(evaluate("{{base64('World')}}"))
    print(evaluate("{{base64(Hello)}}", {'Hello': 'World'}))
