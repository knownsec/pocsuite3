import requests
from requests.sessions import Session
import json

from requests.structures import CaseInsensitiveDict


def extract_dict(text, sep, sep2="="):
    """Split the string into a dictionary according to the split method

    :param text: Split text
    :param sep: The first character of the split, usually'\n'
    :param sep2: The second character of the split, the default is '='
    :return: Return a dict type, the key is the 0th position of sep2,
     and the value is the first position of sep2.
     Only the text can be converted into a dictionary,
     if the text is of other types, an error will occur
    """
    _dict = CaseInsensitiveDict([l.split(sep2, 1) for l in text.split(sep)])
    return _dict


def httpraw(raw: str, ssl: bool = False, **kwargs):
    """
    Send the original HTTP packet request, if you set the parameters such as headers in the parameters, the parameters
    you set will be sent

    :param raw: Original packet text
    :param ssl: whether is HTTPS
    :param kwargs: Support setting of parameters in requests
    :return:requests.Response
    """
    raw = raw.strip()
    # Clear up unnecessary spaces
    raws = list(map(lambda x: x.strip(), raw.splitlines()))
    try:
        method, path, protocol = raws[0].split(" ")
    except Exception:
        raise Exception("Protocol format error")
    post = None
    _json = None
    if method.upper() == "POST":
        index = 0
        for i in raws:
            index += 1
            if i.strip() == "":
                break
        if len(raws) == index:
            raise Exception
        tmp_headers = raws[1:index - 1]
        tmp_headers = extract_dict('\n'.join(tmp_headers), '\n', ": ")
        postData = raws[index]
        try:
            json.loads(postData)
            _json = postData
        except ValueError:
            post = postData
    else:
        tmp_headers = extract_dict('\n'.join(raws[1:]), '\n', ": ")
    netloc = "http" if not ssl else "https"
    host = tmp_headers.get("Host", None)
    if host is None:
        raise Exception("Host is None")
    del tmp_headers["Host"]
    url = "{0}://{1}".format(netloc, host + path)

    kwargs.setdefault('allow_redirects', True)
    kwargs.setdefault('data', post)
    kwargs.setdefault('headers', tmp_headers)
    kwargs.setdefault('json', _json)

    with Session() as session:
        return session.request(method=method, url=url, **kwargs)


def patch_addraw():
    requests.httpraw = httpraw
