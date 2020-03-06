import requests
from requests.sessions import Session
import json

from requests.structures import CaseInsensitiveDict


def extract_dict(text, sep, sep2="="):
    """根据分割方式将字符串分割为字典

    :param text: 分割的文本
    :param sep: 分割的第一个字符 一般为'\n'
    :param sep2: 分割的第二个字符，默认为'='
    :return: 返回一个dict类型，key为sep2的第0个位置，value为sep2的第一个位置
        只能将文本转换为字典，若text为其他类型则会出错
    """
    _dict = CaseInsensitiveDict([l.split(sep2, 1) for l in text.split(sep)])
    return _dict


def httpraw(raw: str, ssl: bool = False, **kwargs):
    """
    发送原始HTTP封包请求,如果你在参数中设置了例如headers参数，将会发送你设置的参数

    :param raw:原始封包文本
    :param ssl:是否是HTTPS
    :param kwargs:支持对requests中的参数进行设置
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
