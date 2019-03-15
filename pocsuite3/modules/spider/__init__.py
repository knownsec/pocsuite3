import re
from urllib.parse import urlparse, urljoin
from html.parser import HTMLParser
from pocsuite3.lib.request import requests
from pocsuite3.lib.core.settings import IMG_EXT
from pocsuite3.lib.core.data import logger


class LinkParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for (key, value) in attrs:
                if key == 'href':
                    new_url = urljoin(self.base_url, value)
                    new_url = new_url.split('#')[0].strip()
                    if self.is_origin(new_url):
                        if self.url_ext:
                            url = new_url.split('?')[0].strip()
                            if url.endswith(self.url_ext):
                                self.urls['url'].add(new_url)
                        else:
                            self.urls['url'].add(new_url)

        if tag == 'img':
            for (key, value) in attrs:
                if key == 'src':
                    new_url = urljoin(self.base_url, value)
                    new_url = new_url.split('?')[0].strip()
                    if new_url.lower().endswith(IMG_EXT) and self.is_origin(new_url):
                        self.urls['img'].add(new_url)

        if tag == 'script':
            for (key, value) in attrs:
                if key == 'src':
                    new_url = urljoin(self.base_url, value)
                    new_url = new_url.split('?')[0].strip()
                    if new_url.lower().endswith('.js') and self.is_origin(new_url):
                        self.urls['js'].add(new_url)

    def is_origin(self, url):
        url_part = urlparse(url)
        return self.origin == (url_part.scheme, url_part.netloc)

    def get_links(self, url, url_ext=()):
        # TODO:
        # set base url from base tag or current url
        self.base_url = url
        url_part = urlparse(url)
        self.origin = (url_part.scheme, url_part.netloc)
        self.urls = {
            'url': set(),
            'js': set(),
            'img': set()
        }
        if isinstance(url_ext, str):
            url_ext = set(url_ext)

        self.url_ext = url_ext

        debug_msg = "crawler visiting: {0}".format(url)
        logger.debug(debug_msg)

        resp = requests.get(url)
        content_type = resp.headers.get('content-type', '')
        if 'text/html' in content_type:
            html = resp.text
            self.feed(html)

        return self.urls


def get_redirect_url(url):
    # TODO:
    # regex need more test cases
    meta_regex = '(?is)\<meta[^<>]*?url\s*=([\d\w://\\\\.?=&;%-]*)[^<>]*'
    body_regex = '''(?is)\<body[^<>]*?location[\s\.\w]*=['"]?([\d\w://\\\\.?=&;%-]*)['"]?[^<>]*'''
    js_regex = '''(?is)<script.*?>[^<>]*?location\.(?:replace|href|assign)[=\("']*([\d\w://\\\\.?=&;%-]*)[^<>]*?</script>'''

    resp = requests.get(url)
    true_url = resp.url

    for regex in [meta_regex, body_regex, js_regex]:
        result = re.search(regex, resp.text)
        if result:
            redirect_url = result.group(1)
            true_url = urljoin(url, redirect_url)
            break
    return true_url


def crawl(url, max_pages=50, url_ext=()):
    true_url = get_redirect_url(url)
    pages_need_visit = [true_url]
    pages_count = 0
    urls = {
        'url': set(),
        'js': set(),
        'img': set()
    }
    while pages_count < max_pages and pages_need_visit:
        url = pages_need_visit.pop(0)
        try:
            parser = LinkParser()
            links = parser.get_links(url, url_ext=url_ext)
            for k, v in links.items():
                urls[k] = urls[k].union(v)

            pages_count += len(links['url'])
            pages_need_visit.extend([i for i in links['url']])

        except Exception as ex:
            logger.error(ex)

    return urls


if __name__ == '__main__':
    import pprint
    urls = crawl('http://example.com:8000/sipo/', url_ext=('.action', '.do'))
    pprint.pprint(urls)
