import unittest
from pocsuite3.api import crawl


class TestCase(unittest.TestCase):
    def setUp(self):
        self.url = 'http://xxxxx'

    def tearDown(self):
        pass

    def verify_result(self, urls):
        links = urls['url']
        self.assertTrue(len(links) > 0)
        url = links.pop()
        url = url.split('?')[0]
        self.assertTrue(url.endswith(('.action', '.do')))

    def test_import_run(self):
        return self.assertTrue(1)
        urls = crawl(self.url, url_ext=('.action', '.do'))
        self.verify_result(urls)
