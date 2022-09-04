import textwrap
import unittest
from tempfile import NamedTemporaryFile

from pocsuite3.api import get_results, init_pocsuite, start_pocsuite


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_target_url_format(self):
        f = NamedTemporaryFile("w+t")
        poc_content = textwrap.dedent(
            """\
                from pocsuite3.api import POCBase, register_poc


                class TestPoC(POCBase):
                    def _verify(self):
                        result = {}
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['url'] = self.url
                        result['VerifyInfo']['scheme'] = self.scheme
                        result['VerifyInfo']['rhost'] = self.rhost
                        result['VerifyInfo']['rport'] = self.rport
                        result['VerifyInfo']['netloc'] = self.netloc
                        return self.parse_output(result)


                register_poc(TestPoC)
        """
        )
        f.write(poc_content)

        # http://127.0.0.1:8080
        f.seek(0)
        config = {
            "url": "http://127.0.0.1:8080",
            "poc": f.name,
        }
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(res[0]["result"]["VerifyInfo"]["url"], "http://127.0.0.1:8080")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "http")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 8080)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:8080")

        # https://127.0.0.1:8080
        f.seek(0)
        config = {
            "url": "https://127.0.0.1:8080",
            "poc": f.name,
        }
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(
            res[0]["result"]["VerifyInfo"]["url"], "https://127.0.0.1:8080"
        )
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "https")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 8080)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:8080")

        # 127.0.0.1
        f.seek(0)
        config = {
            "url": "127.0.0.1",
            "poc": f.name,
        }
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(res[0]["result"]["VerifyInfo"]["url"], "http://127.0.0.1:80")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "http")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 80)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:80")

        # 127.0.0.1:8443
        f.seek(0)
        config = {
            "url": "127.0.0.1:8443",
            "poc": f.name,
        }
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(
            res[0]["result"]["VerifyInfo"]["url"], "https://127.0.0.1:8443"
        )
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "https")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 8443)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:8443")
        f.close()

    def test_url_protocol_correct(self):
        f = NamedTemporaryFile("w+t")
        poc_content = textwrap.dedent(
            """\
                from pocsuite3.api import POCBase, register_poc, POC_CATEGORY


                class TestPoC(POCBase):
                    protocol = POC_CATEGORY.PROTOCOL.FTP

                    def _verify(self):
                        result = {}
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['url'] = self.url
                        result['VerifyInfo']['scheme'] = self.scheme
                        result['VerifyInfo']['rhost'] = self.rhost
                        result['VerifyInfo']['rport'] = self.rport
                        result['VerifyInfo']['netloc'] = self.netloc
                        return self.parse_output(result)


                register_poc(TestPoC)
        """
        )
        f.write(poc_content)

        # https://127.0.0.1
        f.seek(0)
        config = {"url": "https://127.0.0.1", "poc": f.name}
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(res[0]["result"]["VerifyInfo"]["url"], "ftp://127.0.0.1:21")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "ftp")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 21)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:21")

        # 127.0.0.1
        f.seek(0)
        config = {"url": "127.0.0.1", "poc": f.name}
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(res[0]["result"]["VerifyInfo"]["url"], "ftp://127.0.0.1:21")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "ftp")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 21)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:21")

        # 127.0.0.1:8821
        f.seek(0)
        config = {"url": "127.0.0.1:8821", "poc": f.name}
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(res[0]["result"]["VerifyInfo"]["url"], "ftp://127.0.0.1:8821")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "ftp")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 8821)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:8821")

        # ftp://127.0.0.1:8821
        f.seek(0)
        config = {"url": "ftp://127.0.0.1:8821", "poc": f.name}
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(res[0]["result"]["VerifyInfo"]["url"], "ftp://127.0.0.1:8821")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "ftp")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 8821)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:8821")
        f.close()

    def test_set_protocol_and_default_port(self):
        f = NamedTemporaryFile("w+t")
        poc_content = textwrap.dedent(
            """\
                from pocsuite3.api import POCBase, register_poc, POC_CATEGORY


                class TestPoC(POCBase):
                    protocol = POC_CATEGORY.PROTOCOL.FTP
                    protocol_default_port = 10086

                    def _verify(self):
                        result = {}
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['url'] = self.url
                        result['VerifyInfo']['scheme'] = self.scheme
                        result['VerifyInfo']['rhost'] = self.rhost
                        result['VerifyInfo']['rport'] = self.rport
                        result['VerifyInfo']['netloc'] = self.netloc
                        return self.parse_output(result)


                register_poc(TestPoC)
        """
        )
        f.write(poc_content)

        # https://127.0.0.1
        f.seek(0)
        config = {"url": "https://127.0.0.1", "poc": f.name}
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(res[0]["result"]["VerifyInfo"]["url"], "ftp://127.0.0.1:10086")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "ftp")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 10086)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:10086")

        # https://127.0.0.1:21
        f.seek(0)
        config = {"url": "https://127.0.0.1:21", "poc": f.name}
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(res[0]["result"]["VerifyInfo"]["url"], "ftp://127.0.0.1:21")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "ftp")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 21)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:21")
        f.close()

    def test_custom_protocol_and_default_port(self):
        f = NamedTemporaryFile("w+t")
        poc_content = textwrap.dedent(
            """\
                from pocsuite3.api import POCBase, register_poc, POC_CATEGORY


                class TestPoC(POCBase):
                    protocol = "CUSTOM"
                    protocol_default_port = 10086

                    def _verify(self):
                        result = {}
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['url'] = self.url
                        result['VerifyInfo']['scheme'] = self.scheme
                        result['VerifyInfo']['rhost'] = self.rhost
                        result['VerifyInfo']['rport'] = self.rport
                        result['VerifyInfo']['netloc'] = self.netloc
                        return self.parse_output(result)


                register_poc(TestPoC)
        """
        )
        f.write(poc_content)

        # https://127.0.0.1
        f.seek(0)
        config = {"url": "https://127.0.0.1", "poc": f.name}
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(
            res[0]["result"]["VerifyInfo"]["url"], "custom://127.0.0.1:10086"
        )
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "custom")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 10086)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:10086")

        # https://127.0.0.1:8080
        f.seek(0)
        config = {"url": "https://127.0.0.1:8080", "poc": f.name}
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(
            res[0]["result"]["VerifyInfo"]["url"], "custom://127.0.0.1:8080"
        )
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "custom")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 8080)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:8080")
        f.close()

    def test_custom_protocol(self):
        f = NamedTemporaryFile("w+t")
        poc_content = textwrap.dedent(
            """\
                from pocsuite3.api import POCBase, register_poc, POC_CATEGORY


                class TestPoC(POCBase):
                    protocol = "CUSTOM"

                    def _verify(self):
                        result = {}
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['url'] = self.url
                        result['VerifyInfo']['scheme'] = self.scheme
                        result['VerifyInfo']['rhost'] = self.rhost
                        result['VerifyInfo']['rport'] = self.rport
                        result['VerifyInfo']['netloc'] = self.netloc
                        return self.parse_output(result)


                register_poc(TestPoC)
        """
        )
        f.write(poc_content)

        # 127.0.0.1:443
        f.seek(0)
        config = {"url": "127.0.0.1:443", "poc": f.name}
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(res[0]["result"]["VerifyInfo"]["url"], "https://127.0.0.1:443")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "https")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 443)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:443")
        f.close()

    def test_custom_default_port(self):
        f = NamedTemporaryFile("w+t")
        poc_content = textwrap.dedent(
            """\
                from pocsuite3.api import POCBase, register_poc, POC_CATEGORY


                class TestPoC(POCBase):
                    protocol_default_port = 10443

                    def _verify(self):
                        result = {}
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['url'] = self.url
                        result['VerifyInfo']['scheme'] = self.scheme
                        result['VerifyInfo']['rhost'] = self.rhost
                        result['VerifyInfo']['rport'] = self.rport
                        result['VerifyInfo']['netloc'] = self.netloc
                        return self.parse_output(result)


                register_poc(TestPoC)
        """
        )
        f.write(poc_content)

        # 127.0.0.1
        f.seek(0)
        config = {"url": "127.0.0.1", "poc": f.name}
        init_pocsuite(config)
        start_pocsuite()
        res = get_results()
        self.assertEqual(
            res[0]["result"]["VerifyInfo"]["url"], "https://127.0.0.1:10443"
        )
        self.assertEqual(res[0]["result"]["VerifyInfo"]["scheme"], "https")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rhost"], "127.0.0.1")
        self.assertEqual(res[0]["result"]["VerifyInfo"]["rport"], 10443)
        self.assertEqual(res[0]["result"]["VerifyInfo"]["netloc"], "127.0.0.1:10443")
        f.close()
