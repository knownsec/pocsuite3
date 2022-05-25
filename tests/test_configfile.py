import os
import unittest
from configparser import ConfigParser
from optparse import OptionParser, OptionGroup

from pocsuite3.api import paths


class TestCase(unittest.TestCase):
    def setUp(self):
        self.root = paths.POCSUITE_ROOT_PATH
        self.path = os.path.join(self.root, "../pocsuite_test.ini")
        self.path2 = os.path.join(self.root, "../pocsuite.ini")

    def tearDown(self):
        if os.path.isfile(self.path):
            os.remove(self.path)

    def test_build_ini(self):
        config = ConfigParser(allow_no_value=True)

        usage = "pocsuite [options]"
        parser = OptionParser(usage=usage)
        try:
            parser.add_option("--version", dest="show_version", action="store_true",
                              help="Show program's version number and exit")

            parser.add_option("--update", dest="update_all", action="store_true",
                              help="Update Pocsuite")

            parser.add_option("-v", dest="verbose", type="int", default=1,
                              help="Verbosity level: 0-6 (default 1)")

            # Target options
            target = OptionGroup(parser, "Target", "At least one of these "
                                                   "options has to be provided to define the target(s)")
            target.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.site.com/vuln.php?id=1\")")

            target.add_option("-f", "--file", dest="url_file", help="Scan multiple targets given in a textual file")
            target.add_option("-r", dest="poc", help="Load PoC file from local or remote from seebug website")
            target.add_option("-k", dest="poc_keyword", help="Filter PoC by keyword, e.g. ecshop")
            target.add_option("-c", dest="configFile", help="Load options from a configuration INI file")

            # Mode options
            mode = OptionGroup(parser, "Mode", "Pocsuite running mode options")

            mode.add_option("--verify", dest="mode", default='verify', action="store_const", const='verify',
                            help="Run poc with verify mode")

            mode.add_option("--attack", dest="mode", action="store_const", const='attack',
                            help="Run poc with attack mode")
            mode.add_option("--shell", dest="mode", action="store_const", const='shell',
                            help="Run poc with shell mode")
            # Requests options
            request = OptionGroup(parser, "Request", "Network request options")
            request.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
            request.add_option("--host", dest="host", help="HTTP Host header value")
            request.add_option("--referer", dest="referer", help="HTTP Referer header value")
            request.add_option("--user-agent", dest="agent", help="HTTP User-Agent header value (default random)")
            request.add_option("--proxy", dest="proxy", help="Use a proxy to connect to the target URL")
            request.add_option("--proxy-cred", dest="proxy_cred",
                               help="Proxy authentication credentials (name:password)")
            request.add_option("--timeout", dest="timeout",
                               help="Seconds to wait before timeout connection (default 30)")
            request.add_option("--retry", dest="retry", default=False, help="Time out retrials times")
            request.add_option("--delay", dest="delay", help="Delay between two request of one thread")
            request.add_option("--headers", dest="headers", help="Extra headers (e.g. \"key1: value1\\nkey2: value2\")")
            # Account options
            account = OptionGroup(parser, "Account", "Telnet404 account options")
            account.add_option("--login-user", dest="login_user", help="Telnet404 login user")
            account.add_option("--login-pass", dest="login_pass", help="Telnet404 login password")
            account.add_option("--shodan-token", dest="shodan_token", help="Shodan token")
            account.add_option("--fofa-user", dest="fofa_user", help="fofa user")
            account.add_option("--fofa-token", dest="fofa_token", help="fofa token")
            account.add_option("--quake-token", dest="quake_token", help="quake token")
            account.add_option("--hunter-token", dest="hunter_token", help="hunter token")
            account.add_option("--censys-uid", dest="censys_uid", help="Censys uid")
            account.add_option("--censys-secret", dest="censys_secret", help="Censys secret")
            # Modules options
            modules = OptionGroup(parser, "Modules", "Modules(Seebug Zoomeye CEye Listener) options")
            modules.add_option("--dork", dest="dork", action="store", default=None,
                               help="Zoomeye dork used for search")
            modules.add_option("--dork-zoomeye", dest="dork_zoomeye", action="store", default=None,
                               help="Zoomeye dork used for search")
            modules.add_option("--dork-shodan", dest="dork_shodan", action="store", default=None,
                               help="Shodan dork used for search")
            modules.add_option("--dork-censys", dest="dork_censys", action="store", default=None,
                               help="Censys dork used for search")
            modules.add_option("--dork-fofa", dest="dork_fofa", action="store", default=None,
                               help="Fofa dork used for search")
            modules.add_option("--dork-quake", dest="dork_quake", action="store", default=None,
                               help="Quake dork used for search")
            modules.add_option("--dork-hunter", dest="dork_hunter", action="store", default=None,
                               help="Hunter dork used for search")
            modules.add_option("--max-page", dest="max_page", type=int, default=1,
                               help="Max page used in search API")
            modules.add_option("--search-type", dest="search_type", action="store", default='host',
                               help="search type used in ZoomEye API, web or host")
            modules.add_option("--vul-keyword", dest="vul_keyword", action="store", default=None,
                               help="Seebug keyword used for search")
            modules.add_option("--ssv-id", dest="ssvid", action="store", default=None,
                               help="Seebug SSVID number for target PoC")
            modules.add_option("--lhost", dest="connect_back_host", action="store", default=None,
                               help="Connect back host for target PoC in shell mode")
            modules.add_option("--lport", dest="connect_back_port", action="store", default=None,
                               help="Connect back port for target PoC in shell mode")
            modules.add_option("--tls", dest="enable_tls_listener", action="store_true", default=False,
                               help="Enable TLS listener in shell mode")
            modules.add_option("--comparison", dest="comparison", help="Compare popular web search engines",
                               action="store_true",
                               default=False)
            modules.add_option("--dork-b64", dest="dork_b64", help="Whether dork is in base64 format",
                               action="store_true",
                               default=False)

            # Optimization options
            optimization = OptionGroup(parser, "Optimization", "Optimization options")
            optimization.add_option("--plugins", dest="plugins", action="store", default=None,
                                    help="Load plugins to execute")
            optimization.add_option("--pocs-path", dest="pocs_path", action="store", default=None,
                                    help="User defined poc scripts path")
            optimization.add_option("--threads", dest="threads", type=int, default=1,
                                    help="Max number of concurrent network requests (default 1)")
            optimization.add_option("--batch", dest="batch",
                                    help="Automatically choose defaut choice without asking")
            optimization.add_option("--requires", dest="check_requires", action="store_true", default=False,
                                    help="Check install_requires")
            optimization.add_option("--quiet", dest="quiet", action="store_true", default=False,
                                    help="Activate quiet mode, working without logger")
            optimization.add_option("--ppt", dest="ppt", action="store_true", default=False,
                                    help="Hiden sensitive information when published to the network")
            optimization.add_option("--pcap", dest="pcap", action="store_true", default=False,
                                    help="use scapy capture flow")
            optimization.add_option("--rule", dest="rule", action="store_true", default=False,
                                    help="export suricata rules, default export reqeust and response")
            optimization.add_option("--rule-req", dest="rule_req", action="store_true", default=False,
                                    help="only export request rule")
            optimization.add_option("--rule-filename", dest="rule_filename", action="store", default=False,
                                    help="Specify the name of the export rule file")

            # Diy options
            diy_options = OptionGroup(parser, "Poc options", "definition options for PoC")
            diy_options.add_option("--options", dest="show_options", action="store_true", default=False,
                                   help="Show all definition options")

            parser.add_option_group(target)
            parser.add_option_group(mode)
            parser.add_option_group(request)
            parser.add_option_group(account)
            parser.add_option_group(modules)
            parser.add_option_group(optimization)
            parser.add_option_group(diy_options)

        except Exception as e:
            print(Exception, e)

        d = parser.__dict__
        optiondict = {}
        for group in d["option_groups"]:
            # desc = group.description
            title = group.title
            # print(desc, title)
            # config.add_section("; " + desc)
            config.add_section(title)
            optiondict[title] = {}
            for item in group.option_list:
                _type = item.type
                dest = item.dest
                help = item.help
                default = item.default
                if isinstance(default, tuple) and default == ('NO', 'DEFAULT'):
                    default = ''
                print(_type, dest, default)
                config.set(title, '; ' + help)
                config.set(title, dest, str(default))
                optiondict[title][dest] = _type
        with open(self.path, 'w') as fp:
            config.write(fp)

        config.read(self.path)
        print(optiondict)
        self.assertTrue(len(config.items("Target")) > 1)

    def test_read_ini(self):
        config = ConfigParser()
        config.read(self.path2)
        sections = config.sections()
        for section in sections:
            options = config.items(section)
            if options:
                for key, value in options:
                    print(key, type(value))
