import argparse
import os
import sys

from pocsuite3.lib.core.common import data_to_stdout
from pocsuite3.lib.core.settings import IS_WIN, CMD_PARSE_WHITELIST

DIY_OPTIONS = []


def cmd_line_parser(argv=None):
    """
    This function parses the command line parameters and arguments
    """

    if not argv:
        argv = sys.argv

    _ = os.path.basename(argv[0])
    usage = "pocsuite [options]"
    parser = argparse.ArgumentParser(prog='Pocsuite3', usage=usage)
    try:
        parser.add_argument("--version", dest="show_version", action="store_true",
                            help="Show program's version number and exit")

        parser.add_argument("--update", dest="update_all", action="store_true",
                            help="Update Pocsuite")

        parser.add_argument("-v", dest="verbose", type=int, default=1, choices=list(range(7)),
                            help="Verbosity level: 0-6 (default 1)")

        # Target options
        target = parser.add_argument_group('Target', "At least one of these "
                                                     "options has to be provided to define the target(s)")
        target.add_argument("-u", "--url", dest="url", nargs='+',
                            help="Target URL (e.g. \"http://www.site.com/vuln.php?id=1\")")

        target.add_argument("-f", "--file", dest="url_file", help="Scan multiple targets given in a textual file")
        target.add_argument("-r", dest="poc", nargs='+', help="Load PoC file from local or remote from seebug website")
        target.add_argument("-k", dest="poc_keyword", help="Filter PoC by keyword, e.g. ecshop")
        target.add_argument("-c", dest="configFile", help="Load options from a configuration INI file")

        # Mode options
        mode = parser.add_argument_group("Mode", "Pocsuite running mode options")

        mode.add_argument("--verify", dest="mode", default='verify', action="store_const", const='verify',
                          help="Run poc with verify mode")

        mode.add_argument("--attack", dest="mode", action="store_const", const='attack',
                          help="Run poc with attack mode")
        mode.add_argument("--shell", dest="mode", action="store_const", const='shell',
                          help="Run poc with shell mode")
        # Requests options
        request = parser.add_argument_group("Request", "Network request options")
        request.add_argument("--cookie", dest="cookie", help="HTTP Cookie header value")
        request.add_argument("--host", dest="host", help="HTTP Host header value")
        request.add_argument("--referer", dest="referer", help="HTTP Referer header value")
        request.add_argument("--user-agent", dest="agent", help="HTTP User-Agent header value (default random)")
        request.add_argument("--proxy", dest="proxy", help="Use a proxy to connect to the target URL")
        request.add_argument("--proxy-cred", dest="proxy_cred", help="Proxy authentication credentials (name:password)")
        request.add_argument("--timeout", dest="timeout", help="Seconds to wait before timeout connection (default 30)")
        request.add_argument("--retry", dest="retry", default=False, help="Time out retrials times")
        request.add_argument("--delay", dest="delay", help="Delay between two request of one thread")
        request.add_argument("--headers", dest="headers", help="Extra headers (e.g. \"key1: value1\\nkey2: value2\")")
        # Account options
        group = parser.add_argument_group("Account", "Telnet404, Shodan, CEye, Fofa account options")
        group.add_argument("--login-user", dest="login_user", help="Telnet404 login user")
        group.add_argument("--login-pass", dest="login_pass", help="Telnet404 login password")
        group.add_argument("--shodan-token", dest="shodan_token", help="Shodan token")
        group.add_argument("--fofa-user", dest="fofa_user", help="fofa user")
        group.add_argument("--fofa-token", dest="fofa_token", help="fofa token")
        group.add_argument("--quake-token", dest="quake_token", help="quake token")
        group.add_argument("--hunter-token", dest="hunter_token", help="hunter token")
        group.add_argument("--censys-uid", dest="censys_uid", help="Censys uid")
        group.add_argument("--censys-secret", dest="censys_secret", help="Censys secret")
        # Modules options
        modules = parser.add_argument_group(
            "Modules", "Modules(Seebug, Zoomeye, CEye, Fofa, Quake, Hunter, Listener) options")
        modules.add_argument("--dork", dest="dork", action="store", default=None,
                             help="Zoomeye dork used for search")
        modules.add_argument("--dork-zoomeye", dest="dork_zoomeye", action="store", default=None,
                             help="Zoomeye dork used for search")
        modules.add_argument("--dork-shodan", dest="dork_shodan", action="store", default=None,
                             help="Shodan dork used for search")
        modules.add_argument("--dork-censys", dest="dork_censys", action="store", default=None,
                             help="Censys dork used for search")
        modules.add_argument("--dork-fofa", dest="dork_fofa", action="store", default=None,
                             help="Fofa dork used for search")
        modules.add_argument("--dork-quake", dest="dork_quake", action="store", default=None,
                             help="Quake dork used for search")
        modules.add_argument("--dork-hunter", dest="dork_hunter", action="store", default=None,
                             help="Hunter dork used for search")
        modules.add_argument("--max-page", dest="max_page", type=int, default=1,
                             help="Max page used in search API")
        modules.add_argument("--search-type", dest="search_type", action="store", default='host',
                             help="search type used in ZoomEye API, web or host")
        modules.add_argument("--vul-keyword", dest="vul_keyword", action="store", default=None,
                             help="Seebug keyword used for search")
        modules.add_argument("--ssv-id", dest="ssvid", action="store", default=None,
                             help="Seebug SSVID number for target PoC")
        modules.add_argument("--lhost", dest="connect_back_host", action="store", default=None,
                             help="Connect back host for target PoC in shell mode")
        modules.add_argument("--lport", dest="connect_back_port", action="store", default=None,
                             help="Connect back port for target PoC in shell mode")
        modules.add_argument("--tls", dest="enable_tls_listener", action="store_true", default=False,
                             help="Enable TLS listener in shell mode")
        modules.add_argument("--comparison", dest="comparison", help="Compare popular web search engines",
                             action="store_true",
                             default=False)
        modules.add_argument("--dork-b64", dest="dork_b64", help="Whether dork is in base64 format",
                             action="store_true",
                             default=False)

        # Optimization options
        optimization = parser.add_argument_group("Optimization", "Optimization options")
        optimization.add_argument("--plugins", dest="plugins", action="store", default=None,
                                  help="Load plugins to execute")
        optimization.add_argument("--pocs-path", dest="pocs_path", action="store", default=None,
                                  help="User defined poc scripts path")
        optimization.add_argument("--threads", dest="threads", type=int, default=1,
                                  help="Max number of concurrent network requests (default 1)")
        optimization.add_argument("--batch", dest="batch",
                                  help="Automatically choose defaut choice without asking")
        optimization.add_argument("--requires", dest="check_requires", action="store_true", default=False,
                                  help="Check install_requires")
        optimization.add_argument("--quiet", dest="quiet", action="store_true", default=False,
                                  help="Activate quiet mode, working without logger")
        optimization.add_argument("--ppt", dest="ppt", action="store_true", default=False,
                                  help="Hiden sensitive information when published to the network")
        optimization.add_argument("--pcap", dest="pcap", action="store_true", default=False,
                                  help="use scapy capture flow")
        optimization.add_argument("--rule", dest="rule", action="store_true", default=False,
                                  help="export suricata rules, default export reqeust and response")
        optimization.add_argument("--rule-req", dest="rule_req", action="store_true", default=False,
                                  help="only export request rule")
        optimization.add_argument("--rule-filename", dest="rule_filename", action="store", default=False,
                                  help="Specify the name of the export rule file")
        # Diy options
        diy = parser.add_argument_group("Poc options", "definition options for PoC")
        diy.add_argument("--options", dest="show_options", action="store_true", default=False,
                         help="Show all definition options")

        for line in argv:
            if line.startswith("--"):
                if line[2:] not in CMD_PARSE_WHITELIST:
                    diy.add_argument(line)

        args = parser.parse_args()
        return args

    except SystemExit:
        # Protection against Windows dummy double clicking
        if IS_WIN:
            data_to_stdout("\nPress Enter to continue...")
            input()
        raise
