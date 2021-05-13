import copy
import glob
import logging
import os
import re
import socket
from queue import Queue
from urllib.parse import urlsplit

from pocsuite3.lib.core.clear import remove_extra_log_message
from pocsuite3.lib.core.common import boldify_message, check_file, get_file_items, parse_target, \
    get_public_type_members, data_to_stdout
from pocsuite3.lib.core.common import check_path, extract_cookies
from pocsuite3.lib.core.common import get_local_ip, desensitization
from pocsuite3.lib.core.common import single_time_warn_message
from pocsuite3.lib.core.convert import stdout_encode
from pocsuite3.lib.core.data import conf, cmd_line_options
from pocsuite3.lib.core.data import kb
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.data import merged_options
from pocsuite3.lib.core.data import paths
from pocsuite3.lib.core.datatype import AttribDict
from pocsuite3.lib.core.enums import HTTP_HEADER, CUSTOM_LOGGING, PROXY_TYPE
from pocsuite3.lib.core.exception import PocsuiteSyntaxException, PocsuiteSystemException, PocsuiteHeaderTypeException
from pocsuite3.lib.core.log import FORMATTER
from pocsuite3.lib.core.register import load_file_to_module
from pocsuite3.lib.core.settings import DEFAULT_USER_AGENT, DEFAULT_LISTENER_PORT, CMD_PARSE_WHITELIST
from pocsuite3.lib.core.statistics_comparison import StatisticsComparison
from pocsuite3.lib.core.update import update
from pocsuite3.lib.parse.cmd import DIY_OPTIONS
from pocsuite3.lib.parse.configfile import config_file_parser
from pocsuite3.lib.parse.rules import regex_rule
from pocsuite3.lib.request.patch import patch_all
from pocsuite3.modules.listener import start_listener
from pocsuite3.thirdparty.oset.orderedset import OrderedSet
from pocsuite3.thirdparty.pysocks import socks


def _resolve_cross_references():
    import pocsuite3
    pocsuite3.lib.core.revision.stdout_encode = stdout_encode
    pocsuite3.lib.core.convert.single_time_warn_message = single_time_warn_message


def set_verbosity():
    """
    This function set the verbosity of pocsuite output messages.
    """

    if conf.verbose is None:
        conf.verbose = 1

    conf.verbose = int(conf.verbose)

    if conf.verbose == 0:
        logger.setLevel(logging.ERROR)
    elif conf.verbose == 1:
        logger.setLevel(logging.INFO)
    elif conf.verbose == 2:
        logger.setLevel(logging.DEBUG)
    elif conf.verbose == 3:
        logger.setLevel(logging.DEBUG)
        logger.setLevel(CUSTOM_LOGGING.SYSINFO)
    elif conf.verbose == 4:
        logger.setLevel(logging.DEBUG)
        logger.setLevel(CUSTOM_LOGGING.WARNING)
    elif conf.verbose >= 5:
        logger.setLevel(logging.DEBUG)
        logger.setLevel(CUSTOM_LOGGING.ERROR)


def _set_http_user_agent():
    '''
    set user-agent
    :return:
    '''

    conf.http_headers[HTTP_HEADER.USER_AGENT] = DEFAULT_USER_AGENT

    if conf.random_agent:
        uapath = os.path.join(paths.POCSUITE_DATA_PATH, 'user-agents.txt')
        if os.path.exists(uapath):
            with open(uapath) as f:
                agents = f.read().split("\n")
                if len(agents) == 1 and "" in agents:
                    logger.error("user-agents file is empty will use default")
                else:
                    conf.agents = agents
        else:
            logger.error("user-agents file not fond will use default")

    if conf.agent:
        conf.http_headers[HTTP_HEADER.USER_AGENT] = conf.agent


def _set_http_referer():
    if conf.referer:
        conf.http_headers[HTTP_HEADER.REFERER] = conf.referer


def _set_http_cookie():
    if conf.cookie:
        if isinstance(conf.cookie, dict):
            conf.http_headers[HTTP_HEADER.COOKIE] = '; '.join(map(lambda x: '='.join(x), conf.cookie.items()))
        else:
            conf.http_headers[HTTP_HEADER.COOKIE] = conf.cookie


def _set_http_host():
    if conf.host:
        conf.http_headers[HTTP_HEADER.HOST] = conf.host


def _set_http_extra_headers():
    if conf.headers:
        conf.headers = conf.headers.split("\n") if "\n" in conf.headers else conf.headers.split("\\n")
        for header_value in conf.headers:
            if not header_value.strip():
                continue

            if header_value.count(':') >= 1:
                header, value = (_.lstrip() for _ in header_value.split(":", 1))
                if header and value:
                    if header not in conf.http_headers:
                        conf.http_headers[header] = value


def _set_network_timeout():
    if conf.timeout:
        conf.timeout = float(conf.timeout)
        if conf.timeout < 3.0:
            warn_msg = "the minimum HTTP timeout is 3 seconds, pocsuite "
            warn_msg += "will going to reset it"
            logger.warn(warn_msg)

            conf.timeout = 3.0
    else:
        conf.timeout = 30.0

    socket.setdefaulttimeout(conf.timeout)


def _set_network_proxy():
    if conf.proxy:
        debug_msg = "setting the HTTP/SOCKS proxy for all network requests"
        logger.debug(debug_msg)

        try:
            _ = urlsplit(conf.proxy)
        except Exception as ex:
            err_msg = "invalid proxy address '{0}' ('{1}')".format(conf.proxy, str(ex))
            raise PocsuiteSyntaxException(err_msg)

        hostname_port = _.netloc.split(":")
        scheme = _.scheme.upper()
        hostname = hostname_port[0]
        port = None
        username = None
        password = None

        if len(hostname_port) == 2:
            try:
                port = int(hostname_port[1])
            except Exception:
                pass

        if not all((scheme, hasattr(PROXY_TYPE, scheme), hostname, port)):
            err_msg = "proxy value must be in format '({0})://address:port'".format("|".join(
                _[0].lower() for _ in get_public_type_members(PROXY_TYPE)))
            raise PocsuiteSyntaxException(err_msg)

        if conf.proxy_cred:
            _ = re.search(r"\A(.*?):(.*?)\Z", conf.proxy_cred)
            if not _:
                err_msg = "proxy authentication credentials "
                err_msg += "value must be in format username:password"
                raise PocsuiteSyntaxException(err_msg)
            else:
                username = _.group(1)
                password = _.group(2)

        if scheme in (PROXY_TYPE.SOCKS4, PROXY_TYPE.SOCKS5, PROXY_TYPE.SOCKS5H):
            socks.set_default_proxy(
                socks.PROXY_TYPE_SOCKS4 if scheme == PROXY_TYPE.SOCKS4 else socks.PROXY_TYPE_SOCKS5,
                hostname,
                port,
                username=username,
                password=password,
                rdns=True if scheme == PROXY_TYPE.SOCKS5H else False,
            )
            conf.origin_socks = copy.deepcopy(socket.socket)  # Convenient behind recovery
            socket.socket = socks.socksocket

        if conf.proxy_cred:
            proxy_string = "{0}@".format(conf.proxy_cred)
        else:
            proxy_string = ""

        proxy_string = "{scheme}://{proxy_string}{hostname}:{port}".format(scheme=scheme.lower(),
                                                                           proxy_string=proxy_string,
                                                                           hostname=hostname, port=port)
        conf.proxies = {
            "http": proxy_string,
            "https": proxy_string
        }


def _set_multiple_targets():
    # set multi targets to kb
    if conf.url:
        targets = set()
        for url in conf.url:
            parsed = parse_target(url)
            if parsed:
                targets.add(parsed)
        if not targets:
            err_msg = "incorrect target url or ip format!"
            logger.error(err_msg)
        for target in targets:
            kb.targets.add(target)

    if conf.url_file:
        for line in get_file_items(conf.url_file, lowercase=False, unique=True):
            kb.targets.add(line)

    if conf.dork:
        # enable plugin 'target_from_zoomeye' by default
        if 'target_from_shodan' not in conf.plugins and 'target_from_fofa' not in conf.plugins:
            conf.plugins.append('target_from_zoomeye')

    if conf.dork_zoomeye:
        conf.plugins.append('target_from_zoomeye')

    if conf.dork_shodan:
        conf.plugins.append('target_from_shodan')

    if conf.dork_censys:
        conf.plugins.append('target_from_censys')

    if conf.dork_fofa:
        conf.plugins.append('target_from_fofa')


def _set_task_queue():
    if kb.registered_pocs and kb.targets:
        for poc_module in kb.registered_pocs:
            for target in kb.targets:
                kb.task_queue.put((target, poc_module))


def _check_account_login():
    # TODO
    # check telnet404 account login
    pass


def _check_ceye():
    # TODO
    # check ceye and ceye api token is available
    pass


def _check_seebug():
    # TODO
    # check seebug and seebug api token is available
    pass


def _check_zoomeye():
    # TODO
    # check zoomeye and zoomeye api token is available
    pass


def _set_threads():
    if not isinstance(conf.threads, int) or conf.threads <= 0:
        conf.threads = 1


def _set_connect_back():
    ips = get_local_ip(all=True)
    if ips:
        kb.data.local_ips = ips
    if conf.mode == "shell" and conf.connect_back_host is None:
        data_to_stdout("[i] pocsusite is running in shell mode, you need to set connect back host:\n")
        message = '----- Local IP Address -----\n'
        for i, ip in enumerate(kb.data.local_ips):
            message += "{0}    {1}\n".format(i, desensitization(ip) if conf.ppt else ip)
        data_to_stdout(message)
        while True:
            choose = None
            choose = input('Choose>: ').strip()
            if not choose:
                continue
            try:
                if choose.isdigit():
                    choose = int(choose)
                    conf.connect_back_host = kb.data.local_ips[choose]
                    data_to_stdout("you choose {0}\n".format(
                        desensitization(conf.connect_back_host) if conf.ppt else conf.connect_back_host))
                    break
            except Exception:
                data_to_stdout("wrong number, choose again\n")


def _set_listener():
    if conf.mode == "shell" and not conf.api:
        start_listener()


def _set_user_pocs_path():
    if conf.pocs_path:
        if check_path(conf.pocs_path):
            paths.USER_POCS_PATH = conf.pocs_path
            for root, dirs, files in os.walk(paths.USER_POCS_PATH):
                files = list(filter(lambda x: not x.startswith("__") and x.endswith(".py"), files))
                conf.poc = [paths.USER_POCS_PATH + "\\" + f for f in files]
        else:
            warm_msg = "User defined pocs path {0} is invalid".format(conf.pocs_path)
            logger.warn(warm_msg)


def _set_pocs_modules():
    # TODO
    # load poc scripts .pyc file support
    if conf.ssvid:
        conf.plugins.append('poc_from_seebug')
    if conf.poc:
        # step1. load system packed poc from pocsuite3/pocs folder
        exists_poc_with_ext = list(
            filter(lambda x: x not in ['__init__.py', '__init__.pyc'], os.listdir(paths.POCSUITE_POCS_PATH)))
        exists_pocs = dict([os.path.splitext(x) for x in exists_poc_with_ext])
        for poc in conf.poc:
            load_poc_sucess = False
            if any([poc in exists_poc_with_ext, poc in exists_pocs]):
                poc_name, poc_ext = os.path.splitext(poc)
                if poc_ext in ['.py', '.pyc']:
                    file_path = os.path.join(paths.POCSUITE_POCS_PATH, poc)
                else:
                    file_path = os.path.join(paths.POCSUITE_POCS_PATH, poc + exists_pocs.get(poc))
                if file_path:
                    info_msg = "loading PoC script '{0}'".format(file_path)
                    logger.info(info_msg)
                    load_poc_sucess = load_file_to_module(file_path)

            # step2. load poc from given file path
            try:
                if not load_poc_sucess:
                    if not poc.startswith('ssvid-') and check_file(poc):
                        info_msg = "loading PoC script '{0}'".format(poc)
                        logger.info(info_msg)
                        load_poc_sucess = load_file_to_module(poc)
            except PocsuiteSystemException:
                logger.error('PoC file "{0}" not found'.format(repr(poc)))
                continue

            # step3. load poc from seebug website using plugin 'poc_from_seebug'
            if not load_poc_sucess:
                if poc.startswith('ssvid-'):
                    info_msg = "loading Poc script 'https://www.seebug.org/vuldb/{0}'".format(poc)
                    logger.info(info_msg)
                    if "poc_from_seebug" not in conf.plugins:
                        conf.plugins.append('poc_from_seebug')

    load_keyword_poc_sucess = False
    if conf.vul_keyword:
        # step4. load poc with vul_keyword search seebug website
        info_msg = "loading PoC script from seebug website using search keyword '{0}' ".format(conf.vul_keyword)
        logger.info(info_msg)

        conf.plugins.append('poc_from_seebug')


def _set_plugins():
    # TODO
    # load plugin scripts .pyc file support
    if conf.plugins:
        founds = []
        cache_plugins = copy.deepcopy(conf.plugins)

        for found in glob.glob(os.path.join(paths.POCSUITE_PLUGINS_PATH, "*.py*")):
            dirname, filename = os.path.split(found)
            plugin_name = os.path.splitext(filename)[0]
            if found.endswith(('__init__.py', '__init__.pyc')):
                continue
            if plugin_name not in conf.plugins:
                continue
            cache_plugins.remove(plugin_name)
            founds.append(found)
        if len(cache_plugins) > 0:
            for file in cache_plugins:
                if os.path.exists(file):
                    founds.append(file)

        for file in founds:
            debug_msg = "loading plugin script '{0}'".format(file)
            logger.debug(debug_msg)
            load_file_to_module(file)


def _cleanup_options():
    """
    Cleanup configuration attributes.
    """
    if conf.agent:
        conf.agent = re.sub(r"[\r\n]", "", conf.agent)

    if conf.cookie:
        if isinstance(conf.cookie, str):
            conf.cookie = re.sub(r"[\r\n]", "", conf.cookie)
            conf.cookie = extract_cookies(conf.cookie)
        elif not isinstance(conf.cookie, dict):
            raise PocsuiteHeaderTypeException('Does not support type for cookie')
    if conf.delay:
        conf.delay = float(conf.delay)

    if conf.retry:
        conf.retry = min(conf.retry, 10)

    if conf.url:
        if isinstance(conf.url, str):
            conf.url = [conf.url]
        conf.url = [x.strip() for x in conf.url]

    if conf.poc:
        if isinstance(conf.poc, str):
            conf.poc = [conf.poc]
        conf.poc = [poc.lower() if poc.lower().startswith('ssvid-') else poc for poc in conf.poc]

    if conf.url_file:
        conf.url_file = os.path.expanduser(conf.url_file)
        check_file(conf.url_file)

    if conf.plugins:
        conf.plugins = conf.plugins.split(',')
        conf.plugins = [i.strip() for i in conf.plugins]
        conf.plugins = list(set(conf.plugins))

    if conf.connect_back_port:
        conf.connect_back_port = int(conf.connect_back_port)

    conf.origin_socks = None


def _basic_option_validation():
    _check_account_login()
    _check_seebug()
    _check_zoomeye()
    _check_ceye()


def _adjust_logging_formatter():
    """
    Solves problem of line deletition caused by overlapping logging messages
    and retrieved data info in inference mode
    """
    if hasattr(FORMATTER, '_format'):
        return

    def new_format(record):
        message = FORMATTER._format(record)
        message = boldify_message(message)
        return message

    FORMATTER._format = FORMATTER.format
    FORMATTER.format = new_format


def _create_directory():
    if not os.path.isdir(paths.POCSUITE_OUTPUT_PATH):
        try:
            os.makedirs(paths.POCSUITE_OUTPUT_PATH)
        except FileExistsError:
            pass

    if not os.path.isdir(paths.POCSUITE_TMP_PATH):
        try:
            os.makedirs(paths.POCSUITE_TMP_PATH)
        except FileExistsError:
            pass

    if not os.path.isfile(paths.POCSUITE_RC_PATH):
        open(paths.POCSUITE_RC_PATH, 'a').close()


def _set_conf_attributes():
    """
    This function set some needed attributes into the configuration
    singleton.
    """

    debug_msg = "initializing the configuration"
    logger.debug(debug_msg)

    conf.url = None
    conf.url_file = None
    conf.mode = 'verify'
    conf.poc = None
    conf.cookie = None
    conf.host = None
    conf.referer = None
    conf.agent = None
    conf.headers = None
    conf.random_agent = None
    conf.proxy = None
    conf.proxy_cred = None
    conf.proxies = {}
    conf.timeout = 30
    conf.retry = 0
    conf.delay = 0
    conf.http_headers = {}
    conf.agents = [DEFAULT_USER_AGENT]  # 数据源从插件加载的时候无默认值需要处理
    conf.login_user = None
    conf.login_pass = None
    conf.shodan_token = None
    conf.fofa_user = None
    conf.fofa_token = None
    conf.censys_uid = None
    conf.censys_secret = None
    conf.dork = None
    conf.dork_zoomeye = None
    conf.dork_shodan = None
    conf.dork_fofa = None
    conf.dork_censys = None
    conf.dork_b64 = False
    conf.max_page = 1
    conf.search_type = 'host'
    conf.comparison = False
    conf.vul_keyword = None
    conf.ssvid = None
    conf.plugins = []
    conf.threads = 1
    conf.batch = False
    conf.check_requires = False
    conf.quiet = False
    conf.update_all = False
    conf.verbose = 1

    conf.ipv6 = False
    conf.multiple_targets = False
    conf.pocs_path = None
    conf.output_path = None
    conf.plugin_name = None
    conf.plugin_code = None
    conf.connect_back_host = None
    conf.connect_back_port = DEFAULT_LISTENER_PORT
    conf.console_mode = False
    conf.show_version = False
    conf.api = False  # api for zipoc
    conf.ppt = False
    conf.pcap = False
    conf.rule = False
    conf.rule_req = False
    conf.rule_filename = None


def _set_kb_attributes(flush_all=True):
    """
    This function set some needed attributes into the knowledge base
    singleton.
    """

    debug_msg = "initializing the knowledge base"
    logger.debug(debug_msg)

    kb.abs_file_paths = set()
    kb.os = None
    kb.os_version = None
    kb.arch = None
    kb.dbms = None
    kb.auth_header = None
    kb.counters = {}
    kb.multi_thread_mode = False
    kb.thread_continue = True
    kb.thread_exception = False
    kb.word_lists = None
    kb.single_log_flags = set()

    kb.cache = AttribDict()
    kb.cache.addrinfo = {}
    kb.cache.content = {}
    kb.cache.regex = {}

    kb.data = AttribDict()
    kb.data.local_ips = []
    kb.data.connect_back_ip = None
    kb.data.connect_back_port = DEFAULT_LISTENER_PORT
    kb.data.clients = []
    kb.targets = OrderedSet()
    kb.plugins = AttribDict()
    kb.plugins.targets = AttribDict()
    kb.plugins.pocs = AttribDict()
    kb.plugins.results = AttribDict()
    kb.results = []
    kb.current_poc = None
    kb.registered_pocs = AttribDict()
    kb.task_queue = Queue()
    kb.cmd_line = DIY_OPTIONS or []

    kb.comparison = None


def _merge_options(input_options, override_options):
    """
    Merge command line options with configuration file and default options.
    """
    if hasattr(input_options, "items"):
        input_options_items = input_options.items()
    else:
        input_options_items = input_options.__dict__.items()

    for key, value in input_options_items:
        if key not in conf or value not in (None, False) or override_options:
            conf[key] = value

    if input_options.get("configFile"):
        config_file_parser(input_options["configFile"])

    merged_options.update(conf)


def _set_poc_options(input_options):
    for line in input_options.keys():
        if line not in CMD_PARSE_WHITELIST:
            DIY_OPTIONS.append(line)


def init_options(input_options=AttribDict(), override_options=False):
    cmd_line_options.update(input_options)
    _set_conf_attributes()
    _set_poc_options(input_options)
    _set_kb_attributes()
    _merge_options(input_options, override_options)
    # export rules, dont run the poc in the default status
    if conf.rule or conf.rule_req:
        logger.info("The rule export function is in use. The POC is not executed at this point")
        if conf.pocs_path:
            if check_path(conf.pocs_path):
                paths.USER_POCS_PATH = conf.pocs_path
                for root, dirs, files in os.walk(paths.USER_POCS_PATH):
                    files = list(filter(lambda x: not x.startswith("__") and x.endswith(".py"), files))
                regex_rule(list(paths.USER_POCS_PATH + i for i in files))

        if conf.poc:
            regex_rule(conf.poc)
        exit()
    # if check version
    if conf.show_version:
        exit()


def _init_targets_plugins():
    for _, plugin in kb.plugins.targets.items():
        plugin.init()


def _init_pocs_plugins():
    for _, plugin in kb.plugins.pocs.items():
        plugin.init()


def _init_results_plugins():
    for _, plugin in kb.plugins.results.items():
        plugin.init()


def _init_kb_comparison():
    if conf.comparison:
        kb.comparison = StatisticsComparison()


def init():
    """
    Set attributes into both configuration and knowledge base singletons
    based upon command line and configuration file options.
    """
    set_verbosity()
    patch_all()
    _adjust_logging_formatter()
    _cleanup_options()
    _basic_option_validation()
    _create_directory()
    _init_kb_comparison()
    update()
    _set_multiple_targets()
    _set_user_pocs_path()
    _set_pocs_modules()  # poc module模块要在插件模块前，poc选项中某些参数调用了插件
    _set_plugins()
    _init_targets_plugins()
    _init_pocs_plugins()
    _set_task_queue()
    _init_results_plugins()

    if any((conf.url, conf.url_file, conf.plugins)):
        _set_http_cookie()
        _set_http_host()
        _set_http_referer()
        _set_http_user_agent()
        _set_http_extra_headers()

    _set_connect_back()
    _set_network_proxy()
    _set_network_timeout()
    _set_threads()
    _set_listener()
    remove_extra_log_message()
