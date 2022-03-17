#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2018/12/25 上午10:58
# @Author  : chenghs
# @File    : interpreter.py
import os
import re
import chardet
import prettytable
from termcolor import colored

from pocsuite3.lib.controller.controller import start
from pocsuite3.lib.core.common import banner, index_modules, data_to_stdout, module_required, \
    get_poc_name, stop_after, get_local_ip, is_ipv6_address_format, rtrim, ltrim, exec_cmd
from pocsuite3.lib.core.data import logger, paths, kb, conf
from pocsuite3.lib.core.enums import POC_CATEGORY, AUTOCOMPLETE_TYPE
from pocsuite3.lib.core.exception import PocsuiteBaseException, PocsuiteShellQuitException
from pocsuite3.lib.core.option import _set_listener, _set_http_referer, _set_http_user_agent, _set_network_proxy, \
    _set_network_timeout
from pocsuite3.lib.core.register import load_file_to_module
from pocsuite3.lib.core.settings import IS_WIN
from pocsuite3.lib.core.shell import auto_completion, readline


class BaseInterpreter(object):
    global_help = ""

    def __init__(self):
        self.setup()
        self.banner = ""
        self.complete = None
        # Prepare to execute system commands
        self.input_command = ''
        self.input_args = ''

    def setup(self):
        """ Initialization of third-party libraries

        Setting interpreter history.
        Setting appropriate completer function.

        :return:
        """
        auto_completion(completion=AUTOCOMPLETE_TYPE.CONSOLE, console=self.complete)

    def parse_line(self, line):
        """ Split line into command and argument.

        :param line: line to parse
        :return: (command, argument)
        """
        command, _, arg = line.strip().partition(" ")
        return command, arg.strip()

    @property
    def prompt(self):
        """ Returns prompt string """
        return ">>>"

    def get_command_handler(self, command):
        """ Parsing command and returning appropriate handler.

        :param command: command
        :return: command_handler
        """
        try:
            command_handler = getattr(self, "command_{}".format(command))
        except AttributeError:
            cmd = self.input_command + ' ' + self.input_args
            for line in exec_cmd(cmd=cmd):
                result_encoding = chardet.detect(line)['encoding']
                if result_encoding:
                    print(line.decode(result_encoding))
            raise PocsuiteBaseException("Pocsuite3 Unknown this command, and run it on system: '{}'".format(command))

        return command_handler

    def start(self):
        """ Routersploit main entry point. Starting interpreter loop. """

        while True:
            try:
                self.input_command, self.input_args = self.parse_line(input(self.prompt))
                command = self.input_command.lower()
                if not command:
                    continue
                command_handler = self.get_command_handler(command)
                command_handler(self.input_args)
            except PocsuiteBaseException as warn:
                logger.warn(warn)
            except EOFError:
                logger.info("Pocsuite3 stopped")
                break
            except KeyboardInterrupt:
                logger.warn('Interrupt: use the \'exit\' command to quit')
                continue

    def complete(self, text, state):
        """Return the next possible completion for 'text'.

        If a command has not been entered, then complete against command list.
        Otherwise try to call complete_<command> to get list of completions.
        """
        if state == 0:
            original_line = readline.get_line_buffer()
            line = original_line.lstrip()
            stripped = len(original_line) - len(line)
            start_index = readline.get_begidx() - stripped
            end_index = readline.get_endidx() - stripped

            if start_index > 0:
                cmd, args = self.parse_line(line)
                if cmd == "":
                    complete_function = self.default_completer
                else:
                    try:
                        complete_function = getattr(self, "complete_" + cmd)
                    except AttributeError:
                        complete_function = self.default_completer
            else:
                complete_function = self.raw_command_completer

            self.completion_matches = complete_function(text, line, start_index, end_index)

        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    def commands(self, *ignored):
        """ Returns full list of interpreter commands.

        :param ignored:
        :return: full list of interpreter commands
        """
        return [command.rsplit("_").pop() for command in dir(self) if command.startswith("command_")]

    def raw_command_completer(self, text, line, start_index, end_index):
        """ Complete command w/o any argument """
        return [command for command in self.suggested_commands() if command.startswith(text)]

    def default_completer(self, *ignored):
        return []

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.

        Overwrite this method to suggest suitable commands.

        :return: list of suitable commands
        """
        return self.commands()


class PocsuiteInterpreter(BaseInterpreter):
    global_help = """Global commands:
    help                        Print this help menu
    use <module>                Select a module for usage
    search <search term>        Search for appropriate module
    list|show all               Show all available pocs
    clear                       clear the console screen
    exit                        Exit Pocsuite3"""

    module_help = """Module commands:
    run                                 Run the selected module with the given options
    back                                De-select the current module
    set <option name> <option value>    Set an option for the selected module
    setg <option name> <option value>   Set an option for all of the modules
    show [info|options|all]             Print information, options
    check                               Check if a given target is vulnerable to a selected module's attack
    attack                              Attack target and return target vulnerable infomation
    exploit                             Get a shell from remote target"""

    def __init__(self, module_directory=paths.POCSUITE_POCS_PATH):
        super(PocsuiteInterpreter, self).__init__()

        self.current_module = None
        self.raw_prompt_template = None
        self.module_prompt_template = None
        self.prompt_hostname = "Pocsuite3"
        self.show_sub_commands = (
            "info", "options", "ip", "all")

        self.global_commands = sorted(["use ", "help", "exit", "show ", "search ", "clear"])
        self.module_commands = ["run", "back", "set ", "setg ", "check"]
        self.module_commands.extend(self.global_commands)
        self.module_commands.sort()

        self.modules = index_modules(module_directory)
        self.module_parent_directory = os.sep.join(
            module_directory.rstrip(os.sep).split(os.sep)[0:-1]) + os.sep
        self.modules_count = len(self.modules)
        # init
        conf.console_mode = True
        banner()
        logger.info("Load Pocs :{}".format(self.modules_count))

        self.last_search = []
        self.last_ip = []
        self.main_modules_dirs = []
        for module in self.modules:
            temp_module = module
            temp_module = ltrim(temp_module, self.module_parent_directory).lstrip(os.sep)
            self.main_modules_dirs.append(temp_module)

        self.__parse_prompt()

    def __parse_prompt(self):
        raw_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 > "
        self.raw_prompt_template = raw_prompt_default_template
        module_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 (\001\033[91m\002{module}\001\033[0m\002) > "
        self.module_prompt_template = module_prompt_default_template

    @property
    def module_metadata(self):
        return getattr(self.current_module, "pocsuite3_module_path")

    @property
    def prompt(self):
        """ Returns prompt string based on current_module attribute.

        Adding module prefix (module.name) if current_module attribute is set.

        :return: prompt string with appropriate module prefix.
        """
        if self.current_module:
            try:
                return self.module_prompt_template.format(host=self.prompt_hostname,
                                                          module=self.module_metadata)
            except (AttributeError, KeyError):
                return self.module_prompt_template.format(host=self.prompt_hostname, module="UnnamedModule")
        else:
            return self.raw_prompt_template.format(host=self.prompt_hostname)

    def command_show(self, *args, **kwargs):
        sub_command = args[0]
        func = "_show_" + sub_command
        if not hasattr(self, func):
            logger.warning("Unknown 'show' sub-command '{}'. "
                           "What do you want to show?\n"
                           "Possible choices are: {}".format(sub_command, self.show_sub_commands))
            return
        getattr(self, func)(*args, **kwargs)

    def command_exit(self, *args, **kwargs):
        raise EOFError

    def command_clear(self, *args, **kwargs):
        if IS_WIN:
            os.system('cls')
        else:
            os.system('clear')

    def command_help(self, *args, **kwargs):
        data_to_stdout(self.global_help)
        data_to_stdout("\n")
        if self.current_module:
            data_to_stdout("\n")
            data_to_stdout(self.module_help)
            data_to_stdout("\n")

    def _show_ip(self, *args, **kwargs):
        self.last_ip = []
        ips = get_local_ip(all=True)
        tb = prettytable.PrettyTable(["Index", "IP"])
        index = 0
        for item in ips:
            tb.add_row([str(index), item])
            self.last_ip.append(item)
            index += 1
        data_to_stdout("\n" + tb.get_string() + "\n")

    def command_back(self, *args, **kwargs):
        self.current_module = None

    def command_q(self, *args, **kwargs):
        if self.current_module:
            self.command_back(args, kwargs)
        else:
            self.command_exit(args, kwargs)

    def command_search(self, *args, **kwargs):
        keyword = args[0]

        if not keyword:
            logger.warning("Please specify search keyword. e.g. 'search wordpress'")
            return

        tb = prettytable.PrettyTable()
        tb.field_names = ["Index", "Path"]

        search_result = []
        for module in self.main_modules_dirs:
            m = re.search(keyword, module, re.I | re.S)
            if m:
                search_result.append((module, m.group(0)))

        index = 0
        for s, k in search_result:
            tb.add_row([index, "{}\033[31m{}\033[0m{}".format(*s.partition(k))])
            index = index + 1

        self.last_search = [i for i, j in search_result]
        data_to_stdout(tb.get_string())
        data_to_stdout("\n")

    def command_use(self, module_path, *args, **kwargs):
        if module_path.isdigit():
            index = int(module_path)
            if index >= len(self.last_search):
                logger.warning("Index out of range")
                return
            module_path = self.last_search[index]
        if not module_path.endswith(".py"):
            module_path = module_path + ".py"
        if not os.path.exists(module_path):
            module_path = os.path.join(self.module_parent_directory, module_path)
            if not os.path.exists(module_path):
                errMsg = "No such file: '{0}'".format(module_path)
                logger.error(errMsg)
                return
        try:
            load_file_to_module(module_path)
            self.current_module = kb.current_poc
            self.current_module.pocsuite3_module_path = ltrim(
                rtrim(module_path, ".py"), self.module_parent_directory)
        except Exception as err:
            logger.error(str(err))

    @module_required
    def command_set(self, *args, **kwargs):
        key, _, value = args[0].partition(" ")
        if key in self.current_module.options:
            self.current_module.set_option(key, value)
            logger.info("{} => {}".format(key, value))
        elif key in self.current_module.global_options:
            self.current_module.setg_option(key, value)
            logger.info("{} => {}".format(key, value))
        elif key in self.current_module.payload_options:
            if value.isdigit() and key != "lport":
                index = int(value)
                if index >= len(self.last_ip):
                    logger.warning("Index out of range")
                    return
                value = self.last_ip[index]
            self.current_module.setp_option(key, value)
            logger.info("{} => {}".format(key, value))
        else:
            logger.error("You can't set option '{}'."
                         .format(key))

    def _attack_mode(self, mod):
        """
        根据不同模式发起不同的验证

        :param mod: 模式类型 verify|attack|shell
        :return:
        """
        # 设置全局参数
        if self.current_module.current_protocol == POC_CATEGORY.PROTOCOL.HTTP:
            target = self.current_module.getg_option("target")
        else:
            rhost = self.current_module.getg_option("rhost")
            rport = self.current_module.getg_option("rport")
            ssl = self.current_module.getg_option("ssl")
            scheme = "http"
            if ssl:
                scheme = "https"
            target = "{scheme}://{rhost}:{rport}".format(scheme=scheme, rhost=rhost, rport=rport)
        conf.mode = mod
        kb.task_queue.put((target, self.current_module))
        try:
            start()
        except PocsuiteShellQuitException:
            pass
        kb.results = []

    def _set_global_conf(self):
        """
        设置全局的参数

        :return:
        """
        if self.current_module.current_protocol == POC_CATEGORY.PROTOCOL.HTTP:
            conf.referer = self.current_module.getg_option("referer")
            conf.agent = self.current_module.getg_option("agent")
            conf.proxy = self.current_module.getg_option("proxy")
            conf.timeout = self.current_module.getg_option("timeout")
            # 设置全局参数

            _set_http_referer()
            _set_http_user_agent()
            _set_network_proxy()
            _set_network_timeout()

    @module_required
    def command_check(self, *args, **kwargs):
        self.current_module.check_requirement(self.current_module.global_options, self.current_module.options)
        # 检测必须参数是否被设置
        self._set_global_conf()
        self._attack_mode("verify")

    @module_required
    def command_verify(self, *args, **kwargs):
        self.command_check(args, kwargs)

    @module_required
    def command_attack(self, *args, **kwargs):
        # 检测必须参数是否被设置
        self.current_module.check_requirement(self.current_module.global_options, self.current_module.options)
        self._set_global_conf()
        self._attack_mode("attack")

    @module_required
    def command_run(self, *args, **kwargs):
        self.command_attack(args, kwargs)

    @module_required
    def command_exploit(self, *args, **kwargs):
        self.current_module.check_requirement(self.current_module.payload_options, self.current_module.global_options)
        self._set_global_conf()
        conf.connect_back_host = self.current_module.getp_option("lhost")
        conf.connect_back_port = self.current_module.getp_option("lport")
        conf.mode = "shell"
        conf.ipv6 = is_ipv6_address_format(conf.connect_back_host)
        _set_listener()
        self._attack_mode("shell")

    @module_required
    def command_shell(self, *args, **kwargs):
        self.command_exploit(args, kwargs)

    @module_required
    def command_setg(self, *args, **kwargs):
        key, _, value = args[0].partition(" ")
        if key in self.current_module.global_options:
            self.current_module.setg_option(key, value)
            logger.info("{} => {}".format(key, value))
        else:
            logger.error("You can't set option '{}'.\n"
                         "Available options: {}".format(key, self.current_module.options))

    def command_list(self, *args, **kwargs):
        # 展现所有可用的poc
        search_result = []
        tb = prettytable.PrettyTable(["Index", "Path", "Name"])
        index = 0
        for tmp_module in self.main_modules_dirs:
            found = os.path.join(self.module_parent_directory, tmp_module + ".py")
            with open(found, encoding='utf-8') as f:
                code = f.read()
            name = get_poc_name(code)
            tb.add_row([str(index), tmp_module, name])
            search_result.append(tmp_module)
            index += 1
        data_to_stdout("\n" + tb.get_string() + "\n")
        self.last_search = search_result

    def _show_all(self, *args, **kwargs):
        if self.current_module is None:
            self.command_list(args, kwargs)
        else:
            self._show_info(args, kwargs)
            self._show_options(args, kwargs)

    @module_required
    def _show_info(self, *args, **kwargs):
        fields = ["name", "VulID", "version", "author", "vulDate", "createDate", "updateDate", "references",
                  "appPowerLink", "appName", "appVersion", "vulType", "desc"]
        msg = ""
        for field in fields:
            value = getattr(self.current_module, field, None)
            if value:
                value = str(value).strip()
                # for name highlight
                if field == "name":
                    value = colored(value, "green")
                msg = msg + "%-20s %-10s\n" % (field, value)
        data_to_stdout("\n")
        data_to_stdout(msg)
        data_to_stdout("\n")

    @module_required
    def _show_options(self, *args, **kwargs):
        global_options = self.current_module.global_options
        module_options = self.current_module.options
        payload_options = self.current_module.payload_options

        tb2 = prettytable.PrettyTable(["Name", "Current settings", "Type", "Descript"])
        for name, opt in global_options.items():
            value = opt.value
            if opt.require and value == "":
                value = colored("*require*", "red")
            tb2.add_row([name, value, opt.type, opt.description])
        data_to_stdout("\nTarget options:\n")
        data_to_stdout(tb2.get_string())
        data_to_stdout("\n")

        if module_options:
            tb = prettytable.PrettyTable(["Name", "Current settings", "Type", "Descript"])
            # add target option
            for name, opt in module_options.items():
                value = opt.value
                if opt.require and value == "":
                    value = colored("*require*", "red")
                tb.add_row([name, value, opt.type, opt.description])
            data_to_stdout("\nModule options:\n")
            data_to_stdout(tb.get_string())
            data_to_stdout("\n")

        # exploit payload
        if payload_options:
            tb3 = prettytable.PrettyTable(["Name", "Current settings", "Type", "Descript"])
            for name, opt in payload_options.items():
                value = opt.value
                if opt.require and value == "":
                    value = colored("*require*", "red")
                tb3.add_row([name, value, opt.type, opt.description])
            data_to_stdout("\nExploit payloads(using reverse tcp):\n")
            data_to_stdout(tb3.get_string())
            data_to_stdout("\n")

        data_to_stdout("\n")

    @stop_after(2)
    def complete_use(self, text, *args, **kwargs):

        if text:
            all_possible_matches = filter(lambda x: x.startswith(text), self.main_modules_dirs)

            matches = set()
            for match in all_possible_matches:
                head, sep, tail = match[len(text):].partition('.')
                if not tail:
                    sep = ""
                matches.add("".join((text, head, sep)))
            return list(matches)

        else:
            return self.main_modules_dirs

    @stop_after(2)
    def complete_show(self, text, *args, **kwargs):

        if text:
            all_possible_matches = filter(lambda x: x.startswith(text), self.show_sub_commands)
            return list(all_possible_matches)

        else:
            return self.show_sub_commands

    @module_required
    @stop_after(2)
    def complete_set(self, text, *args, **kwargs):
        all_options = self.current_module.get_options().keys()

        if text:
            all_possible_matches = filter(lambda x: x.startswith(text), all_options)
            return list(all_possible_matches)

        else:
            return []
