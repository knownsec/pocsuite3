import copy
import time

from pocsuite3.lib.core.common import data_to_stdout, desensitization
from pocsuite3.lib.core.data import conf, cmd_line_options
from pocsuite3.lib.core.data import kb
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.datatype import AttribDict
from pocsuite3.lib.core.exception import PocsuiteValidationException, PocsuiteSystemException
from pocsuite3.lib.core.poc import Output
from pocsuite3.lib.core.settings import CMD_PARSE_WHITELIST
from pocsuite3.lib.core.threads import run_threads
from pocsuite3.modules.listener import handle_listener_connection
from pocsuite3.modules.listener.reverse_tcp import handle_listener_connection_for_console
from pocsuite3.thirdparty.prettytable.prettytable import PrettyTable


def runtime_check():
    if not kb.registered_pocs:
        error_msg = "no PoC loaded, please check your PoC file"
        logger.error(error_msg)
        raise PocsuiteSystemException(error_msg)


def start():
    runtime_check()
    tasks_count = kb.task_queue.qsize()
    info_msg = "pocsusite got a total of {0} tasks".format(tasks_count)
    logger.info(info_msg)
    logger.debug("pocsuite will open {} threads".format(conf.threads))

    try:
        run_threads(conf.threads, task_run)
        logger.info("Scan completed,ready to print")
    finally:
        task_done()

    if conf.mode == "shell" and not conf.api:
        info_msg = "connect back ip: {0}    port: {1}".format(
            desensitization(conf.connect_back_host) if conf.ppt else conf.connect_back_host, conf.connect_back_port)
        logger.info(info_msg)
        info_msg = "watting for shell connect to pocsuite"
        logger.info(info_msg)
        if conf.console_mode:
            handle_listener_connection_for_console()
        else:
            handle_listener_connection()


def show_task_result():
    if conf.quiet:
        return

    if not kb.results:
        return

    if conf.mode == "shell":
        return

    fields = ["target-url", "poc-name", "poc-id", "component", "version", "status"]
    if kb.comparison:
        fields.append("source")
        fields.append("honey-pot")
    results_table = PrettyTable(fields)
    results_table.align["target-url"] = "l"
    results_table.padding_width = 1

    total_num, success_num = 0, 0
    for row in kb.results:
        data = [
            row.target,
            row.poc_name,
            row.vul_id,
            row.app_name,
            row.app_version,
            row.status,
        ]
        if kb.comparison:
            source, honey = kb.comparison.getinfo(row.target)
            data.append(source)
            data.append(honey)
        results_table.add_row(data)
        total_num += 1
        if row.status == 'success':
            success_num += 1

    data_to_stdout('\n{0}'.format(results_table.get_string(sortby="status", reversesort=True)))
    data_to_stdout("\nsuccess : {} / {}\n".format(success_num, total_num))


def task_run():
    while not kb.task_queue.empty() and kb.thread_continue:
        target, poc_module = kb.task_queue.get()
        if not conf.console_mode:
            poc_module = copy.deepcopy(kb.registered_pocs[poc_module])
        poc_name = poc_module.name

        if conf.pcap:
            # start capture flow
            import urllib
            from pocsuite3.thirdparty.scapy.scapy_test import Sniffer
            from pocsuite3.thirdparty.scapy.utils import wrpcap
            sniffer = Sniffer(urllib.parse.urlparse(target).hostname)
            if sniffer.use_pcap:
                if not sniffer.is_admin:
                    logger.warn("Please use administrator privileges, and the poc will continue to execute without fetching the packet")
                    conf.pcap = False
                else:
                    sniffer.start()
                    #let scapy start for a while
                    time.sleep(1)
            else:
                logger.warn("No libpcap is detected, and the poc will continue to execute without fetching the packet")
                conf.pcap = False

        # for hide some infomations
        if conf.ppt:
            info_msg = "running poc:'{0}' target '{1}'".format(poc_name, desensitization(target))
        else:
            info_msg = "running poc:'{0}' target '{1}'".format(poc_name, target)

        logger.info(info_msg)

        # hand user define parameters
        if hasattr(poc_module, "_options"):
            for item in kb.cmd_line:
                value = cmd_line_options.get(item, "")
                if item in poc_module.options:
                    poc_module.set_option(item, value)
                    info_msg = "Parameter {0} => {1}".format(item, value)
                    logger.info(info_msg)
            # check must be option
            for opt, v in poc_module.options.items():
                # check conflict in whitelist
                if opt in CMD_PARSE_WHITELIST:
                    info_msg = "Poc:'{0}' You can't customize this variable '{1}' because it is already taken up by the pocsuite.".format(
                        poc_name, opt)
                    logger.error(info_msg)
                    raise SystemExit

                if v.require and v.value == "":
                    info_msg = "Poc:'{poc}' Option '{key}' must be set,please add parameters '--{key}'".format(
                        poc=poc_name, key=opt)
                    logger.error(info_msg)
                    raise SystemExit

        try:
            result = poc_module.execute(target, headers=conf.http_headers, mode=conf.mode, verbose=False)
        except PocsuiteValidationException as ex:
            info_msg = "Poc:'{}' PocsuiteValidationException:{}".format(poc_name, ex)
            logger.error(info_msg)
            result = None

        if not isinstance(result, Output) and not None:
            _result = Output(poc_module)
            if result:
                if isinstance(result, bool):
                    _result.success({})
                elif isinstance(result, str):
                    _result.success({"Info": result})
                elif isinstance(result, dict):
                    _result.success(result)
                else:
                    _result.success({"Info": repr(result)})
            else:
                _result.fail('target is not vulnerable')

            result = _result

        if not result:
            continue

        if not conf.quiet:
            result.show_result()

        result_status = "success" if result.is_success() else "failed"
        if result_status == "success" and kb.comparison:
            kb.comparison.change_success(target, True)

        output = AttribDict(result.to_dict())
        if conf.ppt:
            # hide some information
            target = desensitization(target)

        output.update({
            'target': target,
            'poc_name': poc_name,
            'created': time.strftime("%Y-%m-%d %X", time.localtime()),
            'status': result_status
        })
        result_plugins_handle(output)
        kb.results.append(output)
        if conf.pcap:
            sniffer.join(20)
            import urllib
            if not sniffer.is_alive():
                logger.info("save pcap data in :{}".format(poc_name + time.strftime(" %Y%m%d%H ") + urllib.parse.urlparse(target).hostname+'.pcap'))
                wrpcap(poc_name + time.strftime(" %Y%m%d%H ") + urllib.parse.urlparse(target).hostname+'.pcap', sniffer.pcap.results)
            else:
                logger.error("Thread terminates timeout. Failed to save pcap")

        # TODO
        # set task delay


def result_plugins_start():
    """
    run result plugins, such as html report
    :return:
    """
    for _, plugin in kb.plugins.results.items():
        plugin.start()


def result_plugins_handle(output):
    """
    run result plugins when execute poc
    :return:
    """
    for _, plugin in kb.plugins.results.items():
        plugin.handle(output)


def result_compare_handle():
    """
    show comparing data from various of search engine
    :return:
    """
    if not kb.comparison:
        return
    kb.comparison.output()


def task_done():
    show_task_result()
    result_plugins_start()
    result_compare_handle()
