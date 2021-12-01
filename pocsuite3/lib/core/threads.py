import time
import threading
import traceback

from pocsuite3.lib.core.data import conf
from pocsuite3.lib.core.data import kb
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.exception import PocsuiteConnectionException
from pocsuite3.lib.core.exception import PocsuiteUserQuitException
from pocsuite3.lib.core.exception import PocsuiteValueException
from pocsuite3.lib.core.settings import MAX_NUMBER_OF_THREADS


def exception_handled_function(thread_function, args=(), silent=False):
    try:
        thread_function(*args)
    except KeyboardInterrupt:
        kb.thread_continue = False
        kb.thread_exception = True
        raise
    except Exception as ex:
        if not silent:
            logger.error("thread {0}: {1}".format(threading.currentThread().getName(), str(ex)))
            if conf.verbose > 1:
                traceback.print_exc()


def run_threads(num_threads, thread_function, args: tuple = (), forward_exception=True, start_msg=True):
    threads = []

    kb.multi_thread_mode = True
    kb.thread_continue = True
    kb.thread_exception = False

    try:
        if num_threads > 1:
            if start_msg:
                info_msg = "starting {0} threads".format(num_threads)
                logger.info(info_msg)

            if num_threads > MAX_NUMBER_OF_THREADS:
                warn_msg = "starting {0} threads, more than MAX_NUMBER_OF_THREADS:{1}".format(num_threads, MAX_NUMBER_OF_THREADS)
                logger.warn(warn_msg)

        else:
            thread_function(*args)
            return

        # Start the threads
        for num_threads in range(num_threads):
            thread = threading.Thread(target=exception_handled_function, name=str(num_threads),
                                      args=(thread_function, args))
            thread.setDaemon(True)
            try:
                thread.start()
            except Exception as ex:
                err_msg = "error occurred while starting new thread ('{0}')".format(str(ex))
                logger.critical(err_msg)
                break

            threads.append(thread)

        # And wait for them to all finish
        alive = True
        while alive:
            alive = False
            for thread in threads:
                if thread.is_alive():
                    alive = True
                    time.sleep(0.1)

    except (KeyboardInterrupt, PocsuiteUserQuitException):
        kb.thread_continue = False
        kb.thread_exception = True
        logger.info("user aborted (Ctrl+C was pressed multiple times")
        if forward_exception:
            return

    except (PocsuiteConnectionException, PocsuiteValueException) as ex:
        kb.thread_exception = True
        logger.error("thread {0}: {1}".format(threading.currentThread().getName(), str(ex)))
        if conf.verbose > 1:
            traceback.print_exc()

    except Exception as ex:
        kb.thread_exception = True
        logger.error("thread {0}: {1}".format(threading.currentThread().getName(), str(ex)))
        traceback.print_exc()

    finally:
        kb.multi_thread_mode = False
        kb.thread_continue = True
        kb.thread_exception = False
