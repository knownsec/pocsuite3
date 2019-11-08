import os
import sys
import threading
import time
import traceback

try:
    import pocsuite3
except ImportError:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from pocsuite3.lib.core.option import init
from pocsuite3.lib.core.option import init_options
from pocsuite3.lib.core.exception import PocsuiteUserQuitException, PocsuiteSystemException
from pocsuite3.lib.core.exception import PocsuiteShellQuitException
from pocsuite3.lib.core.common import set_paths
from pocsuite3.lib.core.common import banner
from pocsuite3.lib.core.common import data_to_stdout
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.parse.cmd import cmd_line_parser
from pocsuite3.lib.controller.controller import start


def module_path():
    """
    This will get us the program's directory
    """
    return os.path.dirname(os.path.realpath(__file__))


def check_environment():
    try:
        os.path.isdir(module_path())
    except Exception:
        err_msg = "your system does not properly handle non-ASCII paths. "
        err_msg += "Please move the pocsuite's directory to the other location"
        logger.critical(err_msg)
        raise SystemExit


def main():
    """
    @function Main function of pocsuite when running from command line.
    """
    try:
        check_environment()
        set_paths(module_path())
        banner()

        init_options(cmd_line_parser().__dict__)

        data_to_stdout("[*] starting at {0}\n\n".format(time.strftime("%X")))
        init()
        try:
            start()
        except threading.ThreadError:
            raise

    except PocsuiteUserQuitException:
        pass

    except PocsuiteShellQuitException:
        pass

    except PocsuiteSystemException:
        pass

    except KeyboardInterrupt:
        pass

    except EOFError:
        pass

    except SystemExit:
        pass

    except Exception:
        exc_msg = traceback.format_exc()
        data_to_stdout(exc_msg)
        raise SystemExit

    finally:
        data_to_stdout("\n[*] shutting down at {0}\n\n".format(time.strftime("%X")))


if __name__ == "__main__":
    main()
