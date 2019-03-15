import logging


def remove_extra_log_message():
    logger_names = [
        "paramiko",
        "paramiko.transport",
        "websockets",

    ]

    for logger_name in logger_names:
        try:
            logging.getLogger(logger_name).disabled = True
        except Exception:
            pass
