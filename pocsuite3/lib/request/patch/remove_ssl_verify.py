import ssl


def remove_ssl_verify():
    # It doesn't seem to work. 09/07/2022
    ssl._create_default_https_context = ssl._create_unverified_context
