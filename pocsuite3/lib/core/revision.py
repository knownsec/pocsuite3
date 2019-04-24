import os
import re
import subprocess


def stdout_encode(data):
    """
    Cross-linked function
    """
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    else:
        data = str(data)
    return data


def get_revision_number():
    """
    Returns abbreviated commit hash number as retrieved with "git rev-parse --short HEAD"
    """

    ret = None
    file_path = None
    _ = os.path.dirname(__file__)

    while True:
        file_path = os.path.join(_, ".git", "HEAD")
        if os.path.exists(file_path):
            break
        else:
            file_path = None
            if _ == os.path.dirname(_):
                break
            else:
                _ = os.path.dirname(_)

    while True:
        if file_path and os.path.isfile(file_path):
            with open(file_path, "r") as f:
                content = f.read()
                file_path = None
                if content.startswith("ref: "):
                    file_path = os.path.join(_, ".git", content.replace("ref: ", "")).strip()
                else:
                    match = re.match(r"(?i)[0-9a-f]{32}", content)
                    ret = match.group(0) if match else None
                    break
        else:
            break

    if not ret:
        process = subprocess.Popen("git rev-parse --verify HEAD",
                                   shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, _ = process.communicate()
        stdout = stdout_encode(stdout)
        match = re.search(r"(?i)[0-9a-f]{32}", stdout or "")
        ret = match.group(0) if match else None

    return ret[:7] if ret else None
