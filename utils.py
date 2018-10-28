import re
from time import sleep

import requests

URI_TOR_CHECK = "https://check.torproject.org/"


class Colors(object):
    DEFAULT = "\033[0m"
    ORANGE = "\033[91m"
    PINK = "\033[92m"


def check_tor_connect():
    IP_ADDR_REGEX = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    connected_msg = "Congratulations. This browser is configured to use Tor."
    retries = 0
    my_public_ip = None
    while retries < 12:
        try:
            r = requests.get(URI_TOR_CHECK)
            if r.status_code == 200 and any(
                [connected_msg in line for line in r.text.splitlines()]
            ):
                ip = re.search(IP_ADDR_REGEX, r.text)
                if ip:
                    my_public_ip = ip.group(0)
                    break
        except requests.ConnectionError:
            pass
        print(f" [{Colors.PINK}?{Colors.DEFAULT}] Still waiting for IP address...")
        sleep(3)
        retries += 1

    return my_public_ip
