#!/usr/bin/env python3
#
# Rewrite of toriptables2 for python3
#
"""
Tor iptables script is an anonymizer
that sets up iptables and tor to route all services
and traffic including DNS through the tor network.
"""

from subprocess import call, check_call, CalledProcessError
from subprocess import DEVNULL
from os.path import isfile, basename
from os import devnull
from os import geteuid
from pwd import getpwnam
from sys import stdout, stderr
from atexit import register
from argparse import ArgumentParser
from json import load

# from urllib2 import urlopen, URLError
from time import sleep

NAME = "toriptables3"
VERSION = "0.0.1"


class TorIptables(object):
    def __init__(self):
        self.default_dns_port = "53"
        # Local DNS port used by Tor
        self.local_dns_port = "5353"
        # Virtual Network assigned for Tor
        self.virtual_net_addr = "10.0.0.0/10"
        self.loopback = "127.0.0.1"
        self.tor_no_forward = frozenset(
            {
                "192.168.0.0/16",
                "172.16.0.0/12",
                "127.0.0.0/9",
                "127.128.0.0/10",
                "127.0.0.0/8",
            }
        )
        self.tor_uid = self._get_tor_uid()
        self.trans_port = "9040"  # Tor port
        self.torrc = "/etc/tor/torrc"

    def _get_tor_uid(self):
        uids = frozenset({"tor", "debian-tor"})
        tor_uid = None
        for uid in uids:
            try:
                tor_uid = getpwnam(uid).pw_uid
            except KeyError:
                pass
        return tor_uid

    def mod_config(self):
        torrc_iptables_rules = f"""
## DO NOT MODIFY!!
## Inserted by {NAME}, version {VERSION} for Tor iptables rules
## Transparently route all traffic through Tor on port {self.trans_port}
VirtualAddrNetwork {self.virtual_net_addr}
AutomapHostsOnResolve 1
TransPort {self.trans_port} 
DNSPort {self.local_dns_port} 
"""
        need_mod = True
        with open(self.torrc, "r") as tor_conf:
            needs_mod = not any(
                [
                    f"## Inserted by {NAME}, version {VERSION} for Tor iptables rules"
                    in line
                    for line in tor_conf.readlines()
                ]
            )
        if needs_mod:
            with open(self.torrc, "a+") as tor_conf:
                tor_conf.write(torrc_iptables_rules)

    def flush_iptables_rules(self):
        """Flush iptables rules and NAT rules"""
        call(["iptables", "-F"])
        call(["iptables", "-t", "nat", "-F"])

    def load_iptables_rules(self):
        self.flush_iptables_rules()

        @register
        def restart_tor():
            fnull = open(devnull, "w")
            try:
                status = check_call(
                    ["systemctl", "restart", "tor"], stdout=DEVNULL, stderr=DEVNULL
                )
                if status != 0:
                    print("\033[91m[!] Could not restart Tor!")
                    return

            except CalledProcessError as err:
                print("\033[91m[!] Command failed: {err.cmd}\033[0m")

            print("  [\033[92m+\033[0m] Anonymizer status \033[92m[ON]\033[0m")
            print("  [\033[92m*\033[0m] Getting public IP, please wait...")
            # retries = 0
            # my_public_ip = None
            # while retries < 12 and not my_public_ip:
            #    retries += 1
            #    try:
            #        my_public_ip = load(urlopen("http://ident.me/.json"))["address"]
            #    except URLError:
            #        sleep(5)
            #        print(" [\033[93m?\033[0m] Still waiting for IP address...")
            # if not my_public_ip:
            #    my_public_ip = getoutput("wget -qO - v4.ifconfig.co")
            # if not my_public_ip:
            #    exit(" \033[91m[!]\033[0m Can't get public ip address!")
            # print(
            #    " {0}".format(
            #        "[\033[92m+\033[0m] Your IP is \033[92m%s\033[0m" % my_public_ip
            #    )
            # )

        # See https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy#WARNING
        # See https://lists.torproject.org/pipermail/tor-talk/2014-March/032503.html
        call(
            [
                "iptables",
                "-I",
                "OUTPUT",
                "!",
                "-o",
                "lo",
                "!",
                "-d",
                self.loopback,
                "!",
                "-s",
                self.loopback,
                "-p",
                "tcp",
                "-m",
                "tcp",
                "--tcp-flags",
                "ACK,FIN",
                "ACK,FIN",
                "-j",
                "DROP",
            ]
        )
        call(
            [
                "iptables",
                "-I",
                "OUTPUT",
                "!",
                "-o",
                "lo",
                "!",
                "-d",
                self.loopback,
                "!",
                "-s",
                self.loopback,
                "-p",
                "tcp",
                "-m",
                "tcp",
                "--tcp-flags",
                "ACK,RST",
                "ACK,RST",
                "-j",
                "DROP",
            ]
        )

        call(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-m",
                "owner",
                "--uid-owner",
                str(self.tor_uid),
                "-j",
                "RETURN",
            ]
        )
        call(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-p",
                "udp",
                "--dport",
                self.default_dns_port,
                "-j",
                "REDIRECT",
                "--to-ports",
                self.local_dns_port,
            ]
        )

        for net in self.tor_no_forward:
            call(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "OUTPUT",
                    "-d",
                    str(net),
                    "-j",
                    "RETURN",
                ]
            )

        call(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--syn",
                "-j",
                "REDIRECT",
                "--to-ports",
                str(self.trans_port),
            ]
        )

        call(
            [
                "iptables",
                "-A",
                "OUTPUT",
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
        )

        for net in self.tor_no_forward:
            call(["iptables", "-A", "OUTPUT", "-d", str(net), "-j", "ACCEPT"])

        call(
            [
                "iptables",
                "-A",
                "OUTPUT",
                "-m",
                "owner",
                "--uid-owner",
                str(self.tor_uid),
                "-j",
                "ACCEPT",
            ]
        )
        call(["iptables", "-A", "OUTPUT", "-j", "REJECT"])

    def check_tor_connect():
        pass


if __name__ == "__main__":
    if geteuid() != 0:
        print("[!] Needs to be run as super user. Quitting")
        exit(1)

    parser = ArgumentParser(
        description="Tor Iptables script for loading and unloading iptables rules"
    )
    parser.add_argument(
        "-l",
        "--load",
        action="store_true",
        help="This option will load tor iptables rules",
    )
    parser.add_argument(
        "-f",
        "--flush",
        action="store_true",
        help="This option flushes the iptables rules to default",
    )
    args = parser.parse_args()

    tor_iptables = TorIptables()
    tor_iptables.mod_config()

    if args.load:
        load_tables.load_iptables_rules()
    elif args.flush:
        load_tables.flush_iptables_rules()
        print("  [\033[93m!\033[0m] Anonymizer status \033[91m[OFF]\033[0m")
    else:
        # TODO: transient mode
        parser.print_help()
