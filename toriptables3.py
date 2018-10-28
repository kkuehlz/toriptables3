#!/usr/bin/env python3
#
# Rewrite of toriptables2 for python3
#
"""
Tor iptables script is an anonymizer
that sets up iptables and tor to route all services
and traffic including DNS through the tor network.
"""

from argparse import ArgumentParser
from atexit import register
from os import devnull, geteuid
from os.path import basename, isfile
from pwd import getpwnam
from signal import SIGINT, SIGTERM, sigwait
from subprocess import (
    DEVNULL,
    PIPE,
    CalledProcessError,
    Popen,
    call,
    check_call,
    check_output,
)
from sys import stderr, stdout

from utils import Colors, check_tor_connect

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
        call(["iptables", "-F"])
        call(["iptables", "-t", "nat", "-F"])

    def load_iptables_rules(self):
        self.flush_iptables_rules()

        @register
        def restart_tor():
            try:
                status = check_call(
                    ["systemctl", "restart", "tor"], stdout=DEVNULL, stderr=DEVNULL
                )
                if status != 0:
                    print(f"{Colors.ORANGE}[!] Could not restart Tor!")
                    return

            except CalledProcessError as err:
                print(f"{Colors.ORANGE}[!] Command failed: {err.cmd}{Colors.DEFAULT}")

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

        for subnet in self.tor_no_forward:
            call(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "OUTPUT",
                    "-d",
                    str(subnet),
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

        for subnet in self.tor_no_forward:
            call(["iptables", "-A", "OUTPUT", "-d", str(subnet), "-j", "ACCEPT"])

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


def load(tor_iptables):
    tor_iptables.load_iptables_rules()
    print(f"  [{Colors.ORANGE}*{Colors.DEFAULT}] Getting public IP, please wait...")
    public_ip = check_tor_connect()
    if public_ip is None:
        print(f" {Colors.ORANGE}[!]{Colors.DEFAULT} Can't get public ip address!")
        exit(1)
    print(
        f"  [{Colors.ORANGE}+{Colors.DEFAULT}] Your IP is {Colors.ORANGE}{public_ip}{Colors.DEFAULT}"
    )
    print(
        f"  [{Colors.ORANGE}+{Colors.DEFAULT}] Anonymizer status {Colors.ORANGE}[ON]{Colors.DEFAULT}"
    )


def flush(tor_iptables):
    tor_iptables.flush_iptables_rules()
    print(
        f"  [{Colors.PINK}!{Colors.DEFAULT}] Anonymizer status {Colors.ORANGE}[OFF]{Colors.DEFAULT}"
    )


def transient(tor_iptables):
    SIGSET = frozenset({SIGINT, SIGTERM})

    try:
        old_rules = check_output(["iptables-save"])
    except CalledProcessError as err:
        print(f"  {Colors.ORANGE}[!] Could not save iptables rules{Colors.DEFAULT}")
        print(f"  {Colors.ORANGE}[!] Command failed: {err.cmd}{Colors.DEFAULT}")

    print(f"  [{Colors.PINK}+{Colors.DEFAULT}] iptables rules saved")
    flush(tor_iptables)
    load(tor_iptables)
    sigwait(SIGSET)
    p = Popen(["iptables-restore"], stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL)
    r = p.communicate(old_rules)
    if p.returncode == 0:
        print(f"  [{Colors.PINK}+{Colors.DEFAULT}] iptables rules restored")
    else:
        print(
            f"  [{Colors.ORANGE}!{Colors.DEFAULT}] Could not restore iptables rules. Dumping to output!"
        )
        print(old_rules.decode())
        exit(1)


def main():
    if geteuid() != 0:
        print("[!] Needs to be run as root. Quitting")
        exit(1)

    parser = ArgumentParser(
        description="iptables rules to route all traffic through tor"
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
        load(tor_iptables)
    elif args.flush:
        flush(tor_iptables)
    else:
        transient(tor_iptables)


if __name__ == "__main__":
    main()
