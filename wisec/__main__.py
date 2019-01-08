import cmd2
import os
import sys
import argparse

from scapy.all import conf as scapy_conf

from wisec import interface, deauth, router, arp

parser = argparse.ArgumentParser(prog='interface')
subparsers = parser.add_subparsers()

mode = subparsers.add_parser('mode')
lst = subparsers.add_parser('list')
set = subparsers.add_parser('set')


class WifiShell(cmd2.Cmd):
    prompt = '> '
    debug = True

    def __init__(self):
        p = os.path.expanduser('~/.sec_history')
        super().__init__(persistent_history_file=p)

        # Remove unused cmd2 commands
        self.do_py = None
        self.do_pyscript = None
        self.do_set = None
        self.do_shortcuts = None
        self.do_macro = None
        self.do_history = None
        self.do_alias = None

    def postloop(self):
        interface.fin()
        arp.fin()

    @cmd2.with_argparser(interface.parser)
    def do_interface(self, args):
        interface.handler(args)

    @cmd2.with_argparser(deauth.parser)
    def do_deauth(self, args):
        deauth.handler(args)

    @cmd2.with_argparser(router.parser)
    def do_router(self, args):
        router.handler(args)

    @cmd2.with_argparser(arp.parser)
    def do_arp(self, args):
        arp.handler(args)


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Must be run as root.")
        sys.exit(1)

    os.system('figlet wisec')
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    scapy_conf.verb = 0
    interface.init()
    print()

    sh = WifiShell().cmdloop()
