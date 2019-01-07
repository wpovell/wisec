from subprocess import DEVNULL, call, check_output
import re
import argparse
import os
import time
import signal

from multiprocessing import Process
from scapy.all import conf as scapy_conf

from wisec.common import shorts


class Interface:
    def __init__(self, mac, name, short=None):
        self.mac = mac
        self.name = name
        if mac in shorts:
            self.short = shorts[mac]
        else:
            self.short = None
        self.hopping = None

    def set_channel(self, channel):
        '''Set channel of interface.
        Returns True to indicate success.'''
        cmd = f'iw dev {self.name} set channel {channel}'.split()
        return call(cmd, stderr=DEVNULL) == 0

    def get_channel(self):
        '''Get current interface channel.'''
        out = check_output(['iwlist', self.name, 'channel']).decode('utf-8')
        out = re.findall(r'\(Channel (\d+)\)', out)
        if out:
            return out[0]
        else:
            return None

    def get_channels(self):
        '''Get all channels interface can listen on.'''
        out = check_output(['iwlist', self.name, 'channel']).decode('utf-8')
        out = sorted(set(map(int, re.findall(r'Channel (\d+)', out))))
        return out

    def hopper(self):
        '''Function to hop between channels to listen on.'''
        channels = self.get_channels()
        while True:
            for channel in channels:
                os.system(f'iw dev {self.name} set channel {channel}')
                time.sleep(1)

    def hop(self, on):
        '''Set weather to hop between channels.'''
        if on and not self.hopping:
            self.hopping = Process(target=self.hopper)
            orig = signal.signal(signal.SIGINT, signal.SIG_IGN)
            self.hopping.start()
            signal.signal(signal.SIGINT, orig)
        elif not on and self.hopping:
            self.hopping.terminate()
            self.hopping = None

    def set_mode(self, mode='monitor'):
        '''Place interface into monitor mode.
        Returns True to indicate success.'''
        cmd = f'''
        ifconfig {self.name} down
        iwconfig {self.name} mode {mode}
        ifconfig {self.name} up
        '''
        return call(cmd, shell=True, stderr=DEVNULL) == 0

    def get_mode(self):
        '''Get current interface mode'''
        out = check_output(['iwconfig', self.name], stderr=DEVNULL).decode('utf-8')
        return re.findall(r'Mode:(\S+)', out)[0]

    def match(self, name):
        return name == self.mac or \
            name == self.name or \
            name == self.short

    @classmethod
    def find(cls, name):
        '''Find interface for name.'''
        for intr in cls.all:
            if intr.match(name):
                return intr

        return None

    def __str__(self):
        return self.name

    def summary(self):
        short = f' ({self.short})' if self.short else ''
        hopping = ' (Hopping)' if self.hopping else ''
        return f'''
Name:    {self.name}{short}
MAC:     {self.mac}
Mode:    {self.get_mode()}
Channel: {self.get_channel()}{hopping}
        '''.strip()

    @classmethod
    def set_default(cls, intr):
        '''Set default interface for wisec'''
        if 'default' in dir(cls):
            cls.default.hop(False)
        cls.default = intr
        scapy_conf.iface = intr.name

def get_all_interfaces():
    '''Get all active interfaces'''
    interfaces = []

    out = check_output(['ip', 'link'])
    lines = out.decode('utf-8').strip().split('\n')
    interface = None
    for line in lines:
        if interface is None:
            name = re.findall(r'\d+: ([a-z0-9]+)', line)
            if name and name[0].startswith('w'):
                interface = name[0]
        else:
            mac = re.findall(r'^\s+link/\S+ ([a-f0-9:]+)', line)
            if mac:
                interfaces.append(Interface(mac[0], interface))
                interface = None

    return interfaces


def init():
    '''Setup for Interface'''
    Interface.all = get_all_interfaces()
    Interface.set_default(Interface.find('adapter'))
    print(f'Interface: {Interface.default}')


def fin():
    '''Cleanup for Interface'''
    if 'default' in dir(Interface):
        Interface.default.hop(False)


# Parser #
parser = argparse.ArgumentParser(prog='interface')
subparsers = parser.add_subparsers(dest='command')

mode = subparsers.add_parser('mode')
mode.add_argument('mode', nargs='?')

ilist = subparsers.add_parser('list', help='List available interfaces')

iset = subparsers.add_parser('set', help='Set interface used by wisec')
iset.add_argument('interface')

channel = subparsers.add_parser('channel', help='Set channel used by interface')
channel.add_argument('channel')


def handler(args):
    df = Interface.default
    if args.command is None:
        # Summary
        print(df.summary())
    elif args.command == 'list':
        # List
        print('\n'.join(map(str, Interface.all)))
    elif args.command == 'mode':
        # Mode
        if args.mode:
            if not df.set_mode(args.mode):
                print('Failed to set mode')
        else:
            print(df.get_mode())
    elif args.command == 'set':
        # Set
        new = Interface.find(args.interface)
        Interface.set_default(new)
        print(f'Interface set to {new}')
    elif args.command == 'channel':
        # Channel
        if args.channel:
            if args.channel == 'hop':
                # Hop
                df.hop(True)
            else:
                # Set
                df.hop(False)
                if not df.set_channel(args.channel):
                    print('Failed to set channel')
        else:
            # Current
            print(df.get_channel())
