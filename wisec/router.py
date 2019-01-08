import argparse
from scapy.sendrecv import sniff
from scapy.all import Dot11Beacon, Dot11ProbeResp, Dot11, Dot11Elt

from wisec.interface import Interface
from wisec.common import shorts


class Router:
    def __init__(self, pkt):
        self.bssid = pkt[Dot11].addr3

        p = pkt[Dot11Elt]
        self.crypto = set()
        while isinstance(p, Dot11Elt):
            if p.ID == 0:
                self.ssid = p.info.decode('utf-8')
            elif p.ID == 3:
                self.channel = ord(p.info)
            elif p.ID == 48:
                self.crypto.add("WPA2")
            elif p.ID == 221:
                if p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    self.crypto.add("WPA")

            p = p.payload

        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                          "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
        if not self.crypto:
            if 'privacy' in cap:
                self.crypto.add("WEP")
            else:
                self.crypto.add("OPN")

    def __str__(self):
        name = f'"{self.ssid}"'
        sec = ' ({})'.format(' '.join(sorted(self.crypto)))
        return f'{name:25} ({self.bssid} on Ch {self.channel}){sec}'

    def match(self, name):
        return name == self.ssid or name == self.bssid


parser = argparse.ArgumentParser(prog='router')
sub = parser.add_subparsers(dest='cmd')
scan = sub.add_parser('scan', help='Scan for routers')
scan.add_argument('-H', dest='hop', action='store_true', help='Channel hop')
scan.add_argument('-t', dest='timeout', default=10, type=int)

sub.add_parser('list', help='List found routers')
bssids = {}


def get_bssids():
    ret = []
    for router in bssids.values():
        ret.append(router.bssid)
        ret.append(router.ssid)
    return ret


def to_mac(name):
    if name in bssids:
        return bssids[name].bssid

    for r in bssids.values():
        if r.match(name):
            return r.bssid

    for m, n in shorts.items():
        if n == name:
            return m

    return name

c = 0
def scan(p):
    global c
    if (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)):
        bssid = p[Dot11].addr3
        if bssid not in bssids:
            c += 1
            router = Router(p)
            bssids[bssid] = router
            print(router)


def handler(args):
    global c
    if args.cmd == 'scan':
        if args.hop:
            Interface.default.hop(True)
            c = 0
        try:
            sniff(prn=scan, timeout=args.timeout)
        except KeyboardInterrupt:
            pass
        finally:
            if args.hop:
                Interface.default.hop(False)
                total = len(bssids)
                print(f'\n{c} new / {total} total')
    elif args.cmd == 'list':
        print('\n'.join(map(str, bssids.values())))
    else:
        parser.print_help()
