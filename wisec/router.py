import argparse
from scapy.sendrecv import sniff
from scapy.all import Dot11Beacon, Dot11ProbeResp, Dot11, Dot11Elt

from wisec.interface import Interface


class Router:
    def __init__(self, p):
        self.ssid = p[Dot11Elt].info.decode('utf-8')
        self.bssid = p[Dot11].addr3
        self.channel = int(ord(p[Dot11Elt:3].info))

    def __str__(self):
        name = f'"{self.ssid}"'
        return f'{name:20} ({self.bssid} on Ch {self.channel})'

    def match(self, name):
        return name == self.ssid or name == self.bssid


parser = argparse.ArgumentParser(prog='router')
sub = parser.add_subparsers(dest='cmd')
scan = sub.add_parser('scan', help='Scan for routers')
scan.add_argument('-H', dest='hop', action='store_true', help='Channel hop')

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
        return bssids[name]

    for r in bssids.values():
        if r.match(name):
            return r

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
            sniff(prn=scan)
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
