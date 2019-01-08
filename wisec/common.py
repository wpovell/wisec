#!/usr/bin/env python3
from scapy.all import conf, ltoa
from netaddr import IPNetwork

gateway = conf.route.route('0.0.0.0')[-1]

lan = None
for route in conf.route.routes:
    network, netmask, gate, iface, out, metric = route
    if iface != 'lo' and gate == '0.0.0.0':
        lan = str(IPNetwork(ltoa(network) + '/' + ltoa(netmask)))

shorts = {
    '40:4e:36:8f:85:07': 'pixel',
    '00:c0:ca:a5:b9:0c': 'adapter',
    'b0:35:9f:c3:71:6b': 'lambda',
    '0c:d5:02:68:af:a0': 'home',
}
