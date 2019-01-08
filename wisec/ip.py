import argparse
import os

parser = argparse.ArgumentParser(prog='ip')
sub = parser.add_subparsers(dest='cmd')
forward = sub.add_parser('forward')
forward.add_argument('status', nargs='?', choices=['disable', 'enable'])

forward_path = '/proc/sys/net/ipv4/ip_forward'


def set_forward(on):
    val = 1 if on else 0
    os.system(f'echo {val} > {forward_path}')


def get_forward():
    with open(forward_path) as f:
        return f.read().strip() != '0'

def handler(args):
    if args.cmd == 'forward':
        if args.status:
            set_forward(args.status == 'on')

        if get_forward():
            print("Forwarding enabled")
        else:
            print("Forwarding disabled")
