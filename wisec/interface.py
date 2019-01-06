from subprocess import DEVNULL, call, check_output
import re


class Interface:
    shorts = {
        '00:c0:ca:a5:b9:0c': 'adapter',
        'b0:35:9f:c3:71:6b': 'lambda',
    }

    def __init__(self, mac, name, short=None):
        self.mac = mac
        self.name = name
        if mac in Interface.shorts:
            self.short = Interface.shorts[mac]
        else:
            self.short = None

    def monitor(self):
        '''Place interface into monitor mode.
        Returns True to indicate success.'''

        cmd = f'''
        ifconfig {self.name} down
        iwconfig {self.name} mode monitor
        ifconfig {self.name} up
        '''
        return call(cmd, shell=True, stderr=DEVNULL) == 0

    def match(self, name):
        return name == self.mac or \
               name == self.name or \
               name == self.short

    @classmethod
    def all_names(cls):
        '''List of all interface names.'''
        names = []
        for intr in cls.all:
            names.append(intr.mac)
            names.append(intr.name)
            if intr.short is not None:
                names.append(intr.short)

        return names

    @classmethod
    def find(cls, name):
        '''Find interface for name.'''
        for intr in cls.all:
            if intr.match(name):
                return intr

        return None

    def __str__(self):
        return self.name


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


Interface.all = get_all_interfaces()
Interface.default = Interface.find('adapter')
