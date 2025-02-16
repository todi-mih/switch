#!/usr/bin/python3
import sys
import struct
import threading
import time
import os
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name, init

# Port states for STP
PORT_BLOCKING = 0
PORT_LISTENING = 1
VLAN_Table = {}  # Format: interface_name: vlan_id
Trunk_Ports = set()  # Trunk ports for current switch only
MAC_Table = {}  # Format: mac_addr: port


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id
def load_vlan_config(filename):
    priority = None
    global VLAN_Table, Trunk_Ports

    with open(filename, 'r') as file:
        lines = file.readlines()
        priority = int(lines[0].strip())

        for line in lines[1:]:
            parts = line.strip().split()
            interface_name = parts[0]
            if parts[1] == "T":
                Trunk_Ports.add(interface_name)
            else:
                vlan_id = int(parts[1])
                VLAN_Table[interface_name] = vlan_id

    return priority, VLAN_Table, Trunk_Ports

class STPPort:
    def __init__(self, interface_name, interface_id):
        self.interface_name = interface_name
        self.interface_id = interface_id
        self.state = PORT_BLOCKING
        self.is_root_port = False
        self.is_designated_port = False

class STPSwitch:
    def __init__(self, priority):
        self.priority = priority
        self.own_bridge_id = priority
        self.root_bridge_id = self.own_bridge_id
        self.root_path_cost = 0
        self.root_port = None
        self.ports = {}
        self.bpdu_multicast = bytes.fromhex('0180c2000000')

    def initialize_ports(self, trunk_ports, interfaces):
        for interface in interfaces:
            interface_name = get_interface_name(interface)
            if interface_name in trunk_ports:
                port = STPPort(interface_name, interface)
                port.state = PORT_BLOCKING
                self.ports[interface_name] = port

        if self.own_bridge_id == self.root_bridge_id:
            for port in self.ports.values():
                port.state = PORT_LISTENING
                port.is_designated_port = True

    def create_bpdu_frame(self):
        llc_header = struct.pack('!3B', 0x42, 0x42, 0x03)
        bpdu_config = struct.pack('!B8sL8sHHHHH',
            0,  # flags
            self.root_bridge_id.to_bytes(8, 'big'),  # root bridge ID
            self.root_path_cost,  # root path cost
            self.own_bridge_id.to_bytes(8, 'big'),  # sender bridge ID
            0,  # port ID
            0,  # message age
            20,  # max age
            2,  # hello time
            15   # forward delay
        )

        llc_length = len(llc_header) + 4 + len(bpdu_config)
        frame = (
            self.bpdu_multicast +
            get_switch_mac() +
            struct.pack('!H', llc_length) +
            llc_header +
            b'\x00\x00\x00\x00' +
            bpdu_config
        )
        return frame

    def send_bpdu(self, exclude_interface=None):
        if self.own_bridge_id == self.root_bridge_id:
            bpdu_frame = self.create_bpdu_frame()
            for port in self.ports.values():
                if port.state == PORT_LISTENING and port.is_designated_port:
                    send_to_link(port.interface_id, len(bpdu_frame), bpdu_frame)

    def process_bpdu(self, data, interface):
        interface_name = get_interface_name(interface)
        if interface_name not in self.ports:
            return

        offset = 14 + 3
        root_bridge_id = int.from_bytes(data[offset+1:offset+9], 'big')
        sender_path_cost = int.from_bytes(data[offset+9:offset+13], 'big')
        sender_bridge_id = int.from_bytes(data[offset+13:offset+21], 'big')

        was_root = (self.own_bridge_id == self.root_bridge_id)
        port = self.ports[interface_name]

        if root_bridge_id < self.root_bridge_id:
            self.root_bridge_id = root_bridge_id
            self.root_path_cost = sender_path_cost + 10
            self.root_port = port
            port.state = PORT_LISTENING
            port.is_root_port = True

            if was_root:
                for p in self.ports.values():
                    if p != port:
                        p.state = PORT_BLOCKING
                        p.is_designated_port = False

            self.send_bpdu(interface)

        elif root_bridge_id == self.root_bridge_id:
            if port == self.root_port and sender_path_cost + 10 < self.root_path_cost:
                self.root_path_cost = sender_path_cost + 10
            elif port != self.root_port:
                if sender_path_cost > self.root_path_cost:
                    if not port.is_designated_port:
                        port.state = PORT_LISTENING
                        port.is_designated_port = True

        elif sender_bridge_id == self.own_bridge_id:
            port.state = PORT_BLOCKING

        if self.own_bridge_id == self.root_bridge_id:
            for p in self.ports.values():
                p.state = PORT_LISTENING
                p.is_designated_port = True

def send_bpdu_every_sec():
    while True:
        time.sleep(1)
        if stp and stp.own_bridge_id == stp.root_bridge_id:
            stp.send_bpdu()

def is_bpdu_frame(data):
    return data[0:6] == bytes.fromhex('0180c2000000')

def create_vlan_tag(vlan_id):
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def forward_frame(interface, data, vlan_id):
    interface_name = get_interface_name(interface)
    if interface_name in stp.ports and stp.ports[interface_name].state != PORT_LISTENING:
        return

    outgoing_data = data
    if interface_name in Trunk_Ports:
        if vlan_id != -1 and data[12:14] != b'\x82\x00':
            outgoing_data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
    else:
        if data[12:14] == b'\x82\x00':
            outgoing_data = data[0:12] + data[16:]

    send_to_link(interface, len(outgoing_data), outgoing_data)

def forward_with_vlan(src_mac, dst_mac, interface, data, interfaces, frame_vlan_id):
    interface_name = get_interface_name(interface)
    is_trunk = interface_name in Trunk_Ports

    if not is_trunk and frame_vlan_id == -1:
        frame_vlan_id = VLAN_Table.get(interface_name, -1)

    MAC_Table[src_mac] = interface

    if is_unicast(dst_mac):
        if dst_mac in MAC_Table:
            out_port = MAC_Table[dst_mac]
            out_port_name = get_interface_name(out_port)

            if out_port_name in Trunk_Ports or VLAN_Table.get(out_port_name) == frame_vlan_id:
                forward_frame(out_port, data, frame_vlan_id)
        else:
            for o in interfaces:
                if o != interface:
                    out_port_name = get_interface_name(o)
                    if out_port_name in Trunk_Ports or VLAN_Table.get(out_port_name) == frame_vlan_id:
                        forward_frame(o, data, frame_vlan_id)
    else:
        for o in interfaces:
            if o != interface:
                out_port_name = get_interface_name(o)
                if out_port_name in Trunk_Ports or VLAN_Table.get(out_port_name) == frame_vlan_id:
                    forward_frame(o, data, frame_vlan_id)

def is_unicast(mac_address):
    first_byte = int(mac_address.split(":")[0], 16)
    return (first_byte & 1) == 0

def main():
    switch_id = sys.argv[1]
    global VLAN_Table, Trunk_Ports, stp

    filename = os.path.join("configs", f"switch{switch_id}.cfg")
    priority, VLAN_Table, Trunk_Ports = load_vlan_config(filename)
    num_interfaces = init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    stp = STPSwitch(priority)
    stp.initialize_ports(Trunk_Ports, interfaces)


    t = threading.Thread(target=send_bpdu_every_sec)
    t.start()

    while True:
        interface, data, length = recv_from_any_link()

        if is_bpdu_frame(data):
            stp.process_bpdu(data, interface)
            continue

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        
        forward_with_vlan(src_mac, dest_mac, interface, data, interfaces, vlan_id)

if __name__ == "__main__":
    main()
