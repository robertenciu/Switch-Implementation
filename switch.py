#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

BPDU_DST_MAC = b'\x01\x80\xC2\x00\x00\x00'
own_bridge_ID = b'\x00\x00\x00\x00\x00\x00\x00\x00'
root_bridge_ID = b'\x00\x00\x00\x00\x00\x00\x00\x00'
root_path_cost = 0
root_port = 0
switch_priority = 0
 # State of the ports
port_state = {}

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

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def build_bpdu(root_bridge_id, sender_bridge_id, root_path_cost):
    dst_mac = BPDU_DST_MAC
    src_mac = get_switch_mac()

    STD = DSAP = SSAP = 0x42
    CONTROL = 0x03
    BPDU_HEADER = b'\x00' * 4

    llc_header = struct.pack("!BBB", DSAP, SSAP, CONTROL)
    bpdu_config = struct.pack("!B8sI8sHHHHH",
        0x00, # flags
        root_bridge_id,
        root_path_cost,
        sender_bridge_id,
        0, # port_id
        0, # message_age
        0, # max_age
        0, # hello_time
        0,) # forward delay

    llc_length = len(llc_header) + len(bpdu_config) + len(BPDU_HEADER)

    # Pack the LLC_LENGTH as 2 bytes
    llc_length_field = struct.pack("!H", llc_length)

    # Building actual packet
    bpdu_packet = dst_mac + src_mac + llc_length_field + llc_header + BPDU_HEADER + bpdu_config

    return bpdu_packet

def send_bdpu_every_sec(port_config):
    while True:
        global root_bridge_ID
        global own_bridge_ID
        if own_bridge_ID == root_bridge_ID:
            bpdu_packet = build_bpdu(own_bridge_ID, own_bridge_ID, 0)
            for port in port_config:
                if port_config[port] == "T":
                    send_to_link(port, len(bpdu_packet), bpdu_packet)
        time.sleep(1)

def receive_bpdu(data, interface, port_config):
    global root_bridge_ID
    global own_bridge_ID
    global root_path_cost
    global root_port
    global port_state
    bpdu_root_bridge_ID = data[22:30]
    bpdu_path_cost = int(data[30:34])
    bpdu_bridge_ID = data[34:42]

    if bpdu_root_bridge_ID < root_bridge_ID:
        root_bridge_ID = bpdu_root_bridge_ID
        root_path_cost = bpdu_path_cost + 10
        root_port = interface

        if own_bridge_ID == root_bridge_ID:
            for port in port_state:
                if port_config[port] == "T" and port != root_port:
                    port_state[port] = "BLOCKING"
        
        if port_state[root_port] == "BLOCKING":
            port_state[root_port] == "LISTENING"
    elif bpdu_root_bridge_ID == root_bridge_ID:
        if interface == root_port and bpdu_path_cost + 10 < root_path_cost:
            root_path_cost = bpdu_path_cost + 10
        elif port != interface:
            if bpdu_path_cost > root_path_cost:
                if port_state[interface] != "DESIGNATED":
                    port_state[interface] = "LISTENING"
    elif bpdu_bridge_ID == own_bridge_ID:
        port_state[interface] = "BLOCKING"
    
    if own_bridge_ID == root_bridge_ID:
        for port in port_state:
            port_state[port] = "DESIGNATED"





def do_broadcast_from_access(packet, interfaces, port_config):
    interface, data, length = packet
    vlan_id = int(port_config[interface])
    for port in interfaces:
        if interface != port:
            if port_config[interface] == port_config[port]:
                send_to_link(port, length, data)
            elif port_config[port] == "T":
                tagged_frame = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                send_to_link(port, length + 4, tagged_frame)

def do_broadcast_from_trunk(packet, interfaces, port_config, vlan_id):
    interface, data, length = packet
    for port in interfaces:
        if interface != port:
            if port_config[port] == "T": # Sending to trunk port
                send_to_link(port, length, data)
            elif vlan_id == int(port_config[port]):
                send_to_link(port, length - 4, data[0:12] + data[16:])


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    global switch_priority
    # The MAC table
    mac_table = {}

    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    switch_config = f"configs/switch{switch_id}.cfg"

    # Port configuration (access > 10 / trunk = T)
    port_config = {}

    global port_state
    with open(switch_config, 'r') as file:
        switch_priority = int(file.readline().rstrip())
        for line in file:
            line = line.strip()
            interface_name, vlan_id = line.split()
            for i in interfaces:
                if interface_name == get_interface_name(i):
                    port_config[i] = vlan_id
                    if vlan_id == "T":
                        port_state[i] = "BLOCKING"
                    else:
                        port_state[i] = "LISTENING"

    
    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    global own_bridge_ID
    global root_bridge_ID
    global root_path_cost
    root_path_cost = 0
    own_bridge_ID = switch_priority.to_bytes(8, byteorder='big', signed=False)
    root_bridge_ID = own_bridge_ID
    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(port_config,))
    t.start()
    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))


    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()
        packet = (interface, data, length)

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)


        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)
        
        print("primesti?")
        if dest_mac == BPDU_DST_MAC:
            receive_bpdu(data, interface)
            continue

        # TODO: Implement forwarding with learning
        mac_table[src_mac] = interface

        if vlan_id == -1: # Coming from access port
            vlan_id = int(port_config[interface])
            if dest_mac != 'ff:ff:ff:ff:ff:ff': # NOT broadcast
                if dest_mac in mac_table:
                    forward_interface = mac_table[dest_mac]
                    if port_config[forward_interface] == "T":
                        tagged_frame = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                        send_to_link(forward_interface, length + 4, tagged_frame)
                    elif port_config[interface] == port_config[forward_interface]: # It's same VLAN
                        send_to_link(forward_interface, length, data)
                    # else: drop
                else:
                    do_broadcast_from_access(packet, interfaces, port_config)

            else:
                do_broadcast_from_access(packet, interfaces, port_config)
        else: # Coming form trunk port
            if dest_mac != 'ff:ff:ff:ff:ff:ff':
                if dest_mac in mac_table:
                    forward_interface = mac_table[dest_mac]
                    if vlan_id == int(port_config[forward_interface]): # It's same VLAN
                        send_to_link(forward_interface, length - 4, data[0:12] + data[16:])
                    # else: drop
                else:
                    do_broadcast_from_trunk(packet, interfaces, port_config, vlan_id)
            else:
                do_broadcast_from_trunk(packet, interfaces, port_config, vlan_id)

        # TODO: Implement VLAN support


        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
