#!/usr/bin/python3

import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

root_port = 0
root_bridge_ID = 0
root_path_cost = 0


class VLAN:
    def __init__(self, name, vlan_id, state):
        self.name = name
        self.vlan_id = vlan_id
        self.state = state

class Switch:
    def __init__(self, priority, vlans, mac):
        self.priority = priority
        self.vlans = vlans
        self.mac = mac

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


def receive_bpdu(switch, data, port):
    global root_port
    global root_bridge_ID
    global root_path_cost


    # Unpack the BPDU fields from the byte array
    bpdu_root_bridge = int.from_bytes(data[22:30], byteorder='big')
    bpdu_root_path = int.from_bytes(data[30:34], byteorder='big')
    bpdu_bridge = int.from_bytes(data[34:42], byteorder='big')

    # Check if the BPDU is better than the current one
    if bpdu_root_bridge < root_bridge_ID:
        root_path_cost = bpdu_root_path + 10
        root_port = port

        # Block all the ports except the root port
        if switch.priority == root_bridge_ID:
            for port, vlan in switch.vlans.items():
                if vlan.vlan_id == "T" and port != root_port:
                    switch.vlans[port].state = "BLOCKED"

        # Set the new root bridge ID
        root_bridge_ID = bpdu_root_bridge

        # Set the root port to listening
        switch.vlans[root_port].state = "LISTENING"

        # Send BPDU on all the ports except the root port
        for port, vlan in switch.vlans.items():
            if vlan.vlan_id == "T" and vlan.state != "BLOCKED" and port != root_port:
                #TODO send BPDU
                #send_bpdu(port, switch)
                # Create the destination MAC address
                mac_address = "01:80:c2:00:00:00"
                dest_mac = bytes.fromhex(mac_address.replace(":", ""))

                # Create the BPDU
                macs = dest_mac + switch.mac
                llc = struct.pack("!H3b", 38, 0x42, 0x42, 0x03)
                bpdu = bytes(5) + struct.pack("!QIQ", root_bridge_ID, root_path_cost, switch.priority) + bytes(10)

                # Send the BPDU
                message = macs + llc + bpdu
                send_to_link(port, len(message), message)

    # If the BPDU is the same as the current one, we check the path cost
    elif bpdu_root_bridge == root_bridge_ID:
        if port == root_port and bpdu_root_path + 10 < root_path_cost:
            root_path_cost = bpdu_root_path + 10
        elif port != root_port:
            if bpdu_root_path > root_path_cost:
                switch.vlans[port].state = "LISTENING"

    # If the BPDU has the same priority as the switch, we block the port
    elif bpdu_bridge == switch.priority:
        switch.vlans[port].state = "BLOCKED"

    # If the switch is the root bridge, we set all the ports to listening
    if switch.priority == root_bridge_ID:
        for port, info in switch.vlans.items():
            switch.vlans[port].state = "LISTENING"


def send_bpdu(port, switch):
    # Create the destination MAC address
    mac_address = "01:80:c2:00:00:00"
    dest_mac = bytes.fromhex(mac_address.replace(":", ""))

    # Create the BPDU
    macs = dest_mac + switch.mac
    llc = struct.pack("!H3b", 38, 0x42, 0x42, 0x03)
    bpdu = bytes(5) + struct.pack("!QIQ", root_bridge_ID, root_path_cost, switch.priority) + bytes(10)

    # Send the BPDU
    data = macs + llc + bpdu
    send_to_link(port, len(data), data)


def send_bdpu_every_sec(switch):
    while root_bridge_ID == switch.priority:
        for port, vlan in switch.vlans.items():
            if vlan.vlan_id == "T":
                # Create the destination MAC address
                mac_address = "01:80:c2:00:00:00"
                dest_mac = bytes.fromhex(mac_address.replace(":", ""))

                # Create the BPDU
                macs = dest_mac + switch.mac
                llc = struct.pack("!H3b", 38, 0x42, 0x42, 0x03)
                bpdu = bytes(5) + struct.pack("!QIQ", root_bridge_ID, root_path_cost, switch.priority) + bytes(10)

                # Send the BPDU
                data = macs + llc + bpdu
                send_to_link(port, len(data), data)
        time.sleep(1)


# Initialize the bridge with the given switch
def initialize_bridge(switch):
    global root_bridge_ID, root_path_cost

    # Block all the ports
    for port, vlan in switch.vlans.items():
        if vlan.vlan_id == "T":
            switch.vlans[port].state = "BLOCKED"

    # Set the new root bridge ID
    root_bridge_ID = switch.priority
    root_path_cost = 0

    # Set to listening the root port
    if switch.priority == root_bridge_ID:
        for port, vlan in switch.vlans.items():
            switch.vlans[port].state = "LISTENING"


# Function to initialize the switch with the given configuration
def create_switch(switch_id, interfaces_names, mac_address):
    # Read the configuration file for the switch
    filename = f'configs/switch{switch_id}.cfg'
    with open(filename, "r") as file:
        lines = file.readlines()
    
    # Get the priority of the switch
    priority = int(lines[0].strip())

    # Create a dictionary with the interfaces and their respective VLANs
    vlans = {}

    for line in lines[1:]:
        name, vlan_id = line.split()
        vlans[interfaces_names[name]] = VLAN(name=name, vlan_id=vlan_id, state="")

    return Switch(priority, vlans, mac_address)


# Return True if it's a unicast address, otherwise False
def is_unicast(mac):
    mac_int = int.from_bytes(mac, byteorder="big")

    first_byte = mac_int >> 40
    is_unicast = (first_byte & 0b01) == 0
    
    return is_unicast


def vlan_switch(interfaces, cam_table, port, switch, copy_dest_mac, copy_src_mac, copy_vlan_id, copy_data):
    # We received a frame on a blocked port, impossible!, we drop it
    if switch.vlans[port].state == "BLOCKED":
        return

    cam_table[copy_src_mac] = port

    # If the frame is unicast, we should send it only to the destination
    # (if we have its MAC address already stored)
    if is_unicast(copy_dest_mac):
        if copy_dest_mac in cam_table:
            # Get the vlans of both the source and the destination ports, plus
            # the state of the link (blocked, listening)
            v_src = switch.vlans[cam_table[copy_src_mac]].vlan_id
            v_dst = switch.vlans[cam_table[copy_dest_mac]].vlan_id
            state = switch.vlans[cam_table[copy_dest_mac]].state

            ccopy_vlan_id = copy_vlan_id
            if copy_vlan_id == -1:
                copy_vlan_id = int(v_src)
                untagged_frame = copy_data
                tagged_frame = copy_data[0:12] + create_vlan_tag(copy_vlan_id) + copy_data[12:]
            else:
                untagged_frame = copy_data[0:12] + copy_data[16:]
                tagged_frame = copy_data[0:12] + create_vlan_tag(copy_vlan_id) + copy_data[16:]

            if v_dst == "T":
                if state != "BLOCKED":
                    send_to_link(cam_table[copy_dest_mac], len(tagged_frame), tagged_frame)
                else:
                    copy_vlan_id = ccopy_vlan_id
            elif int(v_dst) == copy_vlan_id:
                send_to_link(cam_table[copy_dest_mac], len(untagged_frame), untagged_frame)
            else:
                copy_vlan_id = ccopy_vlan_id

        # When we don't have the MAC address of the destination already stored, we should
        # flood the entire network in order to make sure the packet eventually reaches the
        # destination
        else:
            for p in interfaces:
                if p != port:
                    v_src = switch.vlans[cam_table[copy_src_mac]].vlan_id
                    v_dst = switch.vlans[p].vlan_id
                    state = switch.vlans[p].state

                    ccopy_vlan_id = copy_vlan_id

                    if copy_vlan_id == -1:
                        copy_vlan_id = int(v_src)
                        untagged_frame = copy_data
                        tagged_frame = copy_data[0:12] + create_vlan_tag(copy_vlan_id) + copy_data[12:]
                    else:
                        untagged_frame = copy_data[0:12] + copy_data[16:]
                        tagged_frame = copy_data[0:12] + create_vlan_tag(copy_vlan_id) + copy_data[16:]

                    if v_dst == "T":
                        if state != "BLOCKED":
                            send_to_link(p, len(tagged_frame), tagged_frame)
                        else:
                            copy_vlan_id = ccopy_vlan_id
                    elif int(v_dst) == copy_vlan_id:
                        send_to_link(p, len(untagged_frame), untagged_frame)
                    else:
                        copy_vlan_id = ccopy_vlan_id
    # The frame is not unicast, so we flood it
    else:
        for p in interfaces:
            if p != port:
                v_src = switch.vlans[cam_table[copy_src_mac]].vlan_id
                v_dst = switch.vlans[p].vlan_id
                state = switch.vlans[p].state

                ccopy_vlan_id = copy_vlan_id

                if copy_vlan_id == -1:
                    copy_vlan_id = int(v_src)
                    untagged_frame = copy_data
                    tagged_frame = copy_data[0:12] + create_vlan_tag(copy_vlan_id) + copy_data[12:]
                else:
                    untagged_frame = copy_data[0:12] + copy_data[16:]
                    tagged_frame = copy_data[0:12] + create_vlan_tag(copy_vlan_id) + copy_data[16:]

                if v_dst == "T":
                    if state != "BLOCKED":
                        send_to_link(p, len(tagged_frame), tagged_frame)
                    else:
                        copy_vlan_id = ccopy_vlan_id
                elif int(v_dst) == copy_vlan_id:
                    send_to_link(p, len(untagged_frame), untagged_frame)
                else:
                    copy_vlan_id = ccopy_vlan_id


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    # Associate the interface name with their ID, useful for
    # constructing the CAM table and VLAN switching
    interfaces_names = {}
    for i in interfaces:
        interfaces_names[get_interface_name(i)] = i

    mac_address = get_switch_mac()
    switch = create_switch(switch_id, interfaces_names, mac_address)
    
    initialize_bridge(switch)
    cam_table = {}

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(switch,))
    t.start()

    while True:
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
        copy_dest_mac = dest_mac
        copy_src_mac = src_mac
        copy_vlan_id = vlan_id
        copy_data = data

        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Check if we received a BDPU packet or something else
        if dest_mac == "01:80:c2:00:00:00":
            receive_bpdu(switch, data, interface)
        else:
            vlan_switch(interfaces, cam_table, interface, switch, copy_dest_mac, copy_src_mac, copy_vlan_id, copy_data)

    t.join()


if __name__ == "__main__":
    main()

