#!/usr/bin/env python3
from __future__ import print_function
import os
import sys
import socket
import struct
import time
from scapy.all import *

# Import BF Runtime
SDE_INSTALL   = os.environ['SDE_INSTALL']
SDE_PYTHON_310 = os.path.join(SDE_INSTALL, 'lib', 'python3.10', 'site-packages')

sys.path.append(SDE_PYTHON_310)
sys.path.append(os.path.join(SDE_PYTHON_310, 'tofino'))

import grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as bfrt_client

# Global variables for BFRT interface
interface = None
bfrt_info = None
ipv4_table = None
target = None

def connect_to_bfrt():
    """Connect to the BF Runtime server and set up global variables"""
    global interface, bfrt_info, ipv4_table, target
    
    try:
        # Connect to BF Runtime Server
        interface = bfrt_client.ClientInterface(
            grpc_addr='localhost:50052',
            client_id=0,  
            device_id=0)
        print('Connected to BF Runtime Server')

        # Get program info
        bfrt_info = interface.bfrt_info_get()
        print(f'The target runs the program {bfrt_info.p4_name_get()}')

        # Bind to the program
        interface.bind_pipeline_config(bfrt_info.p4_name_get())

        # Get the IPv4 table
        ipv4_table = bfrt_info.table_get("Ingress.ipv4_host")
        print("Successfully got reference to Ingress.ipv4_host table")

        # Create target for table operations
        target = bfrt_client.Target(device_id=0, pipe_id=0xFFFF)

        return True
    except Exception as e:
        print(f"Error connecting to BFRT: {e}")
        return False

def add_table_entry(dst_ip, port=21):
    """Add an entry to the IPv4 host table"""
    global ipv4_table, target

    try:
        # Convert IP string to integer
        ip_addr = socket.inet_aton(dst_ip)
        ip_int = struct.unpack("!I", ip_addr)[0]

        # Check if entry already exists
        try:
            key = [ipv4_table.make_key([bfrt_client.KeyTuple('hdr.ipv4.dst_addr', ip_int)])]
            resp = ipv4_table.entry_get(target, key, {"from_hw": True})

            # If we got here, entry exists - let's update it
            print(f"Entry for {dst_ip} already exists, updating...")
            ipv4_table.entry_mod(
                target,
                [ipv4_table.make_key([bfrt_client.KeyTuple('hdr.ipv4.dst_addr', ip_int)])],
                [ipv4_table.make_data([bfrt_client.DataTuple('port', port)], 'Ingress.send')]
            )
        except:
            # Entry doesn't exist, let's add it
            print(f"Adding new entry for {dst_ip} -> port {port}")
            ipv4_table.entry_add(
                target,
                [ipv4_table.make_key([bfrt_client.KeyTuple('hdr.ipv4.dst_addr', ip_int)])],
                [ipv4_table.make_data([bfrt_client.DataTuple('port', port)], 'Ingress.send')]
            )

        print(f"Successfully added/updated entry for {dst_ip}")
        return True
    except Exception as e:
        print(f"Error adding table entry: {e}")
        return False

def dump_table():
    """Dump all entries in the table"""
    global ipv4_table, target

    try:
        print("\n--- Current Table Entries ---")
        resp = ipv4_table.entry_get(target, None, {"from_hw": True})

        for data, key in resp:
            print(f"Entry: {key} -> {data}")
        print("----------------------------\n")
    except Exception as e:
        print(f"Error dumping table: {e}")

def reinject_packet(pkt):
    """Reinject the packet back into the switch pipeline"""
    try:
        # Send the packet out on the CPU port interface back to the pipeline`
        sendp(pkt, iface="enp4s0f1")
        print(f"Reinjected packet: {pkt.summary()}")
        return True
    except Exception as e:
        print(f"Error reinjecting packet: {e}")
        return False

def process_packet(pkt):
    """Process received packet and add entry if needed"""
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        print(f"Packet received: {src_ip} -> {dst_ip}")

        # Add entry for the source IP (assuming it's the one we need to route back to)
        # In this simple topology, we're setting port 21 for all entries
        if(src_ip == "0.0.0.0"):
            print(f"Ignoring broadcast packet {src_ip} -> {dst_ip}")
            return

        #Hardcoded match action rules (can be configured)
        if(dst_ip == "5.5.5.6"):
            if add_table_entry(dst_ip, port=21):
                print(f"Added entry for {dst_ip} -> port 21")
                # Reinject the original packet back into the pipeline
                if reinject_packet(pkt):
                    print("Packet successfully reinjected into switch pipeline")
                else:
                    print("Failed to reinject packet")
                dump_table()
        elif(dst_ip == "5.5.5.5"):
            if add_table_entry(dst_ip, port=20):
                print(f"Added entry for {dst_ip} -> port 20")
                # Reinject the original packet back into the pipeline
                if reinject_packet(pkt):
                    print("Packet successfully reinjected into switch pipeline")
                else:
                    print("Failed to reinject packet")
                dump_table()
        else:
            print(f"Failed to add entry for {dst_ip}")
            #packet dropped in cpu
        
        
def main():
    """Main function to sniff packets and process them"""
    # Connect to BFRT
    if not connect_to_bfrt():
        print("Failed to connect to BFRT. Exiting.")
        return

    print(f"Starting packet capture on interface enp4s0f0...")

    # Start packet sniffing
    try:
        sniff(prn=process_packet, iface="enp4s0f0", store=0)
    except KeyboardInterrupt:
        print("\nStopping packet capture.")
    except Exception as e:
        print(f"Error during packet capture: {e}")

    print("Program terminated.")

if __name__ == "__main__":
    main()
