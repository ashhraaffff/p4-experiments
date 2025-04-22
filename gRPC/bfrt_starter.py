#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import pdb
import socket
import struct 

SDE_INSTALL   = os.environ['SDE_INSTALL']
SDE_PYTHON_310 = os.path.join(SDE_INSTALL, 'lib', 'python3.10', 'site-packages')

sys.path.append(SDE_PYTHON_310)
sys.path.append(os.path.join(SDE_PYTHON_310, 'tofino'))
                
import grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as bfrt_client

#
# Connect to the BF Runtime Server
#
interface = bfrt_client.ClientInterface(
    grpc_addr = 'localhost:50052',
    client_id = 0,
    device_id = 0)
print('Connected to BF Runtime Server')

#
# Get the information about the running program
#
bfrt_info = interface.bfrt_info_get()
print('The target runs the program ', bfrt_info.p4_name_get())

#
# Establish that you are using this program on the given connection
#
interface.bind_pipeline_config(bfrt_info.p4_name_get())

################### You can now use BFRT CLIENT ###########################

print("bfrt_info:")
print(dir(bfrt_info))
print()


table1 = bfrt_info.table_get("Ingress.ipv4_host") 
print("table1:")
print(dir(table1))
print()
print(dir(table1.info))
print()


print("Action Names")
print(table1.info.action_name_list_get())
print()

print("parsed info:")
print()
#print(dir(bfrt_info.parsed_info))
#print()
#print(bfrt_info.parsed_info)


#adding an entry

#ip_addr = socket.inet_aton('5.5.5.7')
#ip_int = struct.unpack("!I", ip_addr)[0] 
#target= bfrt_client.Target(device_id=0,pipe_id=0xFFFF)
#table1.entry_add(
#    target,
#    [table1.make_key([bfrt_client.KeyTuple('hdr.ipv4.dst_addr', ip_int)])],
#    [table1.make_data([bfrt_client.DataTuple('port', 21)], 'Ingress.send')]
#)
#print("entry added")


#access current entries

#print("Dumping table entries:")

#resp = table1.entry_get(
#    target,
#    None,  #this will get all entries, you can also specify a key to get specific entries
#    {"from_hw": True}  
#)

#print the entries

#for data, key in resp:
#    print("Entry:")
#    print("  Key:", key)
#    print("  Data:", data)

############################## FINALLY ####################################

# If you use SDE prior to 9.4.0, uncomment the line below
# interface._tear_down_stream()

print("The End")

