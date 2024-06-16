# Joint copyright of Josh Conway and discord user:winter_soldier#1984
# License is GPL3 (Gnu public license version 3)


import sys
import os
import time
import argparse
import base64
import socket
import zmq
import pmt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from meshtastic import protocols, mesh_pb2

# SDR output example data: ffffffff88696733de87bd6f63080000d5a03d20627d01f45a311b00a520ea0659f7a4b412115b2db1ae092a0cf382f01c1e62494facb39222212c
# The output will be "on devices nearby, you will see the new node CLU Server/Csvr"
# portnum: NODEINFO_APP
# payload: "\n\t!33676988\022\nCLU server\032\004Csvr"\006d\3503gi\210(+"


##### START PARSE COMMANDLINE INPUT #####

parser = argparse.ArgumentParser(description='Process incoming command parmeters')
parser.add_argument('-o', '--output', action='store', dest='output', help='SDR transmit of provided hex string. Does no processing of said data.')
parser.add_argument('-n', '--net', action='store',dest='net', help='Network TCP in ip or DNS. ZeroMQ protocol.')
parser.add_argument('-p', '--port', action='store',dest='port', help='Network port')
# parser.add_argument('-k', '--key', action='store',dest='key', help='AES key override in Base64')
# parser.add_argument('-D', '--destination', action='store',dest='destination, help='Destination Address. Default is broadcast if not listed')
# parser.add_argument('-S', '--sender', action='store',dest='sender', help='Sender nodename, without !')
# parser.add_argument('-P', '--packetid', action='store',dest='packetID', help='Packet ID to emit')
# parser.add_argument('-F', '--flags', action='store',dest='flags', help='Listed flags')
# parser.add_argument('-C', '--chanhash', action='store',dest='chanHash', help='Channel hash hint')
# parser.add_argument('-R', '--reserved', action='store',dest='reserved', help='Reeserved, till later. All zeros.')
args = parser.parse_args()

##### END PARSE COMMANDLINE INPUT #####



##### START OPTIONAL NETWORK PROCESS #####

def networkTransmit(ipAddr, port, rawData):


    context = zmq.Context()
    socket = context.socket(zmq.PUSH)
    socket.connect("tcp://" + ipAddr + ":" + port) # connect, not bind, the PUB will bind, only 1 can bind
    socket.send(pmt.serialize_str(pmt.to_pmt(rawData)))

##### START OPTIONAL NETWORK PROCESS #####



if __name__ == "__main__":

    # Network branch. Doesnt exit, so we need IP Port and data
    try:
        if len(args.net) > 0 and len(args.port) > 0:
            print(args.net, args.port)
            networkTransmit(args.net, args.port, args.output)
    except:
        # No data, no workie
        print("Data not present. Transmission halted.")
