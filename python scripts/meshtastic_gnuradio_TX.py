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
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from meshtastic import protocols, mesh_pb2, mqtt_pb2, portnums_pb2, BROADCAST_NUM

# SDR output example data: ffffffff88696733de87bd6f63080000d5a03d20627d01f45a311b00a520ea0659f7a4b412115b2db1ae092a0cf382f01c1e62494facb39222212c
# The output will be "on devices nearby, you will see the new node CLU Server/Csvr"
# portnum: NODEINFO_APP
# payload: "\n\t!33676988\022\nCLU server\032\004Csvr"\006d\3503gi\210(+"

global_message_id = random.getrandbits(32)

##### START PARSE COMMANDLINE INPUT #####

parser = argparse.ArgumentParser(description='Process incoming command parmeters')
parser.add_argument('-o', '--output', action='store', dest='output', help='SDR transmit of provided hex string. Does no processing of said data.')
parser.add_argument('-n', '--net', action='store',dest='net', help='Network TCP in ip or DNS. ZeroMQ protocol.')
parser.add_argument('-p', '--port', action='store',dest='port', help='Network port')
parser.add_argument('-k', '--key', action='store',dest='key', help='AES key override in Base64')
parser.add_argument('-D', '--destination', action='store',dest='destinationID', help='Destination Address. Default is broadcast if not listed')
parser.add_argument('-S', '--sender', action='store',dest='sender', help='Sender nodename, as number!')
parser.add_argument('-P', '--packetid', action='store',dest='packetID', help='Packet ID to emit')
# parser.add_argument('-F', '--flags', action='store',dest='flags', help='Listed flags')
# parser.add_argument('-C', '--chanhash', action='store',dest='chanHash', help='Channel hash hint')
# parser.add_argument('-R', '--reserved', action='store',dest='reserved', help='Reeserved, till later. All zeros.')
args = parser.parse_args()

##### END PARSE COMMANDLINE INPUT #####

def publish_message(destinationID,sender,message_text):
    print("Destination:" + str(destinationID))
    if message_text:
        print("Encoding text: " + message_text)
        encoded_message = mesh_pb2.Data()
        encoded_message.portnum = portnums_pb2.TEXT_MESSAGE_APP 
        encoded_message.payload = message_text.encode("utf-8")
        print(encoded_message)
        data = generate_mesh_packet(destinationID, int(sender), encoded_message)
        return data[1:]
    else:
        print("Something went wrong, no message to publish")
        return

def xor_hash(data):
    result = 0
    for char in data:
        result ^= char
    return result

def generate_hash(name, key):
    replaced_key = key.replace('-', '+').replace('_', '/')
    key_bytes = base64.b64decode(replaced_key.encode('utf-8'))
    h_name = xor_hash(bytes(name, 'utf-8'))
    h_key = xor_hash(key_bytes)
    result = h_name ^ h_key
    return result

def decimal_to_little_endian(decimal_number):
    hex_str = hex(decimal_number)[2:].upper()
    hex_str = hex_str.ljust((len(hex_str) + 1) // 2 * 2, '0')
    bytes_list = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    bytes_list.reverse()
    little_endian_hex_str = ''.join(bytes_list)
    little_endian_int = int(little_endian_hex_str, 16)
    
    return little_endian_int

def generate_mesh_packet(destination_id, sender, encoded_message):
    global global_message_id

    channel="LongFast"
    node_name="test"
    key="1PG7OiApB1nwvP+rz05pAQ=="
    mesh_packet = mesh_pb2.MeshPacket()
  
    # Use the global message ID and increment it for the next call
    print("Generating Message ID" + str(global_message_id))
    #global_message_id=3111234188
    mesh_packet.id = global_message_id
    #global_message_id += 1

    setattr(mesh_packet, "from", sender)
    mesh_packet.to = destination_id
    mesh_packet.id=decimal_to_little_endian(global_message_id)
    mesh_packet.want_ack = False
    #mesh_packet.want_response = False
    #mesh_packet.channelIndex=0
    #mesh_packet.channel = generate_hash(channel, key)
    mesh_packet.channel = 8
    mesh_packet.hop_limit = 3

    print("destination " + str(mesh_packet.to))
    #print("channel hash: " + int(mesh_packet.channel))

    print("processing key:" + key)
    print("about to encrypt mesg: " + str(encoded_message.payload))
    if key == "":
        mesh_packet.decoded.CopyFrom(encoded_message)
    else:
        #dirty hack to add flags
        flags=b'\x81\x08\x00\x00'
        mesh_packet.encrypted = flags + encrypt_message(key, sender, encoded_message)
        print("Encrypted Message. " + mesh_packet.encrypted.hex())

    toRadio = mesh_pb2.ToRadio()
    toRadio.packet.CopyFrom(mesh_packet)

    #lora_payload= mesh_packet.SerializeToString().hex()
    lora_sender= mesh_packet.SerializeToString().hex()[2:10]
    lora_dest=mesh_packet.SerializeToString().hex()[11:20]
    lora_pktid= str(mesh_packet.id.to_bytes(4, "big").hex())
    lora_payload= mesh_packet.encrypted.hex()

    master_string=lora_dest + lora_sender + lora_pktid + lora_payload
    #print(master_string)

    return master_string

def encrypt_message(key, sender, encoded_message):
    global global_message_id

    key_bytes = base64.b64decode(key.encode('ascii'))
    print("key bytes: " + key_bytes.hex())
    nonce_packet_id = global_message_id.to_bytes(4, "little")+ b'\x00\x00\x00\x00'
    nonce_from_node = sender.to_bytes(4, "little") + b'\x00\x00\x00\x00'
    # Put both parts into a single byte array.
    nonce = nonce_packet_id + nonce_from_node
    print("n: "+nonce.hex())
    print("serialised data: " + str(encoded_message.SerializeToString()))
    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(encoded_message.SerializeToString()) + encryptor.finalize()
    #print(encrypted_bytes.hex())
    return encrypted_bytes

##### START OPTIONAL NETWORK PROCESS #####

def networkTransmit(ipAddr, port, rawData, destination, sender):

    context = zmq.Context()
    socket = context.socket(zmq.PUSH)
    socket.connect("tcp://" + ipAddr + ":" + port) # connect, not bind, the PUB will bind, only 1 can bind
    print("Preparing Message")
    data=publish_message(destination,sender,rawData)
    print("Sending " + data)
    for _ in range(6):
        socket.send(pmt.serialize_str(pmt.to_pmt(data)))

##### START OPTIONAL NETWORK PROCESS #####



if __name__ == "__main__":

    # Network branch. Doesnt exit, so we need IP Port and data
    try:
        if len(args.net) > 0 and len(args.port) > 0:
            print(args.net, args.port)
            if args.destinationID is None:
                destinationID=BROADCAST_NUM
            else:
                destinationID=args.destinationID
            networkTransmit(args.net, args.port, args.output, destinationID, args.sender)
    except Exception as e:
        # No data, no workie
        print("Transmission halted."+ str(e))
