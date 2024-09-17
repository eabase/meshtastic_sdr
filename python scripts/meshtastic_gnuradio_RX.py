# Joint copyright of Josh Conway and discord user:winter_soldier#1984 and AT
# License is GPL3 (Gnu public license version 3)


import sys
import os
import time
import argparse
import base64
import socket
import zmq
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from meshtastic import protocols, mesh_pb2, admin_pb2, portnums_pb2, telemetry_pb2, mqtt_pb2
from datetime import datetime
from base64 import b64encode, b64decode

# SDR output example data: ffffffffb45463dab971aa8c6308000078aacf76587a5a4cf4a20e2c1d0349ab3f72
# Use default key. Result should be:  b'\x08\x01\x12\x0eTestingCLU1234'

debug=False

##### START FUNCTIONS BLOCK #####

# Takes in a string encoded as hex, and emits them as a bytes encoded of the same hex representation

def hexStringToBinary(hexString):
    binString = bytes.fromhex(hexString)
    return binString

def bytesToHexString(byteString):
    hexString = byteString.hex()
    return hexString

def msb2lsb(msb):
    #string version of this. ONLY supports 32 bit from the sender/receiver ID. Hacky
    lsb = msb[6] + msb[7] + msb[4] + msb[5] + msb[2] + msb[3] + msb[0] + msb[1]
    return lsb

##### END FUNCTIONS BLOCK #####



##### START PARSE COMMANDLINE INPUT #####

parser = argparse.ArgumentParser(description='Process incoming command parmeters')
parser.add_argument('-i', '--input', action='store', dest='input', help='SDR capture of the full Meshtastic LoRa string')
parser.add_argument('-k', '--key', action='store',dest='key', help='AES key override in Base64')
parser.add_argument('-n', '--net', action='store',dest='net', help='Network TCP in ip or DNS. ZeroMQ protocol.')
parser.add_argument('-p', '--port', action='store',dest='port', help='Network port')
parser.add_argument('-r', '--raw', action='store_true',dest='raw', help='Deactivates all handling and passes Gnuradio data raw')
parser.add_argument('-d', '--debug', action='store_true',dest='debug', help='Print more debug messages')
args = parser.parse_args()

##### END PARSE COMMANDLINE INPUT #####



##### START AES KEY ASSIGNMENT BLOCK #####

def parseAESKey(aesKey):

    # We look if there's a "NOKEY" declaration, a key provided, or an absence of key. We do the right thing depending on each choice.
    # The "NOKEY" is basically ham mode. You're forbidden from using encryption.
    # If you dont provide a key, we use the default one. We try to make it easy on our users!
    # Note this format is in Base64

    try:
        if args.key == "0" or args.key == "NOKEY" or args.key == "nokey" or args.key == "NONE" or args.key == "none" or args.key == "HAM" or args.key == "ham":
            meshtasticFullKeyBase64 = "AAAAAAAAAAAAAAAAAAAAAA=="
        elif ( len(args.key) > 0 ):
            meshtasticFullKeyBase64 = args.key
    except:
        meshtasticFullKeyBase64 = "1PG7OiApB1nwvP+rz05pAQ=="



    # Validate the key is 128bit/32byte or 256bit/64byte long. Fail if not.

    aesKeyLength = len(base64.b64decode(meshtasticFullKeyBase64).hex())
    if (aesKeyLength == 32 or aesKeyLength == 64):
        pass
    else:
        if debug:
            print("The included AES key appears to be invalid. The key length is" , aesKeyLength , "and is not the key length of 128 or 256 bits.")
        sys.exit()


    # Convert the key FROM Base64 TO hexadecimal.
    return base64.b64decode(meshtasticFullKeyBase64.encode('ascii'))

##### END AES KEY ASSIGNMENT BLOCK #####



##### START DATA EXTRACTION BLOCK #####

def dataExtractor(data):

    # Now we split the data into the appropriate meshtastic packet structure using https://meshtastic.org/docs/overview/mesh-algo/
    # NOTE: The data coming out of GnuRadio is MSB or big endian. We have to reverse byte order after this step.

    # destination : 4 bytes 
    # sender      : 4 bytes
    # packetID    : 4 bytes
    # flags       : 1 byte
    # channelHash : 1 byte
    # reserved    : 2 bytes
    # data        : 0-237 bytes

    meshPacketHex = {
        'dest' : hexStringToBinary(data[0:8]),
        'sender' : hexStringToBinary(data[8:16]),
        'packetID' : hexStringToBinary(data[16:24]),
        'flags' : hexStringToBinary(data[24:26]),
        'channelHash' : hexStringToBinary(data[26:28]),
        'reserved' : hexStringToBinary(data[28:32]),
        'data' : hexStringToBinary(data[32:len(data)])
    }
    if debug:
        print("##### PACKET DATA START #####")
        print("dest "   + msb2lsb(str(meshPacketHex['dest'].hex())) + " sender " + msb2lsb(str(meshPacketHex['sender'].hex())) )
        print("id "     + msb2lsb(str(int(meshPacketHex['packetID'].hex(),16))) )
        print("flags "  + str(meshPacketHex['flags'].hex()))
        print("chanhash "  + str(meshPacketHex['channelHash'].hex()))
        print("data "   + str(meshPacketHex['data'].hex()))
        print("##### PACKET DATA END #####")
    return meshPacketHex

##### END DATA EXTRACTION BLOCK #####



##### START DECRYPTION PROCESS #####

def dataDecryptor(meshPacketHex, aesKey):

    # Build the nonce. This is (packetID)+(00000000)+(sender)+(00000000) for a total of 128bit
    # Even though sender is a 32 bit number, internally its used as a 64 bit number.
    # Needs to be a bytes array for AES function.

    aesNonce = meshPacketHex['packetID'] + b'\x00\x00\x00\x00' + meshPacketHex['sender'] + b'\x00\x00\x00\x00'

    if debug:
        print("AES nonce is: ", aesNonce.hex())
        print("AES key used: ", str(b64encode(aesKey)))
    # print("Nonce length is:", len(aesNonce) )


    # Initialize the cipher
    cipher = Cipher(algorithms.AES(meshtasticFullKeyHex), modes.CTR(aesNonce), backend=default_backend())
    decryptor = cipher.decryptor()

    # Do the decryption. Note, that this cipher is reversible, so running the cipher on encrypted gives decrypted, and running the cipher on decrypted gives encrypted.
    decryptedOutput = decryptor.update(meshPacketHex['data']) + decryptor.finalize()
    if debug:
        print("dec: "+ decryptedOutput.hex())
    return decryptedOutput

###### END DECRYPTION PROCESS #####




##### START PROTOBUF DECODER #####

def decodeProtobuf(packetData, sourceID, destID):

    data = mesh_pb2.Data()
    try:
        data.ParseFromString(packetData)
    except:
        data = "INVALID PROTOBUF"
        return data

    match data.portnum :
        case 0 : # UNKNOWN_APP
            data = "UNKNOWN_APP To be implemented"
        case 1 : # TEXT_MESSAGE_APP
            text_payload = data.payload.decode('utf-8')
            if(destID == str("ffffffff") ):
                data = "TEXT_MESSAGE_APP " + str(sourceID) + " -> " + str(destID) + " " + str(text_payload)
            else:
                data = "TEXT_MESSAGE_APP " + str(sourceID) + " -> " + str(destID) + " " + "DIRECT MESSAGE CENSORED"
        case 2 : # REMOTE_HARDWARE_APP
            data = "REMOTE_HARDWARE_APP To be implemented"
        case 3 : # POSITION_APP
            pos = mesh_pb2.Position()
            pos.ParseFromString(data.payload)
            latitude = pos.latitude_i * 1e-7
            longitude = pos.longitude_i * 1e-7
            data="POSITION_APP " + str(sourceID) + " -> " + str(destID) + " " + str(latitude) +"," + str(longitude)
        case 4 : # NODEINFO_APP
            info = mesh_pb2.User()
            try:
                info.ParseFromString(data.payload)
            except:
                print("Unknown Nodeinfo_app parse error")
            data = "NODEINFO_APP " + str(info)
        case 5 : # ROUTING_APP
            rtng = mesh_pb2.Routing()
            rtng.ParseFromString(data.payload)
            data = "TELEMETRY_APP "  + str(rtng)
        case 6 : # ADMIN_APP
            admn = admin_pb2.AdminMessage()
            admn.ParseFromString(data.payload)
            data = "ADMIN_APP " + str(admn) 
        case 7 : # TEXT_MESSAGE_COMPRESSED_APP
            data = "TEXT_MESSAGE_COMPRESSED_APP To be implemented"
        case 10 : # DETECTION_SENSOR_APP
            data = "DETECTION_SENSOR_APP To be implemented"
        case 32 : # REPLY_APP
            data = "REPLY_APP To be implemented"
        case 33 : # IP_TUNNEL_APP
            data = "IP_TUNNEL_APP To be implemented"
        case 34 : # PAXCOUNTER_APP
            data = "PAXCOUNTER_APP To be implemented"
        case 64 : # SERIAL_APP
            print(" ")
        case 65 : # STORE_FORWARD_APP
            sfwd = mesh_pb2.StoreAndForward()
            sfwd.ParseFromString(data.payload)
            data = "STORE_FORWARD_APP " + str(sfwd)
        case 67 : # TELEMETRY_APP
            env = telemetry_pb2.Telemetry()
            env.ParseFromString(data.payload)
            data = "TELEMETRY_APP " + str(env)
        case 68 : # ZPS_APP
            z_info = mesh_pb2.zps()
            z_info.ParseFromString(data.payload)
            data = "ZPS_APP " + str(z_info)
        case 69 : # SIMULATOR_APP
            data = "SIMULATOR_APP To be implemented"
        case 70 : # TRACEROUTE_APP
            trct= mesh_pb2.RouteDiscovery()
            trct.ParseFromString(data.payload)
            data = "TRACEROUTE_APP " + str(sourceID) + " -> " + str(destID) + " " + str(trct) 
        case 71 : # NEIGHBORINFO_APP
            ninfo = mesh_pb2.NeighborInfo()
            ninfo.ParseFromString(data.payload)
            data = "NEIGHBORINFO_APP " + str(ninfo)
        case 72 : # ATAK_PLUGIN
            data = "ATAK_PLUGIN To be implemented"
        case 73 : # MAP_REPORT_APP
            mrpt = mesh_pb2.MapReport()
            mrpt.ParseFromString(data.payload)
            data = "MAP_REPORT_APP " + str(mrpt) 
        case 74 : # POWERSTRESS_APP
            data = "POWERSTRESS_APP To be implemented"
        case 256 : # PRIVATE_APP
            data = "PRIVATE_APP To be implemented"
        case 257 : # ATAK_FORWARDER
            data = "ATAK_FORWARD To be implemented"
        case _:
            data = "UNKNOWN PROTOBUF"

    return data

##### END PROTOBUF DECODER #####



##### START OPTIONAL NETWORK PROCESS #####

def networkParse(ipAddr, port, aesKey):

    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.connect("tcp://" + ipAddr + ":" + port) # connect, not bind, the PUB will bind, only 1 can bind
    socket.setsockopt(zmq.SUBSCRIBE, b'') # subscribe to topic of all (needed or else it won't work)

    while True:
        if socket.poll(10) != 0:
            msg = socket.recv()
            if args.raw:
                print(msg)
            else:
                timeNow = datetime.now()
                print("Datetime: " + timeNow.strftime("%Y-%m-%d %H:%M:%S"))
                extractedData = dataExtractor(msg.hex())
                PacketID  = extractedData['packetID'].hex()
                if debug:
                    print("Packet: " + msg.hex())
                decryptedData = dataDecryptor(extractedData, aesKey)
                protobufMessage = decodeProtobuf(decryptedData, msb2lsb(extractedData['sender'].hex()), msb2lsb(extractedData['dest'].hex()) )
                if (protobufMessage == "INVALID PROTOBUF: "):
                    print(decryptedData)
                else:
                    print(protobufMessage + "\n")

        else:
            time.sleep(0.1) # wait 100ms and try again

##### START OPTIONAL NETWORK PROCESS #####


if __name__ == "__main__":
    meshtasticFullKeyHex = parseAESKey(args.key)

    # Network branch. Doesnt exit, so we need IP Port and AES key
    try:
        if args.debug:
            debug=True
        if len(args.net) > 0 and len(args.port) > 0:
            if debug:
                print(args.net, args.port)
            networkParse(args.net, args.port, meshtasticFullKeyHex)
    except Exception as err:
        print("Function failed. Reason: " + str(err))
        # If we get a payload on commandline, decrypt and exit.
        if debug:
            print("incoming string:", args.input)
        meshPacketHex = dataExtractor(args.input)
        if debug:
            print(meshPacketHex)
        decryptedData = dataDecryptor(meshPacketHex, meshtasticFullKeyHex)
        protobufMessage = decodeProtobuf(decryptedData)
        if(protobufMessage == "INVALID PROTOBUF:"):
            if debug:
                print("INVALID PROTOBUF: ", end = '')
            if debug:
                print(decryptedData)
        else:
            print(protobufMessage)