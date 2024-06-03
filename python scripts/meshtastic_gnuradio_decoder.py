# Joint copyright of Josh Conway and discord user:winter_soldier#1984
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


# SDR output example data: ffffffffb45463dab971aa8c6308000078aacf76587a5a4cf4a20e2c1d0349ab3f72
# Use default key. Result should be:  b'\x08\x01\x12\x0eTestingCLU1234'

##### START FUNCTIONS BLOCK #####

# Takes in a string encoded as hex, and emits them as a bytes encoded of the same hex representation

def hexStringToBinary(hexString):
    binString = bytes.fromhex(hexString)
    return binString

def bytesToHexString(byteString):
    hexString = byteString.hex()
    return hexString

##### END FUNCTIONS BLOCK #####



##### START PARSE COMMANDLINE INPUT #####

parser = argparse.ArgumentParser(description='Process incoming command parmeters')
parser.add_argument('-i', '--input', action='store', dest='input', help='SDR capture of the full Meshtastic LoRa string')
parser.add_argument('-k', '--key', action='store',dest='key', help='AES key override in Base64')
parser.add_argument('-n', '--net', action='store',dest='net', help='Network TCP in ip or DNS. ZeroMQ protocol.')
parser.add_argument('-p', '--port', action='store',dest='port', help='Network port')
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
    return meshPacketHex

##### END DATA EXTRACTION BLOCK #####



##### START DECRYPTION PROCESS #####

def dataDecryptor(meshPacketHex, aesKey):

    # Build the nonce. This is (packetID)+(00000000)+(sender)+(00000000) for a total of 128bit
    # Even though sender is a 32 bit number, internally its used as a 64 bit number.
    # Needs to be a bytes array for AES function.

    aesNonce = meshPacketHex['packetID'] + b'\x00\x00\x00\x00' + meshPacketHex['sender'] + b'\x00\x00\x00\x00'

    # print("Nonce binary is:", aesNonce)
    # print("Nonce length is:", len(aesNonce) )


    # Initialize the cipher
    cipher = Cipher(algorithms.AES(meshtasticFullKeyHex), modes.CTR(aesNonce), backend=default_backend())
    decryptor = cipher.decryptor()

    # Do the decryption. Note, that this cipher is reversible, so running the cipher on encrypted gives decrypted, and running the cipher on decrypted gives encrypted.
    decryptedOutput = decryptor.update(meshPacketHex['data']) + decryptor.finalize()
    return decryptedOutput

##### END DECRYPTION PROCESS #####

##### START OPTIONAL NETWORK PROCESS #####

def networkParse(ipAddr, port, aesKey):

    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.connect("tcp://" + ipAddr + ":" + port) # connect, not bind, the PUB will bind, only 1 can bind
    socket.setsockopt(zmq.SUBSCRIBE, b'') # subscribe to topic of all (needed or else it won't work)

    while True:
        if socket.poll(10) != 0: # check if there is a message on the socket
            msg = socket.recv() # grab the message
            extractedData = dataExtractor(msg.hex())
            decryptedData = dataDecryptor(extractedData, aesKey)
            print(decryptedData)
        else:
            time.sleep(0.1) # wait 100ms and try again

##### START OPTIONAL NETWORK PROCESS #####





if __name__ == "__main__":
    meshtasticFullKeyHex = parseAESKey(args.key)

    # Network branch. Doesnt exit, so we need IP Port and AES key
    try:
        print("do we have ip and port?")
        if len(args.net) > 0 and len(args.port) > 0:
            print(args.net, args.port)
            networkParse(args.net, args.port, meshtasticFullKeyHex)
    except:
        # If we get a payload on commandline, decrypt and exit. 
        meshPacketHex = dataExtractor(args.input)
        decryptedData = dataDecryptor(meshPacketHex, meshtasticFullKeyHex)
        print(decryptedData)




