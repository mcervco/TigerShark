#!/usr/bin/env python3

# Miguel Cervantes

import struct
import sys
import socket

# Display ARP Packet    
def displayARPPacket(frameLength, destMAC, destIP, srcMAC, srcIP, protoType, opcode, optext, protoName):
    print("Captured Packet - Length {}".format(frameLength))
    print("  Eth: Dst:{} SRC:{} Type/Len:0x{} ({})".format(destMAC, srcMAC, protoType, protoName))
    print("  ARP: {} ({}): DestProto:{} DstHw:{}".format(optext, opcode, destIP, destMAC))
    print("       SrcProto:{} SrcHw:{}".format(srcIP, srcMAC))
    print("")

# Display ARP Packet
def displayICMPPacket(frameLength, destMAC, destIP, srcMAC, srcIP, protoType, protoNumber, protoName, reqType, reqTypeCode, ident, seqNum):
    print("Captured Packet - Length {}".format(frameLength))
    print("  Eth:  Dst:{} SRC:{} Type/Len:0x{} (IP)".format(destMAC, srcMAC, protoType))
    print("  IP:   Dst:{} Src:{} Proto:{} ({})".format(destIP, srcIP, protoNumber, protoName))
    print("  ICMP: Echo {} (Type {}): Ident:{} Seq Num:{}".format(reqType, reqTypeCode, ident, seqNum))
    print("")

# Display IP (TCP/UDP) Packet
def displayIPPacket(frameLength, destMAC, destIP, srcMAC, srcIP, protoType, protoNumber, protoName):
    print("Captured Packet - Length {}".format(frameLength))
    print("  Eth:  Dst:{} SRC:{} Type/Len:0x{} (IP)".format(destMAC, srcMAC, protoType))
    print("  IP:   Dst:{} Src:{} Proto:{} ({})".format(destIP, srcIP, protoNumber, protoName))
    print("")

# Decode Ethernet Frames
def decodeEthernetFrame(frame):
    frameLength = len(frame)
    
    # Destination MAC Address 
    destMAC = frame[0:6]
    # Source MAC Address 
    srcMAC = frame[6:12]
    # Protocol Address Type
    protocolType = frame[12:14]
    
    # Check if it's of type ARP 
    if protocolType.hex() == '0806':
        opcode = frame[20:22]
        optext = ""

        # Check if its a request
        if opcode.hex() == '0001':
            opcode = 1
            optext = "Request"
        # Check if its a reply
        elif opcode.hex() == '0002':
            opcode = 2
            optext = "Reply"
        else:
            return
        # Get the destination IP
        srcIP = frame[28:32]
        # Get the source IP
        destIP = frame[38:42]
        # Range helper
        indices = range(0, 8, 2)
        # Format the destination IP
        data = [str(int(destIP.hex()[x:x+2], 16)) for x in indices]
        destIPFormatted = ".".join(data)
        # Format the source IP
        data = [str(int(srcIP.hex()[x:x+2], 16)) for x in indices]
        srcIPFormatted = ".".join(data)
        # Format the destination MAC address
        destMAC = destMAC.hex()
        destMAC = ":".join([destMAC[i:i+2] for i in range(0, len(destMAC), 2)])
        # Format the source MAC address
        srcMAC = srcMAC.hex()
        srcMAC = ":".join([srcMAC[i:i+2] for i in range(0, len(srcMAC), 2)])
        # Get the protocol type
        protocolType = protocolType.hex()
        displayARPPacket(frameLength, destMAC, destIPFormatted, srcMAC, srcIPFormatted, protocolType, opcode, optext, 'ARP')
    
    # Check if its of type ICMP
    elif protocolType.hex() == '0800':
        # Check if destined for Virutal IP Address
        data = [str(int(frame[30:34].hex()[x:x+2], 16)) for x in range(0, 8, 2)]
        destIPFormatted = ".".join(data)
        data = [str(int(frame[26:30].hex()[x:x+2], 16)) for x in range(0, 8, 2)]
        srcIPFormatted = ".".join(data)
        
        # Request Type 
        protoNumber = frame[23]
        protoNumber = int(protoNumber)
        reqType = frame[34]
        reqType = int(reqType) 
        reqText = ""
        # Check its a request
        if reqType == 0:
            reqText = "request"
        elif reqType == 8:
            reqText = "reply"
        else:
            return

        # Identifier
        ident = frame[38:40]
        ident = int(ident.hex(), 16)
        # Get protocol type
        protocolType = protocolType.hex()
        # Get the packet sequence number
        seqNum = frame[40:42]
        seqNum = int(seqNum.hex(), 16)
        # Format destination MAC address
        destMAC = destMAC.hex()
        destMAC = ":".join([destMAC[i:i+2] for i in range(0, len(destMAC), 2)])
        # Format source MAC address
        srcMAC = srcMAC.hex()
        srcMAC = ":".join([srcMAC[i:i+2] for i in range(0, len(srcMAC), 2)])
        # Display message based on packet type
        if protoNumber == 1: 
            displayICMPPacket(frameLength, destMAC, destIPFormatted, srcMAC, srcIPFormatted, protocolType, protoNumber, 'ICMP', reqText, reqType, ident, seqNum)
        elif protoNumber == 6:
            displayIPPacket(frameLength, destMAC, destIPFormatted, srcMAC, srcIPFormatted, protocolType, protoNumber, 'TCP') 
        elif protoNumber == 17:
            displayIPPacket(frameLength, destMAC, destIPFormatted, srcMAC, srcIPFormatted, protocolType, protoNumber, 'UDP') 

# Run TigerShark
def start():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('enp0s3', 0))

    # Receive raw ethernet frames from the network interface
    while 1:
        frame = s.recv(1500)
        decodeEthernetFrame(frame)

def main():
    start()

if __name__ == '__main__':
    if not sys.version_info[:2] == (3,5):
        print("Error: Python 3.5 required to run this program")
        sys.exit(1)
    print("Using Python 3.5 to run program")
    sys.exit(main())
