#!/usr/bin/python2
from os import popen
import argparse
from scapy.sendrecv import sniff
import socket
import sys

eap = []

def pkt_callback(pkt):
    global packetCounter
    packetCounter += 1
    sys.stdout.write('Packets: ' + str(packetCounter) + '\r')
    sys.stdout.flush()
    if 'EAP' in pkt.payload:
        eap.append(pkt)

def main():
    parser = argparse.ArgumentParser(description="Do something.")
    parser.add_argument('-c', '--channel',required=True)
    parser.add_argument('-i', '--interface',required=True)
    args = parser.parse_args()
    cmd = "iwconfig %s | grep Mode: | awk '{print $4}' | cut -d ':' -f 2" % args.interface
    status = popen(cmd).read().strip()
    if not 'Monitor' in status:
        print "[*]Enabling monitoring mode on %s" % args.interface
        cmd = "airmon-ng start %s" % args.interface
        try:
            popen(cmd)
        except:
            print 'Failed to set monitoring mode'
            return 0
    cmd = "iwconfig %s channel %s" % (args.interface, args.channel)
    try:
        popen(cmd)
    except:
        print 'failed to set channel'
        return 0
    global packetCounter
    packetCounter = 0
    while True:
        try:
            sniff(iface=args.interface, prn=pkt_callback, store=0)
        except KeyboardInterrupt:
	    	break
        except socket.error:
	    	print 'Error: Invalid Interface'
	    	pass
    print 'Stopping capture'
    for i in eap:
        print i.show()

main()