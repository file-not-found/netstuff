#!/usr/bin/env python2
from scapy.all import *
import logging
import threading
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def check_packet(p):
    dhcp    = p.getlayer(DHCP)
    for opt in dhcp.options:
        if opt[0] == "message-type" and opt[1] == 2:
            eth     = p.getlayer(Ether)
            bootp   = p.getlayer(BOOTP)
            print "Server:\t\t %s [%s]" % (bootp.siaddr, eth.src)
            print "DHCP IP:\t %s" % bootp.yiaddr
            print_dhcp(dhcp)
            return


def print_dhcp(dhcp):
    print "DHCP options:"
    for opt in dhcp.options:
        if opt != 'pad' and opt != 'end':
            if isinstance(opt, str):
                print "\t%s" % opt
            elif len(opt) == 2:
                print "\t%s: %s" % opt


def send_discover():
    eth     = Ether(dst='ff:ff:ff:ff:ff:ff', src=mac, type=0x0800)
    ip      = IP(src='0.0.0.0', dst='255.255.255.255')
    udp     = UDP(dport=67, sport=68)
    bootp   = BOOTP(op=1, xid=0x1337, chaddr=mac_raw[1])

    #### old version
    # req = ''
    # for i in xrange(1,255):
    #     req += chr(i)

    #### new version
    req = []
    for i in xrange(1, 255):
        req.append(i)

    dhcp    = DHCP(options=[('message-type', 'discover'), ('param_req_list', req), ('end')])
    discover = eth / ip / udp / bootp / dhcp
    sendp(discover, iface=iface, verbose=0)


if len(sys.argv) != 2:
    print "USAGE: %s <interface>" % sys.argv[0]
    exit(1)
else:
    iface = sys.argv[1]

mac     = get_if_hwaddr(iface)
mac_raw = get_if_raw_hwaddr(iface)
filter  = "udp and port 68 and port 67"
timeout = 0.5

t = threading.Timer(0.2, send_discover)
t.start()

sniff(filter=filter, prn=check_packet, timeout=timeout)
