from scapy.all import ARP, Ether, srp

def send_arp_request(target_ip, iface=None):
    # Create an ARP request
    arp_request = ARP(pdst=target_ip)  # pdst is the IP to which the request will be sent

    # Create an Ethernet frame
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address

    # Combine Ethernet frame and ARP request
    arp_request_broadcast = broadcast / arp_request

    # Send the ARP request and capture the response
    answered, unanswered = srp(arp_request_broadcast, timeout=2, iface=iface, verbose=False)

    # Display results
    for sent, received in answered:
        print(f"Received response from IP: {received.psrc}, MAC: {received.hwsrc}")

if __name__ == "__main__":
    target_ip = "192.168.69.69"
    iface = "wlp0s20f3"
    
    if iface.strip() == '':
        iface = None

    send_arp_request(target_ip, iface)
