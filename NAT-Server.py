# Patrick Sacchet
# CSC-841 - Cyber Operations II
# Lab 09/10

# Program will setup to look and act like a traditional NAT service
    # Will take advantage of multithreading to handle traffic in both directions simultaneously
    # Will maintain a master list of all active connections to help with forwarding packets to and from internal clients
    
from time import sleep
import threading
from scapy.all import TCPSession, sniff, IP, TCP, UDP, RandShort, sendp, send, conf, Ether, fragment
import random

EXTERNAL_ADDR = '192.168.149.139'
INTERNAL_ADDR = '192.168.28.128'
CLIENT_ADDR = '192.168.28.129'

# Used to track all threads we create
threads = []

# Global tracker for all TCP connections
tcp_entries = []

# Global tracker for all UDP connections
udp_entries = []

sock_internal = conf.L2socket(iface="ens37") 

sock_external = conf.L2socket(iface="ens33")


class NATEntry:
    # internal_ip - The IP address of the internal client
    # internal_port - The port number of the internal client
    # external_ip - The IP address of the external server (public internet)
    # external_port - The port number of the external server (public internet)
    # self_ip - The IP address of the middleman (us)
    # self_port - The port number of the middleman (us) 
    # internal_ip:internal_port <-> self_ip:self_port <-> external_ip:external_port
    def __init__(self, internal_ip=CLIENT_ADDR, internal_port=None, external_ip=None, external_port=None, self_ip=EXTERNAL_ADDR, self_port=None):
        self.internal_ip = internal_ip
        self.internal_port = internal_port
        self.external_ip = external_ip
        self.external_port = external_port
        self.self_ip = self_ip
        self.self_port = self_port
         

    # A string representation of our NATEntry to help us with debugging and tracking connections in our master list
    def __str__(self):
        return f"{self.internal_ip}:{self.internal_port} <-> {self.self_ip}:{self.self_port} <-> {self.external_ip}:{self.external_port}"   
    
    # Our equality function to help us check if a connection is already being tracked in our master list
    def __eq__(self, other):
        if isinstance(other, NATEntry):
            return (self.internal_ip == other.internal_ip and
                    self.internal_port == other.internal_port and
                    self.external_ip == other.external_ip and
                    self.external_port == other.external_port and
                    self.self_ip == other.self_ip and
                    self.self_port == other.self_port)
        return False

    # Find and return a specific entry in our master list based on the internal and external ip and port
        # In this instance we have the client ip/port and the external ip/port so use that to verify 
    def get_entry_udp_client(self):
        for entry in udp_entries:
            if entry.internal_ip == self.internal_ip and entry.internal_port == self.internal_port and entry.external_ip == self.external_ip and entry.external_port == self.external_port:
                return entry
        return None
    
    # In this instance we only have the external ip/port, and our own ip/port, so we can use that to verify
    def get_entry_udp_server(self):
        for entry in udp_entries:
            if entry.external_ip == self.external_ip and entry.external_port == self.external_port and entry.self_ip == self.self_ip and entry.self_port == self.self_port:
                return entry
        return None
    
    # Find and return a specific entry in our master list based on the internal and external ip and port
        # In this instance we have the client ip/port and the external ip/port so use that to verify 
    def get_entry_tcp_client(self):
        for entry in tcp_entries:
            if entry.internal_ip == self.internal_ip and entry.internal_port == self.internal_port and entry.external_ip == self.external_ip and entry.external_port == self.external_port:
                return entry
        return None
    
    # In this instance we only have the external ip/port, and our own ip/port, so we can use that to verify
    def get_entry_tcp_server(self):
        for entry in tcp_entries:
            if entry.external_ip == self.external_ip and entry.external_port == self.external_port and entry.self_ip == self.self_ip and entry.self_port == self.self_port:
                return entry
        return None

#########################################################################################################################################################
#########################################################################################################################################################

# Our scapy callback for when we receive a UDP packet on our public facing interface to be forwarded to our internal clients
def handle_udp_server(packet):
    if packet.haslayer(UDP) and packet.haslayer(IP):
        print(f"Captured server UDP packet: {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}")

        # Check to see if we're tracking this connection in our master list
            # We only know the external ip and port, along with our self ip and port, but the port alone should be enough to identify our entry
        temp_entry = NATEntry(external_ip=packet[IP].src, external_port=packet[UDP].sport, self_ip=packet[IP].dst, self_port=packet[UDP].dport)
        if (temp_entry.get_entry_udp_server() is not None):
            found_entry = temp_entry.get_entry_udp_server()
            print(f"Existing UDP connection found in NAT table: {found_entry}")
            # Forward this packet to the internal client 
            packet[IP].dst = found_entry.internal_ip
            packet[UDP].dport = found_entry.internal_port

            print(f"Modified packet for internal forwarding: {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}\n")

            # Try re-calculating checksum and length since we modified this packet
            del packet[IP].chksum
            del packet[IP].len
            del packet[UDP].chksum
            del packet[UDP].len

            # Reconstruct the ethernet layer since we are forwarding it 
            new_packet = Ether(src="00:0c:29:7f:08:82", dst="00:0c:29:3b:5f:82") / packet[IP]

            # Send the packet
            sock_internal.send(new_packet)
        else:
            print("No matching UDP connection found in NAT table for incoming server packet. Dropping packet\n")

    return

# Our scapy callback for when we receive a UDP packet on our internal facing interface to be forwarded to the outside world
def handle_udp_client(packet):
    if packet.haslayer(UDP) and packet.haslayer(IP):
        print(f"Captured client UDP packet: {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}")

        # Check if we're already tracking this connection in our master list
        temp_entry = NATEntry(internal_ip=packet[IP].src, internal_port=packet[UDP].sport, external_ip=packet[IP].dst, external_port=packet[UDP].dport)

        # If we're not, add it to the list and forward the packet to the outside world; we'll let our other thread handle the return traffic when it comes back in from the outside
        if (temp_entry.get_entry_udp_client() is None):
            # Generate a random port number for scapy to use to send our data out of        
            port = random.randint(1024, 65535)

            # Add our own details now since we'll be tracking which port this goes out of 
            temp_entry.self_ip = EXTERNAL_ADDR # our outside facing adapter
            temp_entry.self_port = port
            udp_entries.append(temp_entry)
            print(f"New UDP connection added to NAT table: {temp_entry}")

            # Manipulate the source address and port to make it look like it came from us (middleman)
            packet[IP].src = EXTERNAL_ADDR
            packet[UDP].sport = port

            print(f"Modified packet for external forwarding: {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}\n")

            # Try re-calculating checksum and length since we modified this packet
            del packet[IP].chksum
            del packet[IP].len
            del packet[UDP].chksum
            del packet[UDP].len

            # Reconstruct the ethernet layer since we are forwarding it 
            new_packet = Ether(src="00:0c:29:7f:08:78", dst="00:50:56:f6:cd:bd") / packet[IP]

            # Send the packet          
            sock_external.send(new_packet)
            
        # Otherwise we already are, so grab our full entry from our master list 
            # Since we have the internal ip/port and the external ip/port we can use that information to get our NATEntry 
        else:
            found_entry = temp_entry.get_entry_udp_client()
            print(f"Existing UDP connection found in NAT table: {found_entry}\n")
            # Make this packet look like it came from us (middleman)
            packet[IP].src = found_entry.self_ip
            packet[UDP].sport = found_entry.self_port

            # Try re-calculating checksum and length since we modified this packet
            del packet[IP].chksum
            del packet[IP].len
            del packet[UDP].chksum
            del packet[UDP].len

            # Reconstruct the ethernet layer since we are forwarding it 
            new_packet = Ether(src="00:0c:29:7f:08:78", dst="00:50:56:f6:cd:bd") / packet[IP]

            # Send the packet
            sock_external.send(new_packet)
            
    return

# Will handle each packet coming in from our internal clients to be forwarded to the outside world via a blocking call to scapy's sniff function
    # Client may send data anywhere, so make sure we capture it all 
def handle_udp_traffic_client() -> None:
    sniff(iface = "ens37", filter="udp and src 192.168.28.129", prn=handle_udp_client)

# Will handle each packet coming in from the public facing interface to be forwarded to our internal clients via ablocking call to scapy's sniff function
def handle_udp_traffic_server() -> None:
    # Only filter traffic coming IN, not traffic going out - otherwise we will be capturing our own packets 
    sniff(iface = "ens33", filter="udp and dst 192.168.149.139", prn=handle_udp_server)

#########################################################################################################################################################
#########################################################################################################################################################

def handle_tcp_server(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        print(f"Captured server TCP packet: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")

        # Check to see if we're tracking this connection in our master list
            # We only know the external ip and port, along with our self ip and port, but the port alone should be enough to identify our entry
        temp_entry = NATEntry(external_ip=packet[IP].src, external_port=packet[TCP].sport, self_ip=packet[IP].dst, self_port=packet[TCP].dport)
        if (temp_entry.get_entry_tcp_server() is not None):
            found_entry = temp_entry.get_entry_tcp_server()
            print(f"Existing TCP connection found in NAT table: {found_entry}")
            # Forward this packet to the internal client 
            packet[IP].dst = found_entry.internal_ip
            packet[TCP].dport = found_entry.internal_port

            print(f"Modified packet for internal forwarding: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}\n")

            # Strip padding
            if (packet.haslayer('Padding')):
                packet['Padding'].underlayer.remove_payload()

            # Try re-calculating checksum and length since we modified this packet
            del packet[IP].chksum
            del packet[IP].len
            del packet[TCP].chksum

            # Reconstruct the ethernet layer since we are forwarding it 
            new_packet = Ether(src="00:0c:29:7f:08:82", dst="00:0c:29:3b:5f:82") / packet[IP]

            # Send the packet

            # Make sure to fragment the packet 
            fragments = fragment(new_packet, fragsize=1400)
            for frag in fragments:
                sock_internal.send(frag)
        else:
            print("No matching TCP connection found in NAT table for incoming server packet. Dropping packet\n")

    return

# Our scapy callback for when we receive a TCP packet on our internal facing interface to be forwarded to the outside world
def handle_tcp_client(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        print(f"Captured client TCP packet: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")

        # Check if we're already tracking this connection in our master list
        temp_entry = NATEntry(internal_ip=packet[IP].src, internal_port=packet[TCP].sport, external_ip=packet[IP].dst, external_port=packet[TCP].dport)

        # If we're not, add it to the list and forward the packet to the outside world; we'll let our other thread handle the return traffic when it comes back in from the outside
        if (temp_entry.get_entry_tcp_client() is None):
            # Generate a random port number for scapy to use to send our data out of        
            port = random.randint(1024, 65535)

            # Add our own details now since we'll be tracking which port this goes out of 
            temp_entry.self_ip = EXTERNAL_ADDR # our outside facing adapter
            temp_entry.self_port = port
            tcp_entries.append(temp_entry)
            print(f"New TCP connection added to NAT table: {temp_entry}")

            # Manipulate the source address and port to make it look like it came from us (middleman)
            packet[IP].src = EXTERNAL_ADDR
            packet[TCP].sport = port

            print(f"Modified packet for external forwarding: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}\n")

            # Try re-calculating checksum and length since we modified this packet
            del packet[IP].len
            del packet[IP].chksum            
            del packet[TCP].chksum

            # Reconstruct the ethernet layer since we are forwarding it 
            new_packet = Ether(src="00:0c:29:7f:08:78", dst="00:50:56:f6:cd:bd") / packet[IP]

            # Send the packet

            # Make sure to fragment the packet 
            fragments = fragment(new_packet, fragsize=1400)
            for frag in fragments:
                sock_external.send(frag)

        # Otherwise we already are, so grab our full entry from our master list 
            # Since we have the internal ip/port and the external ip/port we can use that information to get our NATEntry 
        else:
            found_entry = temp_entry.get_entry_tcp_client()
            print(f"Existing TCP connection found in NAT table: {found_entry}\n")
            # Make this packet look like it came from us (middleman)
            packet[IP].src = found_entry.self_ip
            packet[TCP].sport = found_entry.self_port

            # Try re-calculating checksum and length since we modified this packet
            del packet[IP].len
            del packet[IP].chksum            
            del packet[TCP].chksum

            # Reconstruct the ethernet layer since we are forwarding it 
            new_packet = Ether(src="00:0c:29:7f:08:78", dst="00:50:56:f6:cd:bd") / packet[IP]

            # Send the packet
            fragments = fragment(new_packet, fragsize=1400)
            for frag in fragments:
                sock_external.send(frag)
            
    return

# Will handle each packet coming in from our internal clients to be forwarded to the outside world via a blocking call to scapy's sniff function
def handle_tcp_traffic_client() -> None:
    sniff(iface = "ens37", filter="tcp and src 192.168.28.129", prn=handle_tcp_client, session=TCPSession)

# Will handle each packet coming in from the public facing interface to be forwarded to our internal clients via ablocking call to scapy's sniff function
def handle_tcp_traffic_server() -> None:
    # Only filter traffic coming IN, not traffic going out - otherwise we will be capturing our own packets 
    sniff(iface = "ens33", filter="tcp and dst 192.168.149.139", prn=handle_tcp_server, session=TCPSession)

#########################################################################################################################################################
#########################################################################################################################################################

def main():
    print("NAT Service Starting...")

    # We'll take advantage of multithreading to help us handle traffic both internally and externally 
    
    # This thread will handle packets coming from our client going to the outside world
    udp_thread_client = threading.Thread(target=handle_udp_traffic_client)
    udp_thread_client.start()
    threads.append(udp_thread_client)

    # This thread will handle packets coming from the outside world going to our client
    udp_thread_server = threading.Thread(target=handle_udp_traffic_server)
    udp_thread_server.start()
    threads.append(udp_thread_server)

    tcp_thread_client = threading.Thread(target=handle_tcp_traffic_client)
    tcp_thread_client.start()
    threads.append(tcp_thread_client)

    tcp_thread_server = threading.Thread(target=handle_tcp_traffic_server)
    tcp_thread_server.start()
    threads.append(tcp_thread_server)

    for thread in threads:
        thread.join()


if __name__ == '__main__':
    main()
