
import struct
import socket
import json

# Class to store hostname, public key, lease time and IP address
class DHCP:
    def __init__(self, hostname, public_key, lease_time, ip_address):
        self.hostname = hostname
        self.public_key = public_key
        self.lease_time = lease_time
        self.ip_address = ip_address

# Dictionary to store DHCP entries
dhcp_entries = {}

# Function to handle DNS requests
def handle_dns_request(data, client_address):
    # Parse the DNS request header
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!6H", data[:12])
    qoffset = 12

    # Parse the question section of the DNS request
    qname = ""
    while True:
        length = data[qoffset]
        qoffset += 1
        if length == 0:
            break
        qname += data[qoffset:qoffset+length].decode() + "."
        qoffset += length
    qtype, qclass = struct.unpack("!2H", data[qoffset:qoffset+4])
    qoffset += 4

    # Check if the question type is A (IPv4 address)
    if qtype != 1:
        # If the question type is not A, return an error
        return b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    # Check if the hostname exists in dhcp_entries
    hostname = qname[:-1]
    if hostname in dhcp_entries:
        ip_address = dhcp_entries[hostname].ip_address
    else:
        # Generate a new IP address
        ip_address = "127.0.0.1"
        public_key = "blobl"
        lease_time = 3600
        dhcp_entries[hostname] = DHCP(hostname, public_key, lease_time, ip_address)

    # Update wireguard config file
    update_wireguard_config(hostname, public_key, lease_time, ip_address)

#    # Build the DNS response
#    response = struct.pack("!6H", id, 0x8180, 1, 1, 0, 0)
#    response += data[qoffset-len(qname)-2:qoffset]
#    response += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
#    response += socket.inet_aton(ip_address)
#

    # Build the DNS response header
    response = struct.pack("!6H", id, 0x8180, 1, 1, 0, 0)

    # Build the DNS response question section
    response += data[qoffset-len(qname)-2:qoffset]
    response += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"

    # Build the DNS response answer section
    response += socket.inet_aton(ip_address)

    # Return the DNS response
    return response

# Function to update wireguard config file
def update_wireguard_config(hostname, public_key, lease_time, ip_address):
    # Write the updated DHCP entry to the wireguard config file
    with open("wireguard_config.conf", "w") as f:
        f.write(hostname + " " + public_key + " " + str(lease_time) + " " + ip_address)

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to a specific address and port
server_address = ('localhost', 53)
sock.bind(server_address)

print("Server started, listening on {}:{}".format(*server_address))

# Listen for incoming requests
while True:
    data, client_address = sock.recvfrom(4096)
    print(f"Received request from: {str(client_address)}")
    print(f"{str(data.decode())}")
    response = handle_dns_request(data, client_address)
    print(f"Sending answer: {str(response.decode())}")
    sock.sendto(response, client_address)
