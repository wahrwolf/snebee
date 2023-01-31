import ipaddress
import dnslib
import socket
import os
import toml

server_config = toml.load("config.toml")

class DNSServer:
    def __init__(self, peer_directory, network='10.0.0.0/24', excluded_ips=[]):
        self.peer_directory = peer_directory
        self.db = {} # DHCP database with hostname, public key, lease time and IP address
        self.available_ips = [str(ip) for ip in ipaddress.IPv4Network(network) if ip not in excluded_ips]

    def load_database(self):
        for filename in os.listdir(self.peer_directory):
            hostname = os.path.splitext(filename)[0]
            config = toml.load(os.path.join(self.peer_directory, filename))
            if not config:
                continue
            self.db[hostname] = {
                'AllowedIps': config['WireGuardPeer']['AllowedIps'],
                'PublicKey': config['WireGuardPeer']['PublicKey'],
            }
            self.available_ips = [
                    ip for ip in self.available_ips if ip not in 
                    [v for k, v in config.items() if "AllowedIps" == k]
            ]
        print(self.db)

    def save_database(self):
        for hostname, data in self.db.items():
            config = {}
            config['WireGuardPeer'] = data
            with open(os.path.join(self.peer_directory, '{}.conf'.format(hostname)), 'w') as f:
                toml.dump(config, f)

    def handle_request(self, data, client_address):
        request = dnslib.DNSRecord.parse(data)
        hostname = str(request.q.qname).split(".")[0]
        if hostname in self.db:
            ip = self.db[hostname]['AllowedIps']
        else:
            # generate a new IP address
            ip = self.available_ips.pop(0)
            # add to database
            self.db[hostname] = {
                'AllowedIps': str(ip),
                'PublicKey': '',
            }
            self.save_database()

        response = dnslib.DNSRecord(
            dnslib.DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
            q=dnslib.DNSQuestion(request.q.qname),
            a=dnslib.RR(request.q.qname, dnslib.QTYPE.A, dnslib.CLASS.IN, ttl=60, rdata=dnslib.A(ip))
        )
        return response.pack()

    def run(self, host='', port=53):
        self.load_database()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((host, port))
            while True:
                data, client_address = sock.recvfrom(4096)
                response = self.handle_request(data, client_address)
                sock.sendto(response, client_address)

if __name__ == '__main__':
    try:
        server = DNSServer(
                peer_directory=server_config.get("peer_directory", "keys"),
                network=server_config.get("network", "10.0.0.0/24"),
                excluded_ips=server_config.get("excluded_ips", []),
        )
    except Exception as error:
        print(f"Startup failed due to: {error}")
        exit(1)
    server.run(
        port=server_config.get("port", 53),
        host=server_config.get("host", '')
    )
