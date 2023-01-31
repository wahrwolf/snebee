import ipaddress
import toml
import dnslib
import socket
import os
import os.path
import click

class DNSClient:
    def __init__(self, server, port=53, hostname=None, interface="wg0", network_path=None, peer_path=None):
        self.server = server
        self.port = port

        self.hostname = hostname if hostname else socket.gethostname()
        self.interface = interface

        if not network_path and not peer_path:
            self.network_path = "/etc/systemd/networkd/99-wireguard.network"
            self.peer_path = "/etc/systemd/networkd/99-wireguard.network"
        elif not network_path or not peer_path:
            path = network_path if network_path else peer_path
            self.network_path = path
            self.peer_path = path
        else:
            self.network_path = network_path
            self.peer_path = peer_path


    def lookup_ip(self, server_host, server_port):
        request = dnslib.DNSRecord(
                dnslib.DNSHeader(id=0, qr=0, aa=0, ra=0),
                q=dnslib.DNSQuestion(self.hostname),
                )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(request.pack(), (server_host, server_port))
            data, _ = sock.recvfrom(4096)
            response = dnslib.DNSRecord.parse(data)
            ip = str(response.a.rdata)
            return ip

    def update_network(self, ip):
        if os.path.isfile(self.network_path):
            with open(self.network_path, 'r') as f:
                config = toml.load(f)
        else:
            config = {}

        if "Match" not in config:
            config["Match"] = {"Name": self.interface}
        if "Network" not in config:
            config["Network"] = {}
        config["Network"]["Address"] = ip

        with open(self.network_path, 'w') as f:
            toml.dump(config, f)

    def update_peer(self, ip=None, public_key=None, preshared_key=None, endpoint_ip=None):
        if os.path.isfile(self.peer_path):
            with open(self.peer_path, 'r') as f:
                config = toml.load(f)

        if "WireGuardPeer" not in config:
            config["WireGuardPeer"] = {}

        if ip:
            config["WireGuardPeer"]["AllowedIps"] = ip
        if public_key:
            config["WireGuardPeer"]["PublicKey"] = public_key
        if preshared_key:
            config["WireGuardPeer"]["PresharedKey"] = preshared_key
        if endpoint_ip:
            config["WireGuardPeer"]["Endpoint"] = endpoint_ip

        with open(self.peer_path, 'w') as f:
            toml.dump(config, f)

    def run(self):
        ip = self.lookup_ip(self.server, self.port)
        self.update_network(ip)
        self.update_peer(endpoint_ip=self.server)

@click.command()
@click.argument("server")
@click.option("--hostname", required=False)
@click.option("--config-file", required=False)
@click.option("--port", required=False, type=int)
def update_wireguard_config(server, hostname=None, port=None, config_file=None):
    client = DNSClient(server, port=port, hostname=hostname, network_path=config_file)
    client.run()


if __name__ == "__main__":
    update_wireguard_config()
