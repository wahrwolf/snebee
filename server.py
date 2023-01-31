import dnslib
import socket

class DNSServer:
    def __init__(self):
        self.db = {} # DHCP database with hostname, public key, lease time and IP address

    def handle_request(self, data, client_address):
        request = dnslib.DNSRecord.parse(data)
        hostname = str(request.q.qname)
        if hostname in self.db:
            ip = self.db[hostname]['ip']
        else:
            # generate a new IP address
            ip = '10.0.0.{}'.format(len(self.db) + 1)
            # add to database
            self.db[hostname] = {
                'ip': ip,
                'public_key': '',
                'lease_time': 0
            }

        response = dnslib.DNSRecord(
            dnslib.DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
            q=dnslib.DNSQuestion(request.q.qname),
            a=dnslib.RR(request.q.qname, dnslib.QTYPE.A, dnslib.CLASS.IN, ttl=60, rdata=dnslib.A(ip))
        )
        return response.pack()

    def run(self, host='', port=53):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((host, port))
            while True:
                data, client_address = sock.recvfrom(4096)
                response = self.handle_request(data, client_address)
                sock.sendto(response, client_address)

if __name__ == '__main__':
    server = DNSServer()
    server.run()
